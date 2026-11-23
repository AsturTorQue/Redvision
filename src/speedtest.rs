//! Medidor de velocidad entre dos equipos (como iperf): un equipo hace de servidor y el otro
//! mide la bajada (el servidor envía) y la subida (el cliente envía) por TCP.
use crate::egui;
use crate::i18n::{tf, tr};
use crate::util::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 5201;
const MAGIC: &str = "RVSPEED1";
const CHUNK: usize = 128 * 1024;

// ---------------------------------------------------------------- servidor

#[derive(Default)]
pub struct SpeedServer {
    pub running: bool,
    pub port: u16,
    pub error: Option<String>,
    pub log: Vec<String>,
}

fn serve_one(mut s: TcpStream, state: Shared<SpeedServer>, ctx: egui::Context) {
    let peer = s.peer_addr().map(|p| p.ip().to_string()).unwrap_or_default();
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.set_nodelay(true).ok();
    let mut line = String::new();
    {
        let mut r = BufReader::new(match s.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        });
        if r.read_line(&mut line).is_err() {
            return;
        }
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != MAGIC {
        return;
    }
    let secs: u64 = parts[2].parse::<u64>().unwrap_or(10).clamp(1, 60);
    let buf = vec![0x5Au8; CHUNK];
    let (bytes, el) = match parts[1] {
        "down" => {
            let t0 = Instant::now();
            let mut total = 0u64;
            while t0.elapsed().as_secs_f64() < secs as f64 {
                match s.write(&buf) {
                    Ok(n) => total += n as u64,
                    Err(_) => break,
                }
            }
            let _ = s.shutdown(Shutdown::Write);
            (total, t0.elapsed().as_secs_f64())
        }
        "up" => {
            s.set_read_timeout(Some(Duration::from_secs(secs + 10))).ok();
            let mut rbuf = vec![0u8; CHUNK];
            let mut total = 0u64;
            let mut t0: Option<Instant> = None;
            loop {
                match s.read(&mut rbuf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        t0.get_or_insert_with(Instant::now);
                        total += n as u64;
                    }
                }
            }
            let el = t0.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
            let _ = s.write_all(format!("RESULT {} {}\n", total, (el * 1e6) as u64).as_bytes());
            (total, el)
        }
        _ => return,
    };
    let dir = if parts[1] == "down" { tr("Bajada") } else { tr("Subida") };
    let mut st = lock(&state);
    st.log.push(format!("{}  {}  {}  {}", fmt_clock(now_secs()), peer, dir, fmt_bps(bytes as f64 / el.max(0.001))));
    if st.log.len() > 50 {
        st.log.remove(0);
    }
    ctx.request_repaint();
}

pub fn start_server(state: Shared<SpeedServer>, stop: Arc<AtomicBool>, port: u16, ctx: egui::Context) {
    stop.store(false, Ordering::Relaxed);
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            let mut s = lock(&state);
            s.running = false;
            s.error = Some(tf("No se pudo abrir el puerto {}: {}", &[&port, &e]));
            return;
        }
    };
    listener.set_nonblocking(true).ok();
    {
        let mut s = lock(&state);
        s.running = true;
        s.port = port;
        s.error = None;
    }
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).ok();
                    let (st, c) = (state.clone(), ctx.clone());
                    thread::spawn(move || serve_one(s, st, c));
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        lock(&state).running = false;
        ctx.request_repaint();
    });
}

// ---------------------------------------------------------------- cliente

#[derive(Default)]
pub struct SpeedTest {
    pub running: bool,
    pub phase: String,
    pub target: String,
    pub latency: Option<f64>,
    pub down: Option<f64>,
    pub up: Option<f64>,
    pub live_down: Vec<Option<f64>>,
    pub live_up: Vec<Option<f64>>,
    pub error: Option<String>,
}

fn connect(addr: SocketAddr, mode: &str, secs: u64) -> Result<TcpStream, String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| {
        tf("No se pudo conectar con {}: {}. ¿Está el servidor activo en ese equipo y el puerto abierto en su cortafuegos?", &[&addr, &e])
    })?;
    s.set_nodelay(true).ok();
    s.write_all(format!("{} {} {}\n", MAGIC, mode, secs).as_bytes()).map_err(|e| e.to_string())?;
    Ok(s)
}

/// Muestra la velocidad cada medio segundo mientras `done` no se active.
fn sample(counter: &AtomicU64, done: &AtomicBool, secs: u64, push: &dyn Fn(f64)) {
    let t0 = Instant::now();
    let mut last = 0u64;
    let mut last_t = 0.0;
    while !done.load(Ordering::Relaxed) && t0.elapsed().as_secs_f64() < secs as f64 + 5.0 {
        thread::sleep(Duration::from_millis(500));
        let now = counter.load(Ordering::Relaxed);
        let t = t0.elapsed().as_secs_f64();
        push((now - last) as f64 * 8.0 / (t - last_t) / 1e6);
        last = now;
        last_t = t;
    }
}

pub fn start_client(state: Shared<SpeedTest>, target: String, port: u16, secs: u64, streams: usize, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        *s = SpeedTest { running: true, target: target.clone(), phase: tr("Midiendo la latencia…").into(), ..Default::default() };
    }
    thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let ip = crate::ping::resolve(&target).ok_or_else(|| tf("No se pudo resolver «{}»", &[&target]))?;
            let addr = SocketAddr::new(ip, port);
            // Latencia: tiempo de conexión TCP
            let mut lat = Vec::new();
            for _ in 0..3 {
                let t = Instant::now();
                let s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| {
                    tf("No se pudo conectar con {}: {}. ¿Está el servidor activo en ese equipo y el puerto abierto en su cortafuegos?", &[&addr, &e])
                })?;
                lat.push(t.elapsed().as_secs_f64() * 1000.0);
                drop(s);
            }
            lock(&state).latency = Some(lat.iter().sum::<f64>() / lat.len() as f64);
            ctx.request_repaint();

            // Bajada: el servidor envía
            lock(&state).phase = tr("Midiendo la bajada…").into();
            let counter = Arc::new(AtomicU64::new(0));
            let done = Arc::new(AtomicBool::new(false));
            let mut handles = Vec::new();
            for _ in 0..streams {
                let mut s = connect(addr, "down", secs)?;
                let c = counter.clone();
                handles.push(thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let mut buf = vec![0u8; CHUNK];
                    let t0 = Instant::now();
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        c.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    t0.elapsed().as_secs_f64()
                }));
            }
            let t0 = Instant::now();
            {
                let (st, cx, d, cn) = (state.clone(), ctx.clone(), done.clone(), counter.clone());
                let sampler = thread::spawn(move || {
                    sample(&cn, &d, secs, &|v| {
                        lock(&st).live_down.push(Some(v));
                        cx.request_repaint();
                    })
                });
                for h in handles {
                    let _ = h.join();
                }
                done.store(true, Ordering::Relaxed);
                let _ = sampler.join();
            }
            let el = t0.elapsed().as_secs_f64().max(0.001);
            lock(&state).down = Some(counter.load(Ordering::Relaxed) as f64 * 8.0 / el / 1e6);
            ctx.request_repaint();

            // Subida: el cliente envía y el servidor dice cuánto recibió
            lock(&state).phase = tr("Midiendo la subida…").into();
            let counter = Arc::new(AtomicU64::new(0));
            let done = Arc::new(AtomicBool::new(false));
            let mut handles = Vec::new();
            for _ in 0..streams {
                let mut s = connect(addr, "up", secs)?;
                let c = counter.clone();
                handles.push(thread::spawn(move || -> (u64, f64) {
                    let buf = vec![0xA5u8; CHUNK];
                    let t0 = Instant::now();
                    while t0.elapsed().as_secs_f64() < secs as f64 {
                        match s.write(&buf) {
                            Ok(n) => {
                                c.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = s.shutdown(Shutdown::Write);
                    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let mut line = String::new();
                    let _ = BufReader::new(s).read_line(&mut line);
                    let p: Vec<&str> = line.split_whitespace().collect();
                    if p.len() == 3 && p[0] == "RESULT" {
                        (p[1].parse().unwrap_or(0), p[2].parse::<f64>().unwrap_or(0.0) / 1e6)
                    } else {
                        (0, 0.0)
                    }
                }));
            }
            let (st, cx, d, cn) = (state.clone(), ctx.clone(), done.clone(), counter.clone());
            let sampler = thread::spawn(move || {
                sample(&cn, &d, secs, &|v| {
                    lock(&st).live_up.push(Some(v));
                    cx.request_repaint();
                })
            });
            let mut bytes = 0u64;
            let mut el = 0.0f64;
            for h in handles {
                if let Ok((b, e)) = h.join() {
                    bytes += b;
                    el = el.max(e);
                }
            }
            done.store(true, Ordering::Relaxed);
            let _ = sampler.join();
            lock(&state).up = if el > 0.0 { Some(bytes as f64 * 8.0 / el / 1e6) } else { None };
            Ok(())
        })();
        let mut s = lock(&state);
        if let Err(e) = result {
            s.error = Some(e);
        }
        s.running = false;
        s.phase = tr("Medición terminada").into();
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_against_local_server() {
        let ctx = egui::Context::default();
        let srv = shared(SpeedServer::default());
        let stop = Arc::new(AtomicBool::new(false));
        start_server(srv.clone(), stop.clone(), 45201, ctx.clone());
        assert!(lock(&srv).running, "el servidor no arrancó: {:?}", lock(&srv).error);
        let st = shared(SpeedTest::default());
        start_client(st.clone(), "127.0.0.1".into(), 45201, 1, 2, ctx);
        let t0 = Instant::now();
        while lock(&st).running && t0.elapsed().as_secs() < 30 {
            thread::sleep(Duration::from_millis(100));
        }
        let s = lock(&st);
        assert!(s.error.is_none(), "{:?}", s.error);
        let (d, u) = (s.down.unwrap_or(0.0), s.up.unwrap_or(0.0));
        println!("bajada {:.0} Mbps, subida {:.0} Mbps, latencia {:?}", d, u, s.latency);
        assert!(d > 10.0 && u > 10.0);
        stop.store(true, Ordering::Relaxed);
    }
}
