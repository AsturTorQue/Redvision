//! Calidad de experiencia (QoE): latencia, jitter, pérdida, DNS, conexión y velocidad de descarga
//! traducidos a una nota para voz, vídeo, juegos y navegación.
use crate::i18n::{tr, tf};
use crate::ping::{measure, mos, resolve, stats, Method, Stats};
use crate::util::*;
use crate::egui;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AppScore {
    pub name: &'static str,
    pub score: f64,
    pub detail: String,
}

#[derive(Clone, Default)]
pub struct QoeResult {
    pub gw: Stats,
    pub inet: Stats,
    pub dns_ms: Option<f64>,
    pub tcp_ms: Option<f64>,
    pub down_bps: Option<f64>,
    pub down_err: Option<String>,
    pub up_bps: Option<f64>,
    pub up_err: Option<String>,
    pub r: f64,
    pub mos: f64,
    pub scores: Vec<AppScore>,
    pub overall: f64,
}

#[derive(Default)]
pub struct QoeState {
    pub running: bool,
    pub step: String,
    pub progress: f32,
    pub live_down: Option<f64>,
    pub live_up: Option<f64>,
    pub result: Option<QoeResult>,
}

pub fn verdict(score: f64) -> &'static str {
    if score >= 85.0 {
        tr("Excelente")
    } else if score >= 70.0 {
        tr("Buena")
    } else if score >= 50.0 {
        tr("Aceptable")
    } else if score >= 30.0 {
        tr("Mala")
    } else {
        tr("Muy mala")
    }
}

/// 100 cuando el valor es <= bueno, 0 cuando es >= malo (menor es mejor).
fn low(v: f64, good: f64, bad: f64) -> f64 {
    (100.0 * (bad - v) / (bad - good)).clamp(0.0, 100.0)
}
/// 100 cuando el valor es >= bueno, 0 cuando es <= malo (mayor es mejor).
fn high(v: f64, bad: f64, good: f64) -> f64 {
    (100.0 * (v - bad) / (good - bad)).clamp(0.0, 100.0)
}

pub const DEFAULT_DOWN: &str = "http://ipv4.download.thinkbroadband.com/512MB.zip";
pub const DEFAULT_UP: &str = "http://speed.cloudflare.com/__up";

fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.trim().strip_prefix("http://")?;
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (h, p) = match hp.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hp.to_string(), 80),
    };
    Some((h, p, path))
}

fn download(url: &str, max_secs: f64, state: &Shared<QoeState>, ctx: &egui::Context) -> Result<f64, String> {
    let (host, port, path) = parse_url(url).ok_or("La dirección debe empezar por http://")?;
    let addr: SocketAddr = (host.as_str(), port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or(tr("Sin dirección"))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| format!("No conecta: {}", e))?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: RedVision\r\nConnection: close\r\n\r\n", path, host).as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65536];
    let mut total = 0u64;
    let mut t0: Option<Instant> = None;
    let start = Instant::now();
    loop {
        let n = match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                if total > 0 {
                    break;
                }
                return Err(e.to_string());
            }
        };
        if t0.is_none() {
            if !buf.starts_with(b"HTTP/1.1 200") && !buf.starts_with(b"HTTP/1.0 200") {
                return Err(tf("El servidor respondió: {}", &[&(printable(&buf[..n.min(40)], 40))]));
            }
            t0 = Some(Instant::now());
            continue;
        }
        total += n as u64;
        let el = t0.unwrap().elapsed().as_secs_f64();
        if el > 0.3 {
            lock(state).live_down = Some(total as f64 / el);
            ctx.request_repaint();
        }
        if start.elapsed().as_secs_f64() > max_secs {
            break;
        }
    }
    let el = t0.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
    if el <= 0.0 || total == 0 {
        return Err(tr("No se recibieron datos").into());
    }
    Ok(total as f64 / el)
}

/// Envía datos a un servidor que acepta subidas por HTTP (POST) durante `secs` segundos y devuelve
/// bytes por segundo. Se envían bloques de 16 MB repetidos por varias conexiones y se ignora el
/// primer segundo (los búferes del sistema se llenan de golpe y falsean el arranque).
fn upload(url: &str, secs: f64, streams: usize, state: &Shared<QoeState>, ctx: &egui::Context) -> Result<f64, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    const BLOCK: usize = 16 * 1024 * 1024;
    let (host, port, path) = parse_url(url).ok_or_else(|| tr("La dirección debe empezar por http://").to_string())?;
    let addr: SocketAddr = (host.as_str(), port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or_else(|| tr("Sin dirección").to_string())?;
    let counter = Arc::new(AtomicU64::new(0));
    let problem: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let mut handles = Vec::new();
    for _ in 0..streams {
        let (counter, problem, host, path) = (counter.clone(), problem.clone(), host.clone(), path.clone());
        handles.push(thread::spawn(move || {
            let chunk = vec![0x5Au8; 64 * 1024];
            while Instant::now() < deadline {
                let mut s = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                    Ok(s) => s,
                    Err(e) => {
                        *problem.lock().unwrap_or_else(|e| e.into_inner()) = Some(tf("No conecta: {}", &[&e]));
                        return;
                    }
                };
                s.set_nodelay(true).ok();
                s.set_write_timeout(Some(Duration::from_secs(5))).ok();
                s.set_read_timeout(Some(Duration::from_secs(4))).ok();
                let head = format!("POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: RedVision\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", path, host, BLOCK);
                if s.write_all(head.as_bytes()).is_err() {
                    return;
                }
                let mut sent = 0usize;
                while sent < BLOCK && Instant::now() < deadline {
                    let n = chunk.len().min(BLOCK - sent);
                    match s.write(&chunk[..n]) {
                        Ok(w) => {
                            sent += w;
                            counter.fetch_add(w as u64, Ordering::Relaxed);
                        }
                        Err(_) => return,
                    }
                }
                if sent == BLOCK {
                    let mut resp = [0u8; 64];
                    let n = s.read(&mut resp).unwrap_or(0);
                    let line = String::from_utf8_lossy(&resp[..n]).to_string();
                    if n > 0 && !line.contains(" 2") {
                        *problem.lock().unwrap_or_else(|e| e.into_inner()) = Some(tf("El servidor respondió: {}", &[&line.lines().next().unwrap_or("")]));
                        return;
                    }
                }
            }
        }));
    }
    let t0 = Instant::now();
    let mut samples: Vec<(f64, u64)> = Vec::new();
    while t0.elapsed().as_secs_f64() < secs + 1.0 && handles.iter().any(|h| !h.is_finished()) {
        thread::sleep(Duration::from_millis(250));
        let (t, b) = (t0.elapsed().as_secs_f64(), counter.load(Ordering::Relaxed));
        if let Some(&(pt, pb)) = samples.iter().rev().find(|(pt, _)| t - pt >= 1.0) {
            lock(state).live_up = Some((b - pb) as f64 / (t - pt));
            ctx.request_repaint();
        }
        samples.push((t, b));
    }
    for h in handles {
        let _ = h.join();
    }
    let total = counter.load(Ordering::Relaxed);
    let t_end = t0.elapsed().as_secs_f64().min(secs);
    let (t1, b1) = samples.iter().find(|(t, _)| *t >= 1.0).copied().unwrap_or((0.0, 0));
    if total < 64 * 1024 {
        return Err(problem.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| tr("No se enviaron datos").to_string()));
    }
    let span = (t_end - t1).max(0.5);
    Ok(total.saturating_sub(b1) as f64 / span)
}

pub fn start_qoe(state: Shared<QoeState>, gateway: Option<Ipv4Addr>, dns: Option<IpAddr>, url: String, up_url: String, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        s.running = true;
        s.progress = 0.0;
        s.live_down = None;
        s.live_up = None;
        s.step = tr("Midiendo la red local…").into();
    }
    thread::spawn(move || {
        let step = |t: &str, p: f32| {
            let mut s = lock(&state);
            s.step = t.into();
            s.progress = p;
            drop(s);
            ctx.request_repaint();
        };
        let mut r = QoeResult::default();
        if let Some(gw) = gateway {
            let v: Vec<Option<f64>> = (0..10).map(|_| measure(IpAddr::V4(gw), Method::Icmp, 1000)).collect();
            r.gw = stats(&v);
        }
        step(tr("Midiendo latencia a Internet…"), 0.2);
        let inet = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut v: Vec<Option<f64>> = Vec::new();
        for i in 0..20 {
            v.push(measure(inet, Method::Icmp, 1000));
            if i == 4 && v.iter().all(|x| x.is_none()) {
                v.clear();
                for _ in 0..20 {
                    v.push(measure(inet, Method::Tcp(443), 1000));
                }
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        r.inet = stats(&v);
        step(tr("Midiendo el tiempo de DNS…"), 0.45);
        if let Some(d) = dns {
            let times: Vec<f64> = ["example.com", "wikipedia.org", "debian.org"]
                .iter()
                .filter_map(|n| crate::dns::query(d, n, 1, false, Duration::from_secs(2)).ok().map(|x| x.1))
                .collect();
            if !times.is_empty() {
                r.dns_ms = Some(times.iter().sum::<f64>() / times.len() as f64);
            }
        }
        step(tr("Midiendo el tiempo de conexión web…"), 0.55);
        if let Some(ip) = resolve("example.com") {
            let t: Vec<f64> = (0..3).filter_map(|_| measure(ip, Method::Tcp(443), 2000)).collect();
            if !t.is_empty() {
                r.tcp_ms = Some(t.iter().sum::<f64>() / t.len() as f64);
            }
        }
        step(tr("Midiendo la velocidad de descarga (10 s)…"), 0.65);
        let mut dl = download(&url, 10.0, &state, &ctx);
        if dl.is_err() && url != DEFAULT_DOWN {
            dl = download(DEFAULT_DOWN, 10.0, &state, &ctx); // servidor de respaldo
        }
        match dl {
            Ok(b) => r.down_bps = Some(b),
            Err(e) => r.down_err = Some(e),
        }
        step(tr("Midiendo la velocidad de subida (8 s)…"), 0.85);
        match upload(&up_url, 8.0, 3, &state, &ctx) {
            Ok(b) => r.up_bps = Some(b),
            Err(e) => r.up_err = Some(e),
        }
        // Notas
        let lat = if r.inet.recv > 0 { r.inet.avg } else { 999.0 };
        let (rr, m) = mos(lat, r.inet.jitter, r.inet.loss);
        r.r = rr;
        r.mos = m;
        let mbps = r.down_bps.map(|b| b * 8.0 / 1e6);
        let voz = ((m - 1.0) / 3.5 * 100.0).clamp(0.0, 100.0);
        let juego = 0.5 * low(lat, 20.0, 150.0) + 0.25 * low(r.inet.jitter, 5.0, 50.0) + 0.25 * low(r.inet.loss, 0.0, 5.0);
        let video = match mbps {
            Some(x) => 0.7 * high(x, 1.0, 25.0) + 0.3 * low(r.inet.loss, 0.0, 5.0),
            None => low(r.inet.loss, 0.0, 5.0) * 0.6,
        };
        let llamada = {
            let base = 0.35 * low(lat, 40.0, 300.0) + 0.25 * low(r.inet.jitter, 10.0, 60.0) + 0.25 * low(r.inet.loss, 0.5, 5.0);
            // En una videollamada lo que manda es la subida: con 1 Mbps va justa y con 5 Mbps va holgada
            let up_mbps = r.up_bps.map(|b| b * 8.0 / 1e6);
            base + 0.15 * up_mbps.or(mbps).map(|x| high(x, 1.0, 5.0)).unwrap_or(50.0)
        };
        let web = 0.4 * low(r.dns_ms.unwrap_or(500.0), 20.0, 300.0) + 0.4 * low(r.tcp_ms.unwrap_or(800.0), 30.0, 400.0) + 0.2 * low(lat, 20.0, 200.0);
        r.scores = vec![
            AppScore { name: tr("Llamadas de voz (VoIP)"), score: voz, detail: tf("MOS {:.2} de 4.5 · factor R {:.0}", &[&(m), &(rr)]) },
            AppScore { name: tr("Videollamadas"), score: llamada, detail: tf("{:.0} ms · jitter {:.1} ms · pérdida {:.1}%", &[&(lat), &(r.inet.jitter), &(r.inet.loss)]) },
            AppScore { name: tr("Vídeo en streaming"), score: video, detail: mbps.map(|x| tf("{:.1} Mbps de descarga", &[&(x)])).unwrap_or(tr("sin prueba de velocidad").into()) },
            AppScore { name: tr("Juegos en línea"), score: juego, detail: tf("latencia {:.0} ms · jitter {:.1} ms", &[&(lat), &(r.inet.jitter)]) },
            AppScore { name: tr("Navegación web"), score: web, detail: tf("DNS {} · conexión {}", &[&(r.dns_ms.map(|x| format!("{:.0} ms", x)).unwrap_or("—".into())), &(r.tcp_ms.map(|x| format!("{:.0} ms", x)).unwrap_or("—".into()))]) },
        ];
        r.overall = r.scores.iter().map(|s| s.score).sum::<f64>() / r.scores.len() as f64;
        let mut s = lock(&state);
        s.result = Some(r);
        s.running = false;
        s.progress = 1.0;
        s.step = tr("Medición terminada").into();
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Subida real (necesita Internet): `cargo test -- --ignored --nocapture upload_live`
    #[test]
    #[ignore]
    fn upload_live() {
        let state = shared(QoeState::default());
        let ctx = egui::Context::default();
        let r = upload(DEFAULT_UP, 5.0, 3, &state, &ctx);
        println!("subida: {:?}", r.as_ref().map(|b| fmt_bps(*b)));
        let bad = upload("http://127.0.0.1:9/x", 2.0, 1, &state, &ctx);
        println!("servidor caído: {:?}", bad);
        assert!(r.is_ok() && bad.is_err());
    }

    /// Prueba completa real (necesita Internet): `cargo test -- --ignored --nocapture qoe_full`
    #[test]
    #[ignore]
    fn qoe_full() {
        let state = shared(QoeState::default());
        start_qoe(state.clone(), Some(Ipv4Addr::new(192, 168, 0, 253)), Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), DEFAULT_DOWN.into(), DEFAULT_UP.into(), egui::Context::default());
        let t0 = Instant::now();
        while lock(&state).result.is_none() && t0.elapsed().as_secs() < 90 {
            thread::sleep(Duration::from_millis(300));
        }
        let s = lock(&state);
        let r = s.result.as_ref().expect("sin resultado");
        println!("duracion {:.0}s bajada {:?} subida {:?} err {:?}/{:?} nota {:.0}", t0.elapsed().as_secs_f64(), r.down_bps.map(fmt_bps), r.up_bps.map(fmt_bps), r.down_err, r.up_err, r.overall);
        for a in &r.scores {
            println!("   {} {:.0} {}", a.name, a.score, a.detail);
        }
        assert!(r.up_bps.is_some());
    }
}
