//! Latencia, pérdida de paquetes, ruta (traceroute) y sondeos TCP.
use crate::egui;
use crate::util::*;
use std::io::{BufRead, BufReader, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub fn resolve(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let addrs: Vec<SocketAddr> = (host, 0).to_socket_addrs().ok()?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .map(|a| a.ip())
}

/// Un ping ICMP usando el programa `ping` del sistema (no necesita permisos).
pub fn ping_once(host: &str, timeout_ms: u32) -> Option<f64> {
    let out = if cfg!(windows) {
        let t = timeout_ms.to_string();
        run("ping", &["-n", "1", "-w", &t, host])
    } else if cfg!(target_os = "macos") {
        let t = timeout_ms.to_string();
        run("ping", &["-c", "1", "-W", &t, host])
    } else {
        let t = ((timeout_ms + 999) / 1000).max(1).to_string();
        run("ping", &["-c", "1", "-W", &t, host])
    }?;
    parse_ping(&out)
}

fn parse_ping(out: &str) -> Option<f64> {
    let l = out.to_lowercase();
    if !l.contains("ttl") {
        return None;
    }
    for key in ["time=", "time<", "tiempo=", "tiempo<", "zeit=", "temps=", "tempo="] {
        if let Some(i) = l.find(key) {
            let rest = &l[i + key.len()..];
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
                .collect();
            if let Ok(v) = num.replace(',', ".").parse::<f64>() {
                return Some(if key.ends_with('<') { v / 2.0 } else { v });
            }
        }
    }
    Some(0.5)
}

pub enum Probe {
    Open(f64),
    Closed(f64),
    Timeout,
}

pub fn tcp_probe(addr: SocketAddr, timeout: Duration) -> Probe {
    let t = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Probe::Open(t.elapsed().as_secs_f64() * 1000.0),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
            Probe::Closed(t.elapsed().as_secs_f64() * 1000.0)
        }
        Err(_) => Probe::Timeout,
    }
}

// ---------------------------------------------------------------- estadísticas

#[derive(Default, Clone, Copy)]
pub struct Stats {
    pub sent: usize,
    pub recv: usize,
    pub loss: f64,
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub jitter: f64,
    pub stddev: f64,
    pub p95: f64,
}

pub fn stats(samples: &[Option<f64>]) -> Stats {
    let mut s = Stats { sent: samples.len(), ..Default::default() };
    let ok: Vec<f64> = samples.iter().flatten().copied().collect();
    s.recv = ok.len();
    if s.sent > 0 {
        s.loss = 100.0 * (s.sent - s.recv) as f64 / s.sent as f64;
    }
    if ok.is_empty() {
        return s;
    }
    s.min = ok.iter().cloned().fold(f64::MAX, f64::min);
    s.max = ok.iter().cloned().fold(0.0, f64::max);
    s.avg = ok.iter().sum::<f64>() / ok.len() as f64;
    s.stddev = (ok.iter().map(|v| (v - s.avg).powi(2)).sum::<f64>() / ok.len() as f64).sqrt();
    if ok.len() > 1 {
        s.jitter = ok.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (ok.len() - 1) as f64;
    }
    let mut sorted = ok.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s.p95 = sorted[((sorted.len() as f64 * 0.95) as usize).min(sorted.len() - 1)];
    s
}

/// Modelo E simplificado (ITU-T G.107): devuelve (factor R, MOS).
pub fn mos(avg_ms: f64, jitter_ms: f64, loss_pct: f64) -> (f64, f64) {
    let eff = avg_ms + 2.0 * jitter_ms + 10.0;
    let mut r = if eff < 160.0 { 93.2 - eff / 40.0 } else { 93.2 - (eff - 120.0) / 10.0 };
    r -= 2.5 * loss_pct;
    let r = r.clamp(0.0, 100.0);
    let m = 1.0 + 0.035 * r + 0.000007 * r * (r - 60.0) * (100.0 - r);
    (r, m.clamp(1.0, 4.5))
}

// ---------------------------------------------------------------- monitor de latencia

#[derive(Clone, Copy, PartialEq)]
pub enum Method {
    Icmp,
    Tcp(u16),
}

#[derive(Default)]
pub struct LatencyState {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub running: bool,
    pub samples: Vec<(f64, Option<f64>)>,
    pub error: Option<String>,
}

pub fn measure(ip: IpAddr, method: Method, timeout_ms: u32) -> Option<f64> {
    match method {
        Method::Icmp => ping_once(&ip.to_string(), timeout_ms),
        Method::Tcp(p) => match tcp_probe(SocketAddr::new(ip, p), Duration::from_millis(timeout_ms as u64)) {
            Probe::Open(r) | Probe::Closed(r) => Some(r),
            Probe::Timeout => None,
        },
    }
}

pub fn start_latency(
    state: Shared<LatencyState>,
    stop: Arc<AtomicBool>,
    target: String,
    method: Method,
    interval_ms: u64,
    ctx: egui::Context,
) {
    {
        let mut s = lock(&state);
        s.target = target.clone();
        s.samples.clear();
        s.running = true;
        s.error = None;
        s.ip = None;
    }
    thread::spawn(move || {
        let ip = resolve(&target);
        {
            let mut s = lock(&state);
            s.ip = ip;
            if ip.is_none() {
                s.error = Some(format!("No se pudo resolver «{}»", target));
            }
        }
        if let Some(ip) = ip {
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let rtt = measure(ip, method, 1000);
                {
                    let mut s = lock(&state);
                    s.samples.push((now_secs(), rtt));
                    if s.samples.len() > 3600 {
                        s.samples.remove(0);
                    }
                }
                ctx.request_repaint();
                let el = t0.elapsed().as_millis() as u64;
                if el < interval_ms {
                    sleep_while(interval_ms - el, &stop);
                }
            }
        }
        lock(&state).running = false;
        ctx.request_repaint();
    });
}

// ---------------------------------------------------------------- traceroute

#[derive(Clone)]
pub struct Hop {
    pub n: u32,
    pub ip: Option<std::net::Ipv4Addr>,
    pub rtt: Option<f64>,
}

#[derive(Default)]
pub struct TraceState {
    pub running: bool,
    pub target: String,
    pub hops: Vec<Hop>,
    pub raw: Vec<String>,
    pub error: Option<String>,
}

fn parse_hop(line: &str) -> Option<Hop> {
    let t = line.trim();
    let first = t.split_whitespace().next()?;
    let n: u32 = first.trim_end_matches(':').trim_end_matches('?').parse().ok()?;
    let ip = ipv4s_in(t).into_iter().next();
    let toks: Vec<&str> = t.split_whitespace().collect();
    let mut rtt = None;
    for (i, tok) in toks.iter().enumerate().skip(1) {
        if *tok == "ms" && i > 0 {
            if let Ok(v) = toks[i - 1].trim_start_matches('<').parse::<f64>() {
                rtt = Some(v);
                break;
            }
        } else if let Some(num) = tok.strip_suffix("ms") {
            if let Ok(v) = num.trim_start_matches('<').parse::<f64>() {
                rtt = Some(v);
                break;
            }
        }
    }
    Some(Hop { n, ip, rtt })
}

pub fn start_trace(state: Shared<TraceState>, target: String, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        *s = TraceState { running: true, target: target.clone(), ..Default::default() };
    }
    thread::spawn(move || {
        let candidates: Vec<(&str, Vec<String>)> = if cfg!(windows) {
            vec![("tracert", vec!["-d".into(), "-w".into(), "1000".into(), "-h".into(), "30".into(), target.clone()])]
        } else {
            vec![
                ("traceroute", vec!["-n".into(), "-q".into(), "1".into(), "-w".into(), "2".into(), "-m".into(), "30".into(), target.clone()]),
                ("tracepath", vec!["-n".into(), target.clone()]),
            ]
        };
        let mut started = false;
        for (prog, args) in candidates {
            let child = command(prog).args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
            let Ok(mut child) = child else { continue };
            started = true;
            if let Some(out) = child.stdout.take() {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    let mut s = lock(&state);
                    if let Some(h) = parse_hop(&line) {
                        if let Some(existing) = s.hops.iter_mut().find(|x| x.n == h.n) {
                            if existing.ip.is_none() {
                                *existing = h;
                            }
                        } else {
                            s.hops.push(h);
                        }
                    }
                    s.raw.push(line);
                    drop(s);
                    ctx.request_repaint();
                }
            }
            let _ = child.wait();
            break;
        }
        let mut s = lock(&state);
        if !started {
            s.error = Some("No se encontró «traceroute» ni «tracepath» en el sistema. Instálalo para ver la ruta.".into());
        }
        s.running = false;
        ctx.request_repaint();
    });
}
