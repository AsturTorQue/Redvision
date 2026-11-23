//! Calidad de experiencia (QoE): latencia, jitter, pérdida, DNS, conexión y velocidad de descarga
//! traducidos a una nota para voz, vídeo, juegos y navegación.
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
    pub result: Option<QoeResult>,
}

pub fn verdict(score: f64) -> &'static str {
    if score >= 85.0 {
        "Excelente"
    } else if score >= 70.0 {
        "Buena"
    } else if score >= 50.0 {
        "Aceptable"
    } else if score >= 30.0 {
        "Mala"
    } else {
        "Muy mala"
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
    let addr: SocketAddr = (host.as_str(), port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("Sin dirección")?;
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
                return Err(format!("El servidor respondió: {}", printable(&buf[..n.min(40)], 40)));
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
        return Err("No se recibieron datos".into());
    }
    Ok(total as f64 / el)
}

pub fn start_qoe(state: Shared<QoeState>, gateway: Option<Ipv4Addr>, dns: Option<IpAddr>, url: String, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        s.running = true;
        s.progress = 0.0;
        s.live_down = None;
        s.step = "Midiendo la red local…".into();
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
        step("Midiendo latencia a Internet…", 0.2);
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
        step("Midiendo el tiempo de DNS…", 0.45);
        if let Some(d) = dns {
            let times: Vec<f64> = ["example.com", "wikipedia.org", "debian.org"]
                .iter()
                .filter_map(|n| crate::dns::query(d, n, 1, false, Duration::from_secs(2)).ok().map(|x| x.1))
                .collect();
            if !times.is_empty() {
                r.dns_ms = Some(times.iter().sum::<f64>() / times.len() as f64);
            }
        }
        step("Midiendo el tiempo de conexión web…", 0.55);
        if let Some(ip) = resolve("example.com") {
            let t: Vec<f64> = (0..3).filter_map(|_| measure(ip, Method::Tcp(443), 2000)).collect();
            if !t.is_empty() {
                r.tcp_ms = Some(t.iter().sum::<f64>() / t.len() as f64);
            }
        }
        step("Midiendo la velocidad de descarga (10 s)…", 0.65);
        match download(&url, 10.0, &state, &ctx) {
            Ok(b) => r.down_bps = Some(b),
            Err(e) => r.down_err = Some(e),
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
            base + 0.15 * mbps.map(|x| high(x, 1.5, 10.0)).unwrap_or(50.0)
        };
        let web = 0.4 * low(r.dns_ms.unwrap_or(500.0), 20.0, 300.0) + 0.4 * low(r.tcp_ms.unwrap_or(800.0), 30.0, 400.0) + 0.2 * low(lat, 20.0, 200.0);
        r.scores = vec![
            AppScore { name: "Llamadas de voz (VoIP)", score: voz, detail: format!("MOS {:.2} de 4.5 · factor R {:.0}", m, rr) },
            AppScore { name: "Videollamadas", score: llamada, detail: format!("{:.0} ms · jitter {:.1} ms · pérdida {:.1}%", lat, r.inet.jitter, r.inet.loss) },
            AppScore { name: "Vídeo en streaming", score: video, detail: mbps.map(|x| format!("{:.1} Mbps de descarga", x)).unwrap_or("sin prueba de velocidad".into()) },
            AppScore { name: "Juegos en línea", score: juego, detail: format!("latencia {:.0} ms · jitter {:.1} ms", lat, r.inet.jitter) },
            AppScore { name: "Navegación web", score: web, detail: format!("DNS {} · conexión {}", r.dns_ms.map(|x| format!("{:.0} ms", x)).unwrap_or("—".into()), r.tcp_ms.map(|x| format!("{:.0} ms", x)).unwrap_or("—".into())) },
        ];
        r.overall = r.scores.iter().map(|s| s.score).sum::<f64>() / r.scores.len() as f64;
        let mut s = lock(&state);
        s.result = Some(r);
        s.running = false;
        s.progress = 1.0;
        s.step = "Medición terminada".into();
        ctx.request_repaint();
    });
}
