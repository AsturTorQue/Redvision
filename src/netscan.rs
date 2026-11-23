//! Descubrimiento de equipos de la subred y escáner de puertos con lectura de banners.
use crate::egui;
use crate::ids::{Ids, Sev};
use crate::ping::{ping_once, resolve, tcp_probe, Probe};
use crate::util::*;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Router,
    ThisPc,
    Computer,
    Phone,
    Printer,
    Server,
    Media,
    Iot,
    Unknown,
}

impl Kind {
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Router => "Router",
            Kind::ThisPc => "Este equipo",
            Kind::Computer => "Ordenador",
            Kind::Phone => "Móvil/Tablet",
            Kind::Printer => "Impresora",
            Kind::Server => "Servidor",
            Kind::Media => "TV/Multimedia",
            Kind::Iot => "IoT/Cámara",
            Kind::Unknown => "Desconocido",
        }
    }
    pub fn icon(&self) -> &'static str {
        match self {
            Kind::Router => "R",
            Kind::ThisPc => "★",
            Kind::Computer => "PC",
            Kind::Phone => "M",
            Kind::Printer => "P",
            Kind::Server => "S",
            Kind::Media => "TV",
            Kind::Iot => "IoT",
            Kind::Unknown => "?",
        }
    }
}

#[derive(Clone)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: String,
    pub name: String,
    pub rtt: Option<f64>,
    pub ports: Vec<u16>,
    pub kind: Kind,
}

#[derive(Default)]
pub struct SubnetScan {
    pub hosts: Vec<Host>,
    pub running: bool,
    pub done: usize,
    pub total: usize,
    pub network: String,
    pub started: f64,
    pub elapsed: f64,
    pub scans: u32,
}

const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 139, 3389, 53, 8080, 62078, 5353];
const PROFILE_PORTS: &[u16] = &[22, 80, 443, 445, 3389, 9100, 631, 8009, 554, 1883, 62078, 5000, 8080];

fn guess_kind(h: &Host, is_gw: bool, is_self: bool) -> Kind {
    if is_self {
        return Kind::ThisPc;
    }
    if is_gw {
        return Kind::Router;
    }
    let p = |x: u16| h.ports.contains(&x);
    let v = h.vendor.to_lowercase();
    if p(9100) || p(631) {
        Kind::Printer
    } else if p(62078) {
        Kind::Phone
    } else if p(8009) || v.contains("roku") || v.contains("sonos") {
        Kind::Media
    } else if p(554) || p(1883) || v.contains("espressif") || v.contains("hue") || v.contains("nest") {
        Kind::Iot
    } else if p(3389) || p(445) {
        Kind::Computer
    } else if p(22) && (p(80) || p(443)) {
        Kind::Server
    } else if v.contains("raspberry") || v.contains("vmware") || v.contains("qemu") || v.contains("virtualbox") {
        Kind::Server
    } else if v.contains("ubiquiti") || v.contains("tp-link") || v.contains("netgear") || v.contains("cisco") {
        Kind::Router
    } else if v.contains("privada") {
        Kind::Phone
    } else if p(22) || p(80) {
        Kind::Computer
    } else {
        Kind::Unknown
    }
}

pub fn start_subnet_scan(info: NetInfo, state: Shared<SubnetScan>, stop: Arc<AtomicBool>, ids: Shared<Ids>, ctx: egui::Context) {
    let Some(local) = info.local_ip else { return };
    let targets = subnet_hosts(local, info.prefix);
    let previous: HashSet<Ipv4Addr> = lock(&state).hosts.iter().map(|h| h.ip).collect();
    {
        let mut s = lock(&state);
        s.running = true;
        s.done = 0;
        s.total = targets.len();
        s.network = info.network_label();
        s.started = now_secs();
        s.hosts.clear();
    }
    stop.store(false, Ordering::Relaxed);
    thread::spawn(move || {
        let targets = Arc::new(targets);
        let idx = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..64 {
            let (targets, idx, state, stop, ctx) = (targets.clone(), idx.clone(), state.clone(), stop.clone(), ctx.clone());
            workers.push(thread::spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let i = idx.fetch_add(1, Ordering::Relaxed);
                let Some(&ip) = targets.get(i) else { break };
                let mut rtt = ping_once(&ip.to_string(), 800);
                let mut ports = Vec::new();
                let mut alive = rtt.is_some();
                if !alive {
                    for &p in DISCOVERY_PORTS {
                        match tcp_probe(SocketAddr::new(IpAddr::V4(ip), p), Duration::from_millis(250)) {
                            Probe::Open(r) => {
                                alive = true;
                                rtt = Some(r);
                                ports.push(p);
                                break;
                            }
                            Probe::Closed(r) => {
                                alive = true;
                                rtt = Some(r);
                                break;
                            }
                            Probe::Timeout => {}
                        }
                    }
                }
                if alive {
                    for &p in PROFILE_PORTS {
                        if ports.contains(&p) {
                            continue;
                        }
                        if let Probe::Open(_) = tcp_probe(SocketAddr::new(IpAddr::V4(ip), p), Duration::from_millis(300)) {
                            ports.push(p);
                        }
                    }
                    ports.sort();
                    let mut s = lock(&state);
                    s.hosts.push(Host { ip, mac: String::new(), vendor: String::new(), name: String::new(), rtt, ports, kind: Kind::Unknown });
                    s.hosts.sort_by_key(|h| h.ip);
                }
                lock(&state).done += 1;
                ctx.request_repaint();
            }));
        }
        for w in workers {
            let _ = w.join();
        }
        // Completar con la tabla ARP, nombres y tipo de equipo
        let arp = arp_table();
        let dns = info.dns.first().copied();
        let mut hosts = lock(&state).hosts.clone();
        for (ip, _) in &arp {
            if !hosts.iter().any(|h| h.ip == *ip) && u32::from(*ip) & mask(effective_prefix(info.prefix)) == u32::from(local) & mask(effective_prefix(info.prefix)) {
                hosts.push(Host { ip: *ip, mac: String::new(), vendor: String::new(), name: String::new(), rtt: None, ports: vec![], kind: Kind::Unknown });
            }
        }
        for h in hosts.iter_mut() {
            if let Some((_, mac)) = arp.iter().find(|(ip, _)| *ip == h.ip) {
                h.mac = mac.clone();
                h.vendor = vendor(mac);
            }
            if h.ip == local {
                h.name = info.hostname.clone();
            } else if let Some(d) = dns {
                if let Some(n) = crate::dns::reverse_lookup(d, h.ip, Duration::from_millis(400)) {
                    h.name = n;
                }
            }
            h.kind = guess_kind(h, Some(h.ip) == info.gateway, h.ip == local);
        }
        hosts.sort_by_key(|h| h.ip);
        if !previous.is_empty() {
            let mut ids = lock(&ids);
            for h in &hosts {
                if !previous.contains(&h.ip) {
                    ids.raise(Sev::Info, "Nuevo dispositivo", &h.ip.to_string(),
                        format!("Apareció {} {} {} desde el último escaneo.", h.ip, h.mac, h.vendor), &h.ip.to_string());
                }
            }
        }
        let mut s = lock(&state);
        s.hosts = hosts;
        s.running = false;
        s.scans += 1;
        s.elapsed = now_secs() - s.started;
        ctx.request_repaint();
    });
}

// ---------------------------------------------------------------- escáner de puertos

#[derive(Clone)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
    pub banner: String,
    pub rtt: f64,
}

#[derive(Default)]
pub struct PortScan {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub running: bool,
    pub done: usize,
    pub total: usize,
    pub open: Vec<OpenPort>,
    pub closed: usize,
    pub filtered: usize,
    pub error: Option<String>,
    pub elapsed: f64,
}

pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim().to_lowercase();
    if spec.is_empty() || spec == "comunes" || spec == "top" {
        return Ok(TOP_PORTS.to_vec());
    }
    if spec == "todos" || spec == "all" {
        return Ok((1..=65535).collect());
    }
    let mut v = Vec::new();
    for part in spec.split(|c| c == ',' || c == ' ').filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().map_err(|_| format!("Rango no válido: {}", part))?;
            let b: u16 = b.trim().parse().map_err(|_| format!("Rango no válido: {}", part))?;
            if a == 0 || a > b {
                return Err(format!("Rango no válido: {}", part));
            }
            v.extend(a..=b);
        } else {
            let p: u16 = part.parse().map_err(|_| format!("Puerto no válido: {}", part))?;
            if p == 0 {
                return Err("El puerto 0 no es válido".into());
            }
            v.push(p);
        }
    }
    v.sort();
    v.dedup();
    Ok(v)
}

pub fn is_http_port(p: u16) -> bool {
    matches!(p, 80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 | 5000 | 9000 | 9200 | 2375 | 3000)
}

/// Lee lo que un servicio anuncia al conectarse (o la cabecera HTTP).
pub fn grab_banner(addr: SocketAddr, timeout: Duration) -> String {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) else { return String::new() };
    s.set_read_timeout(Some(Duration::from_millis(1200))).ok();
    s.set_write_timeout(Some(timeout)).ok();
    if is_http_port(addr.port()) {
        let _ = s.write_all(format!("HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: RedVision\r\n\r\n", addr.ip()).as_bytes());
    }
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).unwrap_or(0);
    let txt = String::from_utf8_lossy(&buf[..n]).to_string();
    if txt.starts_with("HTTP/") {
        let first = txt.lines().next().unwrap_or("").to_string();
        let server = txt.lines().find(|l| l.to_lowercase().starts_with("server:")).map(|l| l[7..].trim().to_string());
        return match server {
            Some(sv) => format!("{} · Servidor: {}", first, sv),
            None => first,
        };
    }
    printable(&buf[..n], 120)
}

pub fn start_port_scan(target: String, ports: Vec<u16>, timeout_ms: u64, banners: bool, state: Shared<PortScan>, stop: Arc<AtomicBool>, ctx: egui::Context) {
    stop.store(false, Ordering::Relaxed);
    {
        let mut s = lock(&state);
        *s = PortScan { target: target.clone(), running: true, total: ports.len(), ..Default::default() };
    }
    thread::spawn(move || {
        let t0 = Instant::now();
        let Some(ip) = resolve(&target) else {
            let mut s = lock(&state);
            s.error = Some(format!("No se pudo resolver «{}»", target));
            s.running = false;
            ctx.request_repaint();
            return;
        };
        lock(&state).ip = Some(ip);
        let ports = Arc::new(ports);
        let idx = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..128 {
            let (ports, idx, state, stop, ctx) = (ports.clone(), idx.clone(), state.clone(), stop.clone(), ctx.clone());
            workers.push(thread::spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let i = idx.fetch_add(1, Ordering::Relaxed);
                let Some(&p) = ports.get(i) else { break };
                let addr = SocketAddr::new(ip, p);
                let r = tcp_probe(addr, Duration::from_millis(timeout_ms));
                let mut found = None;
                match r {
                    Probe::Open(rtt) => {
                        let banner = if banners { grab_banner(addr, Duration::from_millis(timeout_ms.max(800))) } else { String::new() };
                        found = Some(OpenPort { port: p, service: service_name(p).to_string(), banner, rtt });
                    }
                    Probe::Closed(_) => lock(&state).closed += 1,
                    Probe::Timeout => lock(&state).filtered += 1,
                }
                let mut s = lock(&state);
                if let Some(o) = found {
                    s.open.push(o);
                    s.open.sort_by_key(|o| o.port);
                }
                s.done += 1;
                if s.done % 32 == 0 || s.done == s.total {
                    ctx.request_repaint();
                }
            }));
        }
        for w in workers {
            let _ = w.join();
        }
        let mut s = lock(&state);
        s.running = false;
        s.elapsed = t0.elapsed().as_secs_f64();
        ctx.request_repaint();
    });
}
