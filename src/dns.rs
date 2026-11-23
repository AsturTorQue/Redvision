//! Cliente DNS propio (UDP con reintento por TCP) y análisis de dominios.
use crate::egui;
use crate::ids::Sev;
use crate::util::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

pub const TYPES: &[(&str, u16)] = &[
    ("A", 1), ("AAAA", 28), ("MX", 15), ("NS", 2), ("TXT", 16), ("CNAME", 5), ("SOA", 6),
    ("PTR", 12), ("SRV", 33), ("CAA", 257), ("HTTPS", 65), ("DNSKEY", 48), ("DS", 43),
];

pub fn type_name(t: u16) -> String {
    match t {
        41 => "OPT".into(),
        46 => "RRSIG".into(),
        255 => "ANY".into(),
        _ => TYPES
            .iter()
            .find(|(_, v)| *v == t)
            .map(|(n, _)| n.to_string())
            .unwrap_or_else(|| format!("TIPO{}", t)),
    }
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR (correcto)",
        1 => "FORMERR (formato)",
        2 => "SERVFAIL (fallo del servidor)",
        3 => "NXDOMAIN (no existe)",
        4 => "NOTIMP (no implementado)",
        5 => "REFUSED (rechazada)",
        _ => "otro",
    }
}

#[derive(Clone, Default)]
pub struct Rr {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Clone, Default)]
pub struct DnsMsg {
    pub id: u16,
    pub flags: u16,
    pub rcode: u8,
    pub questions: Vec<(String, u16)>,
    pub answers: Vec<Rr>,
    pub authority: Vec<Rr>,
    pub additional: Vec<Rr>,
}

impl DnsMsg {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub fn flag_text(&self) -> String {
        let mut v = Vec::new();
        if self.flags & 0x8000 != 0 { v.push("QR"); }
        if self.flags & 0x0400 != 0 { v.push("AA"); }
        if self.flags & 0x0200 != 0 { v.push("TC"); }
        if self.flags & 0x0100 != 0 { v.push("RD"); }
        if self.flags & 0x0080 != 0 { v.push("RA"); }
        if self.flags & 0x0020 != 0 { v.push("AD"); }
        if self.flags & 0x0010 != 0 { v.push("CD"); }
        v.join(" ")
    }
}

pub fn build_query(id: u16, name: &str, qtype: u16, dnssec: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = 0x0100 | if dnssec { 0x0020 } else { 0 };
    b.extend_from_slice(&flags.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&(if dnssec { 1u16 } else { 0 }).to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let l = &label.as_bytes()[..label.len().min(63)];
        b.push(l.len() as u8);
        b.extend_from_slice(l);
    }
    b.push(0);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    if dnssec {
        // Registro OPT (EDNS0) con el bit DO para pedir firmas DNSSEC.
        b.push(0);
        b.extend_from_slice(&41u16.to_be_bytes());
        b.extend_from_slice(&4096u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0x80, 0]);
        b.extend_from_slice(&0u16.to_be_bytes());
    }
    b
}

fn g16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}
fn g32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

fn read_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(pos)? as usize;
        if len == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *b.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 20 {
                return None;
            }
            pos = ptr;
            continue;
        }
        let l = b.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(l).to_string());
        pos += 1 + len;
        if labels.len() > 128 {
            return None;
        }
    }
    let name = if labels.is_empty() { ".".into() } else { labels.join(".") };
    Some((name, end?))
}

fn rdata_text(b: &[u8], start: usize, len: usize, t: u16) -> String {
    let rd = match b.get(start..start + len) {
        Some(r) => r,
        None => return "?".into(),
    };
    match t {
        1 if len == 4 => Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]).to_string(),
        28 if len == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rd);
            std::net::Ipv6Addr::from(a).to_string()
        }
        2 | 5 | 12 => read_name(b, start).map(|x| x.0).unwrap_or_default(),
        15 => format!(
            "{} {}",
            g16(b, start).unwrap_or(0),
            read_name(b, start + 2).map(|x| x.0).unwrap_or_default()
        ),
        16 => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < rd.len() {
                let l = rd[i] as usize;
                out.push(String::from_utf8_lossy(rd.get(i + 1..(i + 1 + l).min(rd.len())).unwrap_or(&[])).to_string());
                i += 1 + l;
            }
            out.join(" ")
        }
        6 => {
            let (m, p) = read_name(b, start).unwrap_or_default();
            let (r, p2) = read_name(b, p).unwrap_or_default();
            format!("{} {} serie {}", m, r, g32(b, p2).unwrap_or(0))
        }
        33 => format!(
            "prio {} peso {} puerto {} {}",
            g16(b, start).unwrap_or(0),
            g16(b, start + 2).unwrap_or(0),
            g16(b, start + 4).unwrap_or(0),
            read_name(b, start + 6).map(|x| x.0).unwrap_or_default()
        ),
        257 if len > 2 => {
            let tl = rd[1] as usize;
            let tag = String::from_utf8_lossy(rd.get(2..2 + tl).unwrap_or(&[])).to_string();
            let val = String::from_utf8_lossy(rd.get(2 + tl..).unwrap_or(&[])).to_string();
            format!("{} {} \"{}\"", rd[0], tag, val)
        }
        46 => format!("firma DNSSEC de {}", type_name(g16(b, start).unwrap_or(0))),
        48 => format!("clave DNSSEC ({} bytes)", len),
        43 => format!("resumen de clave DS ({} bytes)", len),
        _ => format!("{} bytes", len),
    }
}

pub fn parse(b: &[u8]) -> Option<DnsMsg> {
    if b.len() < 12 {
        return None;
    }
    let mut m = DnsMsg {
        id: g16(b, 0)?,
        flags: g16(b, 2)?,
        ..Default::default()
    };
    m.rcode = (m.flags & 0x000F) as u8;
    let qd = g16(b, 4)? as usize;
    let an = g16(b, 6)? as usize;
    let ns = g16(b, 8)? as usize;
    let ar = g16(b, 10)? as usize;
    if qd > 32 || an > 512 || ns > 512 || ar > 512 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..qd {
        let (n, p) = read_name(b, pos)?;
        let t = g16(b, p)?;
        pos = p + 4;
        m.questions.push((n, t));
    }
    for sec in 0..3 {
        let count = [an, ns, ar][sec];
        for _ in 0..count {
            let Some((n, p)) = read_name(b, pos) else { return Some(m) };
            let (Some(t), Some(ttl), Some(len)) = (g16(b, p), g32(b, p + 4), g16(b, p + 8)) else { return Some(m) };
            let start = p + 10;
            let len = len as usize;
            let rr = Rr { name: n, rtype: t, ttl, data: rdata_text(b, start, len, t) };
            match sec {
                0 => m.answers.push(rr),
                1 => m.authority.push(rr),
                _ => m.additional.push(rr),
            }
            pos = start + len;
        }
    }
    Some(m)
}

pub fn query(server: IpAddr, name: &str, qtype: u16, dnssec: bool, timeout: Duration) -> Result<(DnsMsg, f64), String> {
    let id = (rand_u64() & 0xFFFF) as u16;
    let q = build_query(id, name, qtype, dnssec);
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout)).ok();
    let addr = SocketAddr::new(server, 53);
    let t0 = Instant::now();
    sock.send_to(&q, addr).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, _) = sock.recv_from(&mut buf).map_err(|_| "Sin respuesta (tiempo agotado)".to_string())?;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        if let Some(m) = parse(&buf[..n]) {
            if m.id != id {
                continue;
            }
            if m.flags & 0x0200 != 0 {
                if let Ok(r) = query_tcp(server, &q, timeout) {
                    return Ok(r);
                }
            }
            return Ok((m, ms));
        }
        return Err("Respuesta no válida".into());
    }
}

fn query_tcp(server: IpAddr, q: &[u8], timeout: Duration) -> Result<(DnsMsg, f64), String> {
    let t0 = Instant::now();
    let mut s = TcpStream::connect_timeout(&SocketAddr::new(server, 53), timeout).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(timeout)).ok();
    let mut msg = (q.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(q);
    s.write_all(&msg).map_err(|e| e.to_string())?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; u16::from_be_bytes(lb) as usize];
    s.read_exact(&mut buf).map_err(|e| e.to_string())?;
    let m = parse(&buf).ok_or("Respuesta no válida")?;
    Ok((m, t0.elapsed().as_secs_f64() * 1000.0))
}

pub fn ptr_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

pub fn reverse_lookup(server: IpAddr, ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let (m, _) = query(server, &ptr_name(ip), 12, false, timeout).ok()?;
    m.answers.iter().find(|r| r.rtype == 12).map(|r| r.data.trim_end_matches('.').to_string())
}

// ---------------------------------------------------------------- análisis

#[derive(Clone)]
pub struct DnsFinding {
    pub sev: Sev,
    pub title: String,
    pub detail: String,
}

#[derive(Clone)]
pub struct ResolverResult {
    pub name: String,
    pub server: IpAddr,
    pub ms: Option<f64>,
    pub answers: Vec<String>,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct DnsState {
    pub running: bool,
    pub step: String,
    pub last: Option<(String, IpAddr, Result<(DnsMsg, f64), String>)>,
    pub resolvers: Vec<ResolverResult>,
    pub records: Vec<(String, Vec<String>)>,
    pub findings: Vec<DnsFinding>,
}

pub fn public_resolvers(system: &[IpAddr]) -> Vec<(String, IpAddr)> {
    let mut v: Vec<(String, IpAddr)> = system
        .iter()
        .take(2)
        .map(|ip| ("Sistema".to_string(), *ip))
        .collect();
    v.push(("Cloudflare".into(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    v.push(("Google".into(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    v.push(("Quad9".into(), IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
    v.push(("OpenDNS".into(), IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222))));
    v
}

pub fn start_query(state: Shared<DnsState>, server: IpAddr, name: String, qtype: u16, ctx: egui::Context) {
    lock(&state).running = true;
    thread::spawn(move || {
        let r = query(server, &name, qtype, true, Duration::from_secs(3));
        let mut s = lock(&state);
        s.last = Some((name, server, r));
        s.running = false;
        ctx.request_repaint();
    });
}

pub fn start_analysis(state: Shared<DnsState>, system: Vec<IpAddr>, domain: String, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        s.running = true;
        s.resolvers.clear();
        s.records.clear();
        s.findings.clear();
        s.step = "Comparando servidores DNS…".into();
    }
    thread::spawn(move || {
        let to = Duration::from_millis(2500);
        let set_step = |t: &str| {
            lock(&state).step = t.to_string();
            ctx.request_repaint();
        };
        let mut findings = Vec::new();
        // 1. Velocidad y coherencia entre servidores
        let resolvers = public_resolvers(&system);
        let mut results = Vec::new();
        for (name, ip) in &resolvers {
            let r = query(*ip, &domain, 1, false, to);
            let rr = match r {
                Ok((m, ms)) => ResolverResult {
                    name: name.clone(),
                    server: *ip,
                    ms: Some(ms),
                    answers: m.answers.iter().filter(|a| a.rtype == 1).map(|a| a.data.clone()).collect(),
                    error: if m.rcode != 0 { Some(rcode_name(m.rcode).into()) } else { None },
                },
                Err(e) => ResolverResult { name: name.clone(), server: *ip, ms: None, answers: vec![], error: Some(e) },
            };
            results.push(rr.clone());
            lock(&state).resolvers = results.clone();
            ctx.request_repaint();
        }
        if let Some(best) = results.iter().filter(|r| r.ms.is_some()).min_by(|a, b| a.ms.partial_cmp(&b.ms).unwrap()) {
            findings.push(DnsFinding {
                sev: Sev::Info,
                title: format!("Servidor más rápido: {} ({})", best.name, best.server),
                detail: format!("Respondió en {:.1} ms.", best.ms.unwrap_or(0.0)),
            });
        }
        if let Some(sys) = results.iter().find(|r| r.name == "Sistema") {
            match sys.ms {
                None => findings.push(DnsFinding {
                    sev: Sev::High,
                    title: "El DNS del sistema no responde".into(),
                    detail: "Las páginas tardarán en abrir o no abrirán. Revisa el router o usa un DNS público.".into(),
                }),
                Some(ms) if ms > 150.0 => findings.push(DnsFinding {
                    sev: Sev::Medium,
                    title: format!("DNS del sistema lento ({:.0} ms)", ms),
                    detail: "Un DNS por encima de 150 ms ralentiza la navegación.".into(),
                }),
                _ => {}
            }
            let cf = results.iter().find(|r| r.name == "Cloudflare");
            if let Some(cf) = cf {
                if !sys.answers.is_empty() && !cf.answers.is_empty() && !sys.answers.iter().any(|a| cf.answers.contains(a)) {
                    findings.push(DnsFinding {
                        sev: Sev::Low,
                        title: "Respuestas distintas entre tu DNS y uno público".into(),
                        detail: format!(
                            "Sistema: {} · Cloudflare: {}. Es normal en servicios con CDN, pero también puede indicar manipulación.",
                            sys.answers.join(", "),
                            cf.answers.join(", ")
                        ),
                    });
                }
            }
        }
        let server = system.first().copied().unwrap_or(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        // 2. Registros del dominio
        set_step("Consultando registros del dominio…");
        let mut records = Vec::new();
        for (tn, t) in [("A", 1u16), ("AAAA", 28), ("MX", 15), ("NS", 2), ("TXT", 16), ("SOA", 6), ("CAA", 257)] {
            let vals = match query(server, &domain, t, false, to) {
                Ok((m, _)) => m.answers.iter().filter(|a| a.rtype == t).map(|a| a.data.clone()).collect(),
                Err(e) => vec![format!("(error: {})", e)],
            };
            records.push((tn.to_string(), vals));
            lock(&state).records = records.clone();
            ctx.request_repaint();
        }
        let get = |n: &str| records.iter().find(|r| r.0 == n).map(|r| r.1.clone()).unwrap_or_default();
        if get("A").is_empty() && get("AAAA").is_empty() {
            findings.push(DnsFinding { sev: Sev::Medium, title: "El dominio no tiene dirección (A/AAAA)".into(), detail: "No se puede abrir como web.".into() });
        }
        if get("AAAA").is_empty() {
            findings.push(DnsFinding { sev: Sev::Info, title: "Sin IPv6 (AAAA)".into(), detail: "El dominio solo responde por IPv4.".into() });
        }
        let txt = get("TXT");
        if !get("MX").is_empty() {
            if !txt.iter().any(|t| t.contains("v=spf1")) {
                findings.push(DnsFinding { sev: Sev::Medium, title: "Falta registro SPF".into(), detail: "Sin SPF es más fácil suplantar correos de este dominio.".into() });
            }
            let dmarc = query(server, &format!("_dmarc.{}", domain), 16, false, to)
                .map(|(m, _)| m.answers.iter().any(|a| a.data.contains("v=DMARC1")))
                .unwrap_or(false);
            if !dmarc {
                findings.push(DnsFinding { sev: Sev::Medium, title: "Falta política DMARC".into(), detail: "Añade _dmarc con v=DMARC1 para proteger el correo.".into() });
            } else {
                findings.push(DnsFinding { sev: Sev::Info, title: "DMARC configurado".into(), detail: "El dominio publica una política DMARC.".into() });
            }
        }
        if get("CAA").is_empty() {
            findings.push(DnsFinding { sev: Sev::Low, title: "Sin registro CAA".into(), detail: "CAA limita qué autoridades pueden emitir certificados.".into() });
        }
        // 3. DNSSEC
        set_step("Comprobando DNSSEC…");
        match query(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), &domain, 1, true, to) {
            Ok((m, _)) => {
                let signed = m.answers.iter().any(|a| a.rtype == 46);
                if m.flags & 0x0020 != 0 || signed {
                    findings.push(DnsFinding { sev: Sev::Info, title: "DNSSEC válido".into(), detail: "Las respuestas están firmadas y verificadas (bit AD).".into() });
                } else {
                    findings.push(DnsFinding { sev: Sev::Low, title: "Sin DNSSEC".into(), detail: "Las respuestas no están firmadas; son más fáciles de falsificar.".into() });
                }
            }
            Err(e) => findings.push(DnsFinding { sev: Sev::Info, title: "No se pudo comprobar DNSSEC".into(), detail: e }),
        }
        // 4. Secuestro de NXDOMAIN
        set_step("Buscando redirecciones de dominios inexistentes…");
        let fake = format!("no-existe-{:x}.example.com", rand_u64() & 0xFFFFFFFF);
        match query(server, &fake, 1, false, to) {
            Ok((m, _)) if m.rcode == 0 && !m.answers.is_empty() => findings.push(DnsFinding {
                sev: Sev::High,
                title: "Tu DNS responde a dominios inexistentes".into(),
                detail: format!(
                    "{} devolvió {}. El proveedor o un intruso redirige errores (secuestro de NXDOMAIN).",
                    fake,
                    m.answers.first().map(|a| a.data.clone()).unwrap_or_default()
                ),
            }),
            Ok(_) => findings.push(DnsFinding { sev: Sev::Info, title: "Sin secuestro de NXDOMAIN".into(), detail: "Los dominios inexistentes se informan correctamente.".into() }),
            Err(_) => {}
        }
        let mut s = lock(&state);
        s.findings = findings;
        s.running = false;
        s.step = "Análisis terminado".into();
        ctx.request_repaint();
    });
}
