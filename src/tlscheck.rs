//! Comprobación de certificados HTTPS sin librerías de cifrado.
//! En TLS 1.2 (y anteriores) el servidor envía su certificado sin cifrar durante el saludo, así que
//! basta con hacer el saludo hasta ese punto y leerlo (formato X.509/DER). Para saber qué versiones
//! de TLS acepta se prueba cada una por separado. No se verifica la firma de la cadena de confianza.
use crate::i18n::{tf, tr};
use crate::ids::Sev;
use crate::lanaudit::LanFinding;
use crate::util::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- X.509 mínimo (DER)

/// Lee un elemento TLV: (etiqueta, contenido, resto).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *b.get(2 + i)? as usize;
        }
        (v, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(hdr..end)?, b.get(end..)?))
}

fn children(b: &[u8]) -> Vec<(u8, &[u8])> {
    let mut v = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let Some((t, c, r)) = tlv(rest) else { break };
        v.push((t, c));
        rest = r;
    }
    v
}

fn oid(b: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v = 0u64;
    for &x in b {
        v = (v << 7) | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    let Some(&first) = parts.first() else { return String::new() };
    let mut s = format!("{}.{}", (first / 40).min(2), if first < 80 { first % 40 } else { first - 80 });
    for p in &parts[1..] {
        s.push_str(&format!(".{}", p));
    }
    s
}

fn text(tag: u8, b: &[u8]) -> String {
    if tag == 0x1e {
        let u: Vec<u16> = b.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(b).to_string()
    }
}

/// (CN, O, nombre completo) de un Name.
fn name(b: &[u8]) -> (String, String, String) {
    let (mut cn, mut org, mut full) = (String::new(), String::new(), Vec::new());
    for (_, set) in children(b) {
        for (_, atv) in children(set) {
            let c = children(atv);
            if c.len() == 2 {
                let o = oid(c[0].1);
                let v = text(c[1].0, c[1].1);
                let label = match o.as_str() {
                    "2.5.4.3" => {
                        cn = v.clone();
                        "CN"
                    }
                    "2.5.4.10" => {
                        org = v.clone();
                        "O"
                    }
                    "2.5.4.6" => "C",
                    "2.5.4.7" => "L",
                    "2.5.4.8" => "ST",
                    "2.5.4.11" => "OU",
                    _ => continue,
                };
                full.push(format!("{}={}", label, v));
            }
        }
    }
    (cn, org, full.join(", "))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn time(tag: u8, b: &[u8]) -> i64 {
    let s = String::from_utf8_lossy(b);
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    let n = |a: usize, l: usize| -> i64 { digits.get(a..a + l).and_then(|x| x.parse().ok()).unwrap_or(0) };
    let (y, rest) = if tag == 0x17 {
        let yy = n(0, 2);
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
    } else {
        (n(0, 4), 4)
    };
    days_from_civil(y, n(rest, 2), n(rest + 2, 2)) * 86400 + n(rest + 4, 2) * 3600 + n(rest + 6, 2) * 60 + n(rest + 8, 2)
}

#[derive(Clone, Default)]
pub struct Cert {
    pub subject_cn: String,
    pub subject: String,
    pub issuer_cn: String,
    pub issuer_org: String,
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
    pub sans: Vec<String>,
    pub sig_alg: String,
    pub key: String,
    pub key_bits: u32,
    pub serial: String,
    pub self_signed: bool,
    pub is_ca: bool,
}

fn sig_name(o: &str) -> String {
    match o {
        "1.2.840.113549.1.1.5" => "SHA-1 con RSA".into(),
        "1.2.840.113549.1.1.4" => "MD5 con RSA".into(),
        "1.2.840.113549.1.1.11" => "SHA-256 con RSA".into(),
        "1.2.840.113549.1.1.12" => "SHA-384 con RSA".into(),
        "1.2.840.113549.1.1.13" => "SHA-512 con RSA".into(),
        "1.2.840.113549.1.1.10" => "RSA-PSS".into(),
        "1.2.840.10045.4.1" => "SHA-1 con ECDSA".into(),
        "1.2.840.10045.4.3.2" => "SHA-256 con ECDSA".into(),
        "1.2.840.10045.4.3.3" => "SHA-384 con ECDSA".into(),
        "1.2.840.10045.4.3.4" => "SHA-512 con ECDSA".into(),
        "1.3.101.112" => "Ed25519".into(),
        other => other.to_string(),
    }
}

pub fn parse_cert(der: &[u8]) -> Option<Cert> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, rest) = tlv(cert)?;
    let (_, sigalg, _) = tlv(rest)?;
    let mut c = Cert { sig_alg: sig_name(&oid(children(sigalg).first()?.1)), ..Default::default() };
    let items = children(tbs);
    let mut i = 0;
    if items.get(i)?.0 == 0xa0 {
        i += 1; // versión
    }
    let (_, serial) = *items.get(i)?;
    c.serial = serial.iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join(":");
    // items[i+1] = algoritmo de firma, [i+2] = emisor, [i+3] = validez, [i+4] = sujeto, [i+5] = clave
    let issuer_raw = items.get(i + 2)?.1;
    let (icn, iorg, ifull) = name(issuer_raw);
    c.issuer_cn = icn;
    c.issuer_org = iorg;
    c.issuer = ifull;
    let val = children(items.get(i + 3)?.1);
    c.not_before = time(val.first()?.0, val.first()?.1);
    c.not_after = time(val.get(1)?.0, val.get(1)?.1);
    let subject_raw = items.get(i + 4)?.1;
    let (scn, _, sfull) = name(subject_raw);
    c.subject_cn = scn;
    c.subject = sfull;
    c.self_signed = issuer_raw == subject_raw;
    // clave pública
    let spki = children(items.get(i + 5)?.1);
    let alg = children(spki.first()?.1);
    let alg_oid = oid(alg.first()?.1);
    let bits = spki.get(1)?.1;
    match alg_oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let inner = bits.get(1..).unwrap_or(&[]);
            if let Some((_, seq, _)) = tlv(inner) {
                if let Some((_, n)) = children(seq).first().copied() {
                    let n = if n.first() == Some(&0) { &n[1..] } else { n };
                    c.key_bits = (n.len() * 8) as u32;
                }
            }
            c.key = format!("RSA {}", c.key_bits);
        }
        "1.2.840.10045.2.1" => {
            let curve = alg.get(1).map(|x| oid(x.1)).unwrap_or_default();
            let (n, b) = match curve.as_str() {
                "1.2.840.10045.3.1.7" => ("P-256", 256),
                "1.3.132.0.34" => ("P-384", 384),
                "1.3.132.0.35" => ("P-521", 521),
                _ => ("EC", 0),
            };
            c.key = format!("ECDSA {}", n);
            c.key_bits = b;
        }
        "1.3.101.112" => {
            c.key = "Ed25519".into();
            c.key_bits = 256;
        }
        other => c.key = other.to_string(),
    }
    // extensiones
    if let Some((_, ext_wrap)) = items.iter().skip(i + 6).find(|(t, _)| *t == 0xa3).copied() {
        if let Some((_, exts, _)) = tlv(ext_wrap) {
            for (_, e) in children(exts) {
                let f = children(e);
                let Some(o) = f.first().map(|x| oid(x.1)) else { continue };
                let value = f.last().map(|x| x.1).unwrap_or(&[]);
                match o.as_str() {
                    "2.5.29.17" => {
                        if let Some((_, seq, _)) = tlv(value) {
                            for (t, g) in children(seq) {
                                match t {
                                    0x82 => c.sans.push(String::from_utf8_lossy(g).to_string()),
                                    0x87 if g.len() == 4 => c.sans.push(format!("{}.{}.{}.{}", g[0], g[1], g[2], g[3])),
                                    _ => {}
                                }
                            }
                        }
                    }
                    "2.5.29.19" => {
                        if let Some((_, seq, _)) = tlv(value) {
                            c.is_ca = children(seq).first().map(|(t, v)| *t == 0x01 && v.first() == Some(&0xff)).unwrap_or(false);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Some(c)
}

/// ¿Cubre el certificado este nombre? Admite comodines de un solo nivel (*.ejemplo.com).
pub fn matches_host(c: &Cert, host: &str) -> bool {
    let host = host.to_lowercase();
    let names: Vec<String> = if c.sans.is_empty() { vec![c.subject_cn.to_lowercase()] } else { c.sans.iter().map(|s| s.to_lowercase()).collect() };
    names.iter().any(|n| {
        if let Some(rest) = n.strip_prefix("*.") {
            host.split_once('.').map(|(first, tail)| !first.is_empty() && tail == rest).unwrap_or(false)
        } else {
            *n == host
        }
    })
}

// ---------------------------------------------------------------- saludo TLS

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ver {
    V10,
    V11,
    V12,
    V13,
}

impl Ver {
    pub fn label(&self) -> &'static str {
        match self {
            Ver::V10 => "TLS 1.0",
            Ver::V11 => "TLS 1.1",
            Ver::V12 => "TLS 1.2",
            Ver::V13 => "TLS 1.3",
        }
    }
    fn wire(&self) -> u16 {
        match self {
            Ver::V10 => 0x0301,
            Ver::V11 => 0x0302,
            _ => 0x0303,
        }
    }
}

fn rnd(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n + 8);
    while v.len() < n {
        v.extend_from_slice(&rand_u64().to_le_bytes());
    }
    v.truncate(n);
    v
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn ext(out: &mut Vec<u8>, t: u16, data: &[u8]) {
    put16(out, t);
    put16(out, data.len() as u16);
    out.extend_from_slice(data);
}

fn client_hello(host: &str, ver: Ver) -> Vec<u8> {
    let mut b = Vec::new();
    put16(&mut b, ver.wire());
    b.extend_from_slice(&rnd(32));
    if ver == Ver::V13 {
        b.push(32);
        b.extend_from_slice(&rnd(32));
    } else {
        b.push(0);
    }
    let mut suites: Vec<u16> = Vec::new();
    if ver == Ver::V13 {
        suites.extend([0x1301, 0x1302, 0x1303]);
    }
    suites.extend([0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a]);
    put16(&mut b, (suites.len() * 2) as u16);
    for s in suites {
        put16(&mut b, s);
    }
    b.extend_from_slice(&[1, 0]);
    let mut e = Vec::new();
    // server_name
    let h = host.as_bytes();
    let mut sn = Vec::new();
    put16(&mut sn, (h.len() + 3) as u16);
    sn.push(0);
    put16(&mut sn, h.len() as u16);
    sn.extend_from_slice(h);
    ext(&mut e, 0, &sn);
    ext(&mut e, 10, &[0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]);
    ext(&mut e, 11, &[1, 0]);
    let algs: [u16; 9] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];
    let mut sa = Vec::new();
    put16(&mut sa, (algs.len() * 2) as u16);
    for a in algs {
        put16(&mut sa, a);
    }
    ext(&mut e, 13, &sa);
    ext(&mut e, 0xff01, &[0]);
    if ver == Ver::V13 {
        ext(&mut e, 43, &[4, 0x03, 0x04, 0x03, 0x03]);
        let mut ks = Vec::new();
        put16(&mut ks, 36);
        put16(&mut ks, 0x001d);
        put16(&mut ks, 32);
        ks.extend_from_slice(&rnd(32));
        ext(&mut e, 51, &ks);
    }
    put16(&mut b, e.len() as u16);
    b.extend_from_slice(&e);
    let mut hs = vec![1, 0, (b.len() >> 8) as u8, b.len() as u8];
    hs.splice(1..2, [(b.len() >> 16) as u8]);
    hs.extend_from_slice(&b);
    let mut rec = vec![0x16, 0x03, 0x01];
    put16(&mut rec, hs.len() as u16);
    rec.extend_from_slice(&hs);
    rec
}

#[derive(Default, Clone, Debug)]
pub struct Probe {
    /// El servidor respondió con un ServerHello de esta versión.
    pub accepted: bool,
    pub certs: Vec<Vec<u8>>,
    pub alert: Option<u8>,
}

fn probe(addr: SocketAddr, host: &str, ver: Ver) -> Result<Probe, String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    s.set_nodelay(true).ok();
    s.write_all(&client_hello(host, ver)).map_err(|e| e.to_string())?;
    let mut p = Probe::default();
    let mut hs: Vec<u8> = Vec::new();
    let mut raw: Vec<u8> = Vec::new();
    let t0 = Instant::now();
    let mut buf = [0u8; 16384];
    'outer: while t0.elapsed() < Duration::from_secs(6) {
        let n = match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(_) => break,
        };
        raw.extend_from_slice(&buf[..n]);
        // registros completos
        loop {
            if raw.len() < 5 {
                break;
            }
            let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
            if raw.len() < 5 + len {
                break;
            }
            let (typ, body) = (raw[0], raw[5..5 + len].to_vec());
            raw.drain(..5 + len);
            match typ {
                0x15 if body.len() >= 2 => {
                    p.alert = Some(body[1]);
                    break 'outer;
                }
                0x16 => hs.extend_from_slice(&body),
                _ => break 'outer, // datos cifrados: ya no hay nada legible
            }
            // mensajes de saludo completos
            while hs.len() >= 4 {
                let ml = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
                if hs.len() < 4 + ml {
                    break;
                }
                let msg: Vec<u8> = hs[4..4 + ml].to_vec();
                let mt = hs[0];
                hs.drain(..4 + ml);
                match mt {
                    2 => {
                        // ServerHello
                        let mut selected = u16::from_be_bytes([*msg.first().unwrap_or(&0), *msg.get(1).unwrap_or(&0)]);
                        // buscar la extensión supported_versions (TLS 1.3)
                        if msg.len() > 35 {
                            let sid = msg[34] as usize;
                            let ex = 35 + sid + 3;
                            if msg.len() >= ex + 2 {
                                let mut i = ex + 2;
                                while i + 4 <= msg.len() {
                                    let (t, l) = (u16::from_be_bytes([msg[i], msg[i + 1]]), u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize);
                                    if t == 43 && l == 2 && i + 6 <= msg.len() {
                                        selected = u16::from_be_bytes([msg[i + 4], msg[i + 5]]);
                                    }
                                    i += 4 + l;
                                }
                            }
                        }
                        p.accepted = match ver {
                            Ver::V13 => selected == 0x0304,
                            _ => selected == ver.wire(),
                        };
                        if !p.accepted || ver == Ver::V13 {
                            break 'outer;
                        }
                    }
                    11 => {
                        // Certificate (TLS 1.2 y anteriores)
                        let mut i = 3;
                        while i + 3 <= msg.len() {
                            let l = ((msg[i] as usize) << 16) | ((msg[i + 1] as usize) << 8) | msg[i + 2] as usize;
                            if i + 3 + l > msg.len() {
                                break;
                            }
                            p.certs.push(msg[i + 3..i + 3 + l].to_vec());
                            i += 3 + l;
                        }
                        break 'outer;
                    }
                    14 => break 'outer,
                    _ => {}
                }
            }
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
    Ok(p)
}

// ---------------------------------------------------------------- informe

#[derive(Clone, Default)]
pub struct CertReport {
    pub host: String,
    pub port: u16,
    pub error: Option<String>,
    pub certs: Vec<Cert>,
    pub versions: Vec<(Ver, bool)>,
    pub findings: Vec<LanFinding>,
}

impl CertReport {
    pub fn days_left(&self) -> Option<i64> {
        self.certs.first().map(|c| (c.not_after - now_secs() as i64).div_euclid(86400))
    }
}

pub fn parse_target(s: &str) -> Option<(String, u16)> {
    let s = s.trim().trim_start_matches("https://").trim_start_matches("http://");
    let s = s.split('/').next().unwrap_or("");
    if s.is_empty() {
        return None;
    }
    match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((s.to_string(), 443)),
    }
}

pub fn check(host: &str, port: u16) -> CertReport {
    let mut r = CertReport { host: host.to_string(), port, ..Default::default() };
    let Some(addr) = (host, port).to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        r.error = Some(tf("No se pudo resolver «{}»", &[&host]));
        return r;
    };
    let results: Vec<(Ver, Result<Probe, String>)> = std::thread::scope(|sc| {
        let hs: Vec<_> = [Ver::V10, Ver::V11, Ver::V12, Ver::V13].into_iter().map(|v| (v, sc.spawn(move || probe(addr, host, v)))).collect();
        hs.into_iter().map(|(v, h)| (v, h.join().unwrap_or_else(|_| Err("error".into())))).collect()
    });
    if results.iter().all(|(_, p)| p.is_err()) {
        r.error = Some(tf("No se pudo conectar con {}:{}: {}", &[&host, &port, &results[2].1.as_ref().err().cloned().unwrap_or_default()]));
        return r;
    }
    for (v, p) in &results {
        r.versions.push((*v, p.as_ref().map(|p| p.accepted).unwrap_or(false)));
    }
    let tls12 = results.iter().find(|(v, _)| *v == Ver::V12).and_then(|(_, p)| p.as_ref().ok());
    let der_list: Vec<Vec<u8>> = results.iter().filter_map(|(_, p)| p.as_ref().ok()).find(|p| !p.certs.is_empty()).map(|p| p.certs.clone()).unwrap_or_default();
    r.certs = der_list.iter().filter_map(|d| parse_cert(d)).collect();
    if r.certs.is_empty() {
        let any = r.versions.iter().any(|(_, ok)| *ok);
        r.error = Some(if any && tls12.map(|p| !p.accepted).unwrap_or(true) {
            tr("El servidor solo acepta TLS 1.3, que cifra su certificado: con este método no se puede leer.").into()
        } else {
            tr("El servidor no respondió con un certificado (¿no es un servicio HTTPS?).").into()
        });
    }
    r.findings = findings(&r);
    r
}

fn private_ip(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().map(|ip| ip.is_private() || ip.is_loopback() || ip.is_link_local()).unwrap_or(false)
}

pub fn findings(r: &CertReport) -> Vec<LanFinding> {
    let mut v = Vec::new();
    let add = |v: &mut Vec<LanFinding>, sev: Sev, title: String, detail: String, fix: &str| {
        v.push(LanFinding { sev, title, detail, fix: tr(fix).to_string() });
    };
    if let Some(c) = r.certs.first() {
        let days = (c.not_after - now_secs() as i64).div_euclid(86400);
        if c.not_before > now_secs() as i64 {
            add(&mut v, Sev::High, tr("El certificado todavía no es válido").into(), tr("Su fecha de inicio es futura: el reloj del equipo o del servidor está mal.").into(), "Revisa la fecha y hora de este equipo y del servidor.");
        }
        if days < 0 {
            add(&mut v, Sev::Critical, tf("Certificado caducado hace {} días", &[&-days]), tr("Los navegadores mostrarán un aviso de seguridad y muchos programas se negarán a conectar.").into(), "Renueva el certificado cuanto antes.");
        } else if days <= 7 {
            add(&mut v, Sev::High, tf("El certificado caduca en {} días", &[&days]), tr("Está a punto de caducar.").into(), "Renueva el certificado ahora (y comprueba que la renovación automática funciona).");
        } else if days <= 30 {
            add(&mut v, Sev::Medium, tf("El certificado caduca en {} días", &[&days]), tr("Conviene renovarlo pronto.").into(), "Renueva el certificado o revisa la renovación automática.");
        }
        if !private_ip(&r.host) && !matches_host(c, &r.host) {
            add(&mut v, Sev::High, tr("El certificado no es de este nombre").into(), tf("Cubre: {}. Se consultó: {}.", &[&if c.sans.is_empty() { c.subject_cn.clone() } else { c.sans.iter().take(6).cloned().collect::<Vec<_>>().join(", ") }, &r.host]),
                "Usa un certificado que incluya este nombre (o conéctate con el nombre correcto).");
        }
        if c.self_signed {
            let sev = if private_ip(&r.host) { Sev::Low } else { Sev::High };
            add(&mut v, sev, tr("Certificado autofirmado").into(), tr("Ninguna autoridad lo avala, así que los navegadores no se fían de él.").into(), "Usa un certificado de una autoridad (por ejemplo Let's Encrypt, que es gratuito).");
        }
        if c.sig_alg.contains("SHA-1") || c.sig_alg.contains("MD5") {
            add(&mut v, Sev::High, tf("Firma débil: {}", &[&c.sig_alg]), tr("Ese algoritmo se puede falsificar; los navegadores ya no lo aceptan.").into(), "Emite un certificado nuevo con SHA-256 o superior.");
        }
        if c.key.starts_with("RSA") && c.key_bits > 0 && c.key_bits < 2048 {
            add(&mut v, Sev::High, tf("Clave RSA corta ({} bits)", &[&c.key_bits]), tr("Las claves de menos de 2048 bits se consideran inseguras.").into(), "Genera una clave RSA de 2048 bits o más (o ECDSA P-256).");
        }
    }
    let ok = |ver: Ver| r.versions.iter().any(|(v, ok)| *v == ver && *ok);
    if ok(Ver::V10) || ok(Ver::V11) {
        let which: Vec<&str> = [Ver::V10, Ver::V11].iter().filter(|x| ok(**x)).map(|x| x.label()).collect();
        add(&mut v, Sev::Medium, tf("Acepta versiones antiguas de TLS: {}", &[&which.join(", ")]), tr("TLS 1.0 y 1.1 están obsoletos y tienen fallos conocidos.").into(), "Desactiva TLS 1.0 y 1.1 en el servidor y deja solo TLS 1.2 y 1.3.");
    }
    if !r.versions.is_empty() && !ok(Ver::V13) && (ok(Ver::V12)) {
        add(&mut v, Sev::Info, tr("No admite TLS 1.3").into(), tr("TLS 1.3 es más rápido y seguro.").into(), "Actualiza el servidor web o su biblioteca TLS para activar TLS 1.3.");
    }
    v.sort_by(|a, b| b.sev.cmp(&a.sev));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_math() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(days_from_civil(2024, 1, 1) * 86400, 1704067200);
        assert_eq!(time(0x17, b"240101000000Z"), 1704067200);
        assert_eq!(time(0x18, b"20240101000000Z"), 1704067200);
    }

    #[test]
    fn wildcard() {
        let c = Cert { sans: vec!["*.example.com".into(), "example.com".into()], ..Default::default() };
        assert!(matches_host(&c, "www.example.com"));
        assert!(matches_host(&c, "example.com"));
        assert!(!matches_host(&c, "a.b.example.com"));
        assert!(!matches_host(&c, "evil.com"));
    }

    #[test]
    fn targets() {
        assert_eq!(parse_target("https://debian.org/x"), Some(("debian.org".into(), 443)));
        assert_eq!(parse_target("mail.example.com:993"), Some(("mail.example.com".into(), 993)));
    }

    /// Certificados reales (necesita Internet): `cargo test -- --ignored --nocapture certs_live`
    #[test]
    #[ignore]
    fn certs_live() {
        for h in ["debian.org", "wikipedia.org", "expired.badssl.com", "self-signed.badssl.com", "wrong.host.badssl.com", "tls-v1-0.badssl.com:1010"] {
            let (host, port) = parse_target(h).unwrap();
            let r = check(&host, port);
            let c = r.certs.first();
            println!(
                "{} -> err={:?} cn={:?} issuer={:?} dias={:?} key={:?} firma={:?} sans={} versiones={:?}",
                h,
                r.error,
                c.map(|c| c.subject_cn.clone()),
                c.map(|c| c.issuer_cn.clone()),
                r.days_left(),
                c.map(|c| c.key.clone()),
                c.map(|c| c.sig_alg.clone()),
                c.map(|c| c.sans.len()).unwrap_or(0),
                r.versions.iter().map(|(v, ok)| format!("{}={}", v.label(), ok)).collect::<Vec<_>>()
            );
            for f in &r.findings {
                println!("     [{:?}] {}", f.sev, f.title);
            }
        }
    }
}
