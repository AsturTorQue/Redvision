//! Decodificador de paquetes: Ethernet, ARP, IPv4/IPv6, TCP/UDP/ICMP y protocolos de aplicación.
use crate::util::{printable, service_name};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Default)]
pub struct Layer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

impl Layer {
    fn new(n: impl Into<String>) -> Self {
        Layer { name: n.into(), fields: Vec::new() }
    }
    fn f(&mut self, k: &str, v: impl ToString) {
        self.fields.push((k.to_string(), v.to_string()));
    }
}

#[derive(Clone)]
pub struct ArpInfo {
    pub op: u16,
    pub sip: Ipv4Addr,
    pub smac: String,
    pub tip: Ipv4Addr,
}

#[derive(Clone, Default)]
pub struct Summary {
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub info: String,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub sport: u16,
    pub dport: u16,
    pub l4: u8,
    pub tcp_flags: u8,
    pub src_mac: String,
    pub dst_mac: String,
    pub dns_qname: Option<String>,
    pub dns_response: bool,
    pub dns_answers: Vec<String>,
    pub sni: Option<String>,
    pub http: Option<String>,
    pub http_host: Option<String>,
    pub arp: Option<ArpInfo>,
    pub icmp_type: Option<u8>,
    pub dhcp: Option<(u8, String)>,
    pub payload_start: usize,
    pub payload_len: usize,
}

#[derive(Clone)]
pub struct Packet {
    pub no: u64,
    pub ts: f64,
    pub data: Vec<u8>,
    pub orig_len: u32,
    pub s: Summary,
}

fn u16at(d: &[u8], i: usize) -> u16 {
    if i + 1 < d.len() { u16::from_be_bytes([d[i], d[i + 1]]) } else { 0 }
}
fn u32at(d: &[u8], i: usize) -> u32 {
    if i + 3 < d.len() { u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) } else { 0 }
}
fn g16(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?]))
}

pub fn mac(d: &[u8]) -> String {
    d.iter().take(6).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

fn ethertype_name(et: u16) -> &'static str {
    match et {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "VLAN",
        0x88CC => "LLDP",
        0x888E => "EAPOL",
        0x8863 | 0x8864 => "PPPoE",
        0x8847 | 0x8848 => "MPLS",
        0x88E5 => "MACsec",
        0x893A => "IEEE1905",
        0x9000 => "Loopback",
        _ => "Ethernet",
    }
}

pub fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "IP",
    }
}

pub fn tcp_flags_text(f: u8) -> String {
    let names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")];
    let v: Vec<&str> = names.iter().filter(|(b, _)| f & b != 0).map(|(_, n)| *n).collect();
    if v.is_empty() { "ninguno".into() } else { v.join(", ") }
}

pub fn dissect(d: &[u8]) -> (Summary, Vec<Layer>) {
    let mut s = Summary::default();
    let mut ls = Vec::new();
    let mut fr = Layer::new("Trama");
    fr.f("Bytes capturados", d.len());
    ls.push(fr);
    if d.len() < 14 {
        s.proto = "?".into();
        s.info = "Trama demasiado corta".into();
        return (s, ls);
    }
    s.dst_mac = mac(&d[0..6]);
    s.src_mac = mac(&d[6..12]);
    let mut et = u16at(d, 12);
    let mut off = 14;
    let mut eth = Layer::new("Ethernet II");
    eth.f("Destino", &s.dst_mac);
    eth.f("Origen", &s.src_mac);
    if et == 0x8100 && d.len() >= 18 {
        eth.f("VLAN", u16at(d, 14) & 0x0fff);
        et = u16at(d, 16);
        off = 18;
    }
    s.src = s.src_mac.clone();
    s.dst = s.dst_mac.clone();
    if et < 0x0600 {
        eth.f("Tipo", "802.3 con longitud (LLC)");
        ls.push(eth);
        let stp = d.len() > off + 2 && d[off] == 0x42 && d[off + 1] == 0x42;
        s.proto = if stp { "STP".into() } else { "LLC".into() };
        s.info = if stp { "Árbol de expansión (Spanning Tree)".into() } else { "Trama LLC".into() };
        return (s, ls);
    }
    eth.f("Tipo", format!("0x{:04x} ({})", et, ethertype_name(et)));
    ls.push(eth);
    match et {
        0x0806 => arp(&d[off..], &mut s, &mut ls),
        0x0800 => ipv4(d, off, &mut s, &mut ls),
        0x86DD => ipv6(d, off, &mut s, &mut ls),
        _ => {
            s.proto = ethertype_name(et).to_string();
            s.info = format!("EtherType 0x{:04x}", et);
        }
    }
    (s, ls)
}

fn arp(p: &[u8], s: &mut Summary, ls: &mut Vec<Layer>) {
    s.proto = "ARP".into();
    if p.len() < 28 {
        s.info = "ARP truncado".into();
        return;
    }
    let op = u16at(p, 6);
    let sha = mac(&p[8..14]);
    let spa = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    let tha = mac(&p[18..24]);
    let tpa = Ipv4Addr::new(p[24], p[25], p[26], p[27]);
    let mut l = Layer::new("ARP");
    l.f("Operación", if op == 1 { "Petición (1)" } else if op == 2 { "Respuesta (2)" } else { "Otra" });
    l.f("MAC emisor", &sha);
    l.f("IP emisor", spa);
    l.f("MAC destino", &tha);
    l.f("IP destino", tpa);
    ls.push(l);
    s.src = spa.to_string();
    s.dst = tpa.to_string();
    s.info = if op == 1 {
        if spa == tpa { format!("ARP gratuito: {} anuncia {}", spa, sha) } else { format!("¿Quién tiene {}? Responder a {}", tpa, spa) }
    } else {
        format!("{} está en {}", spa, sha)
    };
    s.arp = Some(ArpInfo { op, sip: spa, smac: sha, tip: tpa });
}

fn ipv4(d: &[u8], off: usize, s: &mut Summary, ls: &mut Vec<Layer>) {
    let p = &d[off..];
    s.proto = "IPv4".into();
    if p.len() < 20 {
        s.info = "Cabecera IPv4 truncada".into();
        return;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let total = u16at(p, 2) as usize;
    let ff = u16at(p, 6);
    let ttl = p[8];
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    s.src_ip = Some(IpAddr::V4(src));
    s.dst_ip = Some(IpAddr::V4(dst));
    s.src = src.to_string();
    s.dst = dst.to_string();
    let mut l = Layer::new("IPv4");
    l.f("Longitud cabecera", format!("{} bytes", ihl));
    l.f("Longitud total", total);
    l.f("Identificación", format!("0x{:04x}", u16at(p, 4)));
    let mut fl = Vec::new();
    if ff & 0x4000 != 0 { fl.push("No fragmentar"); }
    if ff & 0x2000 != 0 { fl.push("Más fragmentos"); }
    l.f("Indicadores", if fl.is_empty() { "ninguno".into() } else { fl.join(", ") });
    l.f("Desplazamiento", (ff & 0x1fff) * 8);
    l.f("TTL", ttl);
    l.f("Protocolo", format!("{} ({})", proto, ip_proto_name(proto)));
    l.f("Origen", src);
    l.f("Destino", dst);
    ls.push(l);
    if ihl < 20 || ihl > p.len() {
        return;
    }
    if ff & 0x1fff != 0 {
        s.info = "Fragmento IP".into();
        return;
    }
    let end = off + total.clamp(ihl, p.len());
    s.info = format!("Protocolo {}", ip_proto_name(proto));
    transport(d, off + ihl, end, proto, s, ls);
}

fn ipv6(d: &[u8], off: usize, s: &mut Summary, ls: &mut Vec<Layer>) {
    let p = &d[off..];
    s.proto = "IPv6".into();
    if p.len() < 40 {
        s.info = "Cabecera IPv6 truncada".into();
        return;
    }
    let plen = u16at(p, 4) as usize;
    let mut nh = p[6];
    let hlim = p[7];
    let mut a = [0u8; 16];
    a.copy_from_slice(&p[8..24]);
    let src = Ipv6Addr::from(a);
    a.copy_from_slice(&p[24..40]);
    let dst = Ipv6Addr::from(a);
    s.src_ip = Some(IpAddr::V6(src));
    s.dst_ip = Some(IpAddr::V6(dst));
    s.src = src.to_string();
    s.dst = dst.to_string();
    let mut l = Layer::new("IPv6");
    l.f("Longitud de datos", plen);
    l.f("Límite de saltos", hlim);
    l.f("Origen", src);
    l.f("Destino", dst);
    let mut o = 40;
    let end = (40 + plen).min(p.len());
    loop {
        match nh {
            0 | 43 | 60 if o + 8 <= end => {
                let n2 = p[o];
                o += (p[o + 1] as usize + 1) * 8;
                nh = n2;
            }
            51 if o + 8 <= end => {
                let n2 = p[o];
                o += (p[o + 1] as usize + 2) * 4;
                nh = n2;
            }
            44 if o + 8 <= end => {
                let fo = u16at(p, o + 2) >> 3;
                if fo != 0 {
                    l.f("Fragmento", "sí");
                    ls.push(l);
                    s.info = "Fragmento IPv6".into();
                    return;
                }
                nh = p[o];
                o += 8;
            }
            _ => break,
        }
    }
    l.f("Siguiente cabecera", format!("{} ({})", nh, ip_proto_name(nh)));
    ls.push(l);
    if o > end {
        return;
    }
    transport(d, off + o, off + end, nh, s, ls);
}

fn transport(d: &[u8], start: usize, end: usize, proto: u8, s: &mut Summary, ls: &mut Vec<Layer>) {
    if start > end || end > d.len() {
        return;
    }
    s.l4 = proto;
    let p = &d[start..end];
    match proto {
        6 => tcp(d, start, end, s, ls),
        17 => udp(d, start, end, s, ls),
        1 => icmp(p, s, ls, false),
        58 => icmp(p, s, ls, true),
        2 => {
            s.proto = "IGMP".into();
            s.info = "Gestión de grupos multicast".into();
        }
        47 => {
            s.proto = "GRE".into();
            s.info = "Túnel GRE".into();
        }
        50 => {
            s.proto = "ESP".into();
            s.info = "IPsec cifrado (ESP)".into();
        }
        89 => {
            s.proto = "OSPF".into();
            s.info = "Enrutamiento OSPF".into();
        }
        _ => s.info = format!("Protocolo IP {}", proto),
    }
}

fn port_label(sp: u16, dp: u16) -> &'static str {
    let a = service_name(dp);
    if !a.is_empty() && dp < 49152 {
        return a;
    }
    let b = service_name(sp);
    if !b.is_empty() {
        return b;
    }
    a
}

fn tcp(d: &[u8], start: usize, end: usize, s: &mut Summary, ls: &mut Vec<Layer>) {
    let p = &d[start..end];
    s.proto = "TCP".into();
    if p.len() < 20 {
        s.info = "TCP truncado".into();
        return;
    }
    let sp = u16at(p, 0);
    let dp = u16at(p, 2);
    let seq = u32at(p, 4);
    let ack = u32at(p, 8);
    let doff = (((p[12] >> 4) as usize) * 4).clamp(20, p.len());
    let flags = p[13];
    let win = u16at(p, 14);
    s.sport = sp;
    s.dport = dp;
    s.tcp_flags = flags;
    let pl = &d[start + doff..end];
    s.payload_start = start + doff;
    s.payload_len = pl.len();
    let mut l = Layer::new("TCP");
    l.f("Puerto origen", format!("{} {}", sp, service_name(sp)));
    l.f("Puerto destino", format!("{} {}", dp, service_name(dp)));
    l.f("Secuencia", seq);
    l.f("Acuse", ack);
    l.f("Longitud cabecera", format!("{} bytes", doff));
    l.f("Indicadores", format!("0x{:02x} [{}]", flags, tcp_flags_text(flags)));
    l.f("Ventana", win);
    l.f("Datos", format!("{} bytes", pl.len()));
    ls.push(l);
    s.info = format!("{} → {} [{}] Sec={} Ack={} Ventana={} Long={}", sp, dp, tcp_flags_text(flags), seq, ack, win, pl.len());
    let label = port_label(sp, dp);
    if pl.is_empty() {
        return;
    }
    if !label.is_empty() {
        s.proto = label.to_string();
    }
    let methods = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "];
    if methods.iter().any(|m| pl.starts_with(m.as_bytes())) || pl.starts_with(b"HTTP/1.") {
        http(pl, s, ls);
    } else if pl.len() >= 5 && (20..=23).contains(&pl[0]) && pl[1] == 3 && pl[2] <= 4 {
        tls(pl, s, ls);
    } else if pl.starts_with(b"SSH-") {
        s.proto = "SSH".into();
        s.info = printable(pl, 80);
    } else if (sp == 53 || dp == 53) && pl.len() > 2 {
        dns(&pl[2..], s, ls, "DNS");
    } else if pl.len() > 8 && (sp == 445 || dp == 445 || sp == 139 || dp == 139) && (pl[4..8] == [0xff, b'S', b'M', b'B'] || pl[4..8] == [0xfe, b'S', b'M', b'B']) {
        s.proto = if pl[4] == 0xfe { "SMB2".into() } else { "SMB1".into() };
        s.info = format!("Compartición de archivos {} ({} bytes)", s.proto, pl.len());
    } else if matches!(label, "FTP" | "SMTP" | "POP3" | "IMAP" | "Telnet" | "IRC") {
        s.info = printable(pl, 100);
        let mut a = Layer::new(label);
        a.f("Texto", printable(pl, 200));
        ls.push(a);
    }
    let mut dl = Layer::new("Datos de aplicación");
    dl.f("Vista previa", printable(pl, 120));
    ls.push(dl);
}

fn http(pl: &[u8], s: &mut Summary, ls: &mut Vec<Layer>) {
    let text = String::from_utf8_lossy(&pl[..pl.len().min(4096)]).to_string();
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("").to_string();
    s.proto = "HTTP".into();
    s.info = first.clone();
    let mut l = Layer::new("HTTP");
    l.f(if first.starts_with("HTTP/") { "Respuesta" } else { "Petición" }, &first);
    for h in lines.take(14) {
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("host") {
                s.http_host = Some(v.to_string());
            }
            let shown = if k.eq_ignore_ascii_case("authorization") || k.eq_ignore_ascii_case("cookie") { "(oculto)" } else { v };
            l.f(k, shown);
        }
    }
    if !first.starts_with("HTTP/") {
        s.http = Some(format!("{} {}", s.http_host.clone().unwrap_or_default(), first));
    }
    ls.push(l);
}

fn tls_ver(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "desconocida",
    }
}

fn tls(p: &[u8], s: &mut Summary, ls: &mut Vec<Layer>) {
    let ct = p[0];
    let ver = u16at(p, 1);
    let mut l = Layer::new("TLS");
    let ctn = match ct {
        20 => "Cambio de cifrado",
        21 => "Alerta",
        22 => "Negociación",
        23 => "Datos cifrados",
        _ => "?",
    };
    l.f("Tipo de registro", ctn);
    l.f("Versión del registro", tls_ver(ver));
    l.f("Longitud", u16at(p, 3));
    s.proto = "TLS".into();
    s.info = ctn.to_string();
    if ct == 22 && p.len() > 9 {
        let ht = p[5];
        let hn = match ht {
            1 => "Client Hello",
            2 => "Server Hello",
            4 => "Ticket de sesión",
            11 => "Certificado",
            12 => "Intercambio de claves (servidor)",
            14 => "Server Hello Done",
            16 => "Intercambio de claves (cliente)",
            _ => "Negociación cifrada",
        };
        l.f("Mensaje", hn);
        s.info = hn.to_string();
        if ht == 1 {
            if let Some((sni, alpn, vers)) = client_hello(&p[5..]) {
                if let Some(n) = &sni {
                    l.f("Servidor (SNI)", n);
                    s.info = format!("Client Hello · {}", n);
                }
                if !alpn.is_empty() {
                    l.f("ALPN", alpn.join(", "));
                }
                if !vers.is_empty() {
                    l.f("Versiones ofrecidas", vers.join(", "));
                }
                s.sni = sni;
            }
        }
    }
    ls.push(l);
}

fn client_hello(h: &[u8]) -> Option<(Option<String>, Vec<String>, Vec<String>)> {
    let mut i = 38;
    let sid = *h.get(i)? as usize;
    i += 1 + sid;
    let cs = g16(h, i)? as usize;
    i += 2 + cs;
    let comp = *h.get(i)? as usize;
    i += 1 + comp;
    let ext_total = g16(h, i)? as usize;
    i += 2;
    let end = (i + ext_total).min(h.len());
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut vers = Vec::new();
    while i + 4 <= end {
        let et = g16(h, i)?;
        let el = g16(h, i + 2)? as usize;
        let ed = h.get(i + 4..i + 4 + el)?;
        match et {
            0 if ed.len() > 5 => {
                let nl = g16(ed, 3)? as usize;
                sni = Some(String::from_utf8_lossy(ed.get(5..5 + nl)?).to_string());
            }
            16 => {
                let mut j = 2;
                while j < ed.len() {
                    let l = ed[j] as usize;
                    alpn.push(String::from_utf8_lossy(ed.get(j + 1..j + 1 + l)?).to_string());
                    j += 1 + l;
                }
            }
            43 if !ed.is_empty() => {
                let mut j = 1;
                while j + 1 < ed.len() {
                    let v = u16at(ed, j);
                    if v & 0x0f0f != 0x0a0a {
                        vers.push(tls_ver(v).to_string());
                    }
                    j += 2;
                }
            }
            _ => {}
        }
        i += 4 + el;
    }
    Some((sni, alpn, vers))
}

fn udp(d: &[u8], start: usize, end: usize, s: &mut Summary, ls: &mut Vec<Layer>) {
    let p = &d[start..end];
    s.proto = "UDP".into();
    if p.len() < 8 {
        s.info = "UDP truncado".into();
        return;
    }
    let sp = u16at(p, 0);
    let dp = u16at(p, 2);
    s.sport = sp;
    s.dport = dp;
    let pl = &p[8..];
    s.payload_start = start + 8;
    s.payload_len = pl.len();
    let mut l = Layer::new("UDP");
    l.f("Puerto origen", format!("{} {}", sp, service_name(sp)));
    l.f("Puerto destino", format!("{} {}", dp, service_name(dp)));
    l.f("Longitud", u16at(p, 4));
    ls.push(l);
    s.info = format!("{} → {} Long={}", sp, dp, pl.len());
    let label = port_label(sp, dp);
    if !label.is_empty() {
        s.proto = label.to_string();
    }
    let has = |port: u16| sp == port || dp == port;
    if has(53) {
        dns(pl, s, ls, "DNS");
    } else if has(5353) {
        dns(pl, s, ls, "mDNS");
    } else if has(5355) {
        dns(pl, s, ls, "LLMNR");
    } else if has(67) || has(68) {
        dhcp(pl, s, ls);
    } else if has(123) && !pl.is_empty() {
        s.proto = "NTP".into();
        s.info = format!("Sincronización horaria NTP v{} modo {}", (pl[0] >> 3) & 7, pl[0] & 7);
    } else if has(1900) {
        s.proto = "SSDP".into();
        s.info = printable(pl.split(|&c| c == b'\r').next().unwrap_or(&[]), 80);
    } else if has(5060) {
        s.proto = "SIP".into();
        s.info = printable(pl.split(|&c| c == b'\r').next().unwrap_or(&[]), 80);
    } else if (has(443) || has(80)) && !pl.is_empty() && pl[0] & 0x80 != 0 {
        s.proto = "QUIC".into();
        s.info = "QUIC (HTTP/3) cabecera larga".into();
    } else if has(443) && !pl.is_empty() {
        s.proto = "QUIC".into();
        s.info = "QUIC (HTTP/3) datos cifrados".into();
    } else if has(3478) {
        s.proto = "STUN".into();
        s.info = "Descubrimiento NAT (STUN)".into();
    } else if has(51820) {
        s.proto = "WireGuard".into();
        s.info = "Túnel VPN WireGuard".into();
    }
}

fn dns(pl: &[u8], s: &mut Summary, ls: &mut Vec<Layer>, label: &str) {
    s.proto = label.into();
    let Some(m) = crate::dns::parse(pl) else {
        s.info = format!("{} no válido", label);
        return;
    };
    let mut l = Layer::new(label);
    l.f("ID", format!("0x{:04x}", m.id));
    l.f("Indicadores", m.flag_text());
    if m.is_response() {
        l.f("Código", crate::dns::rcode_name(m.rcode));
    }
    let q = m.questions.first().cloned();
    for (n, t) in &m.questions {
        l.f("Pregunta", format!("{} {}", crate::dns::type_name(*t), n));
    }
    for a in m.answers.iter().take(12) {
        l.f("Respuesta", format!("{} {} → {} (TTL {})", crate::dns::type_name(a.rtype), a.name, a.data, a.ttl));
    }
    ls.push(l);
    s.dns_response = m.is_response();
    if let Some((n, t)) = q {
        s.dns_qname = Some(n.clone());
        if m.is_response() {
            let ans: Vec<String> = m.answers.iter().map(|a| a.data.clone()).collect();
            s.info = if m.rcode != 0 {
                format!("Respuesta {} {} · {}", crate::dns::type_name(t), n, crate::dns::rcode_name(m.rcode))
            } else {
                format!("Respuesta {} {} → {}", crate::dns::type_name(t), n, ans.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
            };
            s.dns_answers = ans;
        } else {
            s.info = format!("Consulta {} {}", crate::dns::type_name(t), n);
        }
    }
}

fn dhcp(pl: &[u8], s: &mut Summary, ls: &mut Vec<Layer>) {
    s.proto = "DHCP".into();
    if pl.len() < 240 || pl[236..240] != [0x63, 0x82, 0x53, 0x63] {
        s.info = "DHCP/BOOTP".into();
        return;
    }
    let mut l = Layer::new("DHCP");
    let yi = Ipv4Addr::new(pl[16], pl[17], pl[18], pl[19]);
    let ch = mac(&pl[28..34]);
    l.f("Transacción", format!("0x{:08x}", u32at(pl, 4)));
    l.f("MAC cliente", &ch);
    if !yi.is_unspecified() {
        l.f("IP asignada", yi);
    }
    let mut i = 240;
    let mut mt = 0u8;
    let mut host = String::new();
    while i + 1 < pl.len() {
        let code = pl[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        let len = pl[i + 1] as usize;
        let v = match pl.get(i + 2..i + 2 + len) {
            Some(v) => v,
            None => break,
        };
        match code {
            53 if len == 1 => mt = v[0],
            12 => host = String::from_utf8_lossy(v).to_string(),
            50 if len == 4 => l.f("IP solicitada", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            54 if len == 4 => l.f("Servidor DHCP", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            3 if len >= 4 => l.f("Router", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            6 if len >= 4 => l.f("DNS", Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            60 => l.f("Clase de fabricante", String::from_utf8_lossy(v)),
            _ => {}
        }
        i += 2 + len;
    }
    let name = match mt {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "?",
    };
    l.f("Mensaje", name);
    if !host.is_empty() {
        l.f("Nombre del equipo", &host);
    }
    ls.push(l);
    let desc = format!("DHCP {} · {}{}", name, ch, if host.is_empty() { String::new() } else { format!(" ({})", host) });
    s.info = desc.clone();
    s.dhcp = Some((mt, desc));
}

fn icmp(p: &[u8], s: &mut Summary, ls: &mut Vec<Layer>, v6: bool) {
    s.proto = if v6 { "ICMPv6".into() } else { "ICMP".into() };
    if p.len() < 4 {
        return;
    }
    let t = p[0];
    let c = p[1];
    s.icmp_type = Some(t);
    let name = if v6 {
        match t {
            1 => "Destino inalcanzable",
            2 => "Paquete demasiado grande",
            3 => "Tiempo excedido",
            128 => "Solicitud de eco (ping)",
            129 => "Respuesta de eco (ping)",
            133 => "Solicitud de router",
            134 => "Anuncio de router",
            135 => "Solicitud de vecino",
            136 => "Anuncio de vecino",
            143 => "Informe de multicast",
            _ => "Mensaje ICMPv6",
        }
    } else {
        match t {
            0 => "Respuesta de eco (ping)",
            3 => "Destino inalcanzable",
            5 => "Redirección",
            8 => "Solicitud de eco (ping)",
            11 => "TTL excedido",
            _ => "Mensaje ICMP",
        }
    };
    let mut l = Layer::new(if v6 { "ICMPv6" } else { "ICMP" });
    l.f("Tipo", format!("{} ({})", t, name));
    l.f("Código", c);
    let echo = (!v6 && (t == 0 || t == 8)) || (v6 && (t == 128 || t == 129));
    if echo && p.len() >= 8 {
        l.f("Identificador", u16at(p, 4));
        l.f("Secuencia", u16at(p, 6));
        s.info = format!("{} id={} sec={}", name, u16at(p, 4), u16at(p, 6));
    } else {
        s.info = format!("{} (código {})", name, c);
    }
    ls.push(l);
}

pub fn hexdump(d: &[u8], max: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in d.chunks(16).take(max / 16 + 1).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let asc: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
        out.push_str(&format!("{:04x}  {:<48} {}\n", i * 16, hex.join(" "), asc));
    }
    out
}
