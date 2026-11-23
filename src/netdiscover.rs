//! Más herramientas: MTU de la ruta, descubrimiento UPnP (SSDP) y Bonjour (mDNS),
//! y la configuración de red del sistema.
use crate::util::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- MTU de la ruta

/// Un ping con "no fragmentar" y `size` bytes de datos. None si el ping no existe.
fn ping_df(host: &str, size: u32) -> Option<bool> {
    let s = size.to_string();
    let out = if cfg!(windows) {
        run("ping", &["-n", "1", "-w", "1000", "-f", "-l", &s, host])
    } else if cfg!(target_os = "macos") {
        run("ping", &["-c", "1", "-W", "1000", "-D", "-s", &s, host])
    } else {
        run("ping", &["-c", "1", "-W", "1", "-M", "do", "-s", &s, host])
    }?;
    Some(out.to_lowercase().contains("ttl="))
}

/// Busca el mayor paquete que llega sin fragmentarse. Devuelve la MTU (datos + 28 bytes de cabeceras).
pub fn path_mtu(host: &str, step: &dyn Fn(u32)) -> Result<u32, String> {
    match ping_df(host, 64) {
        None => return Err("ping".into()),
        Some(false) => return Err(crate::i18n::tr("El destino no responde al ping.").into()),
        Some(true) => {}
    }
    step(1472);
    if ping_df(host, 1472) == Some(true) {
        return Ok(1500);
    }
    let (mut lo, mut hi) = (64u32, 1472u32);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        step(mid);
        if ping_df(host, mid) == Some(true) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo + 28)
}

// ---------------------------------------------------------------- UPnP / SSDP

#[derive(Clone, Default)]
pub struct UpnpDevice {
    pub ip: String,
    pub name: String,
    pub maker: String,
    pub model: String,
    pub server: String,
    pub location: String,
    pub types: Vec<String>,
}

fn header(resp: &str, name: &str) -> String {
    resp.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case(name) {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn xml_tag(xml: &str, tag: &str) -> String {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    xml.find(&open)
        .and_then(|i| {
            let rest = &xml[i + open.len()..];
            rest.find(&close).map(|j| rest[..j].trim().to_string())
        })
        .unwrap_or_default()
}

/// Lee nombre, fabricante y modelo de la descripción XML del dispositivo.
fn describe(location: &str) -> (String, String, String) {
    let Some(rest) = location.strip_prefix("http://") else { return Default::default() };
    let (hp, path) = rest.split_once('/').map(|(a, b)| (a, format!("/{}", b))).unwrap_or((rest, "/".into()));
    let Ok(addr) = hp.parse::<SocketAddr>().or_else(|_| format!("{}:80", hp).parse::<SocketAddr>()) else { return Default::default() };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) else { return Default::default() };
    s.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    let _ = s.write_all(format!("GET {} HTTP/1.0\r\nHost: {}\r\n\r\n", path, hp).as_bytes());
    let mut buf = Vec::new();
    let _ = s.take(256 * 1024).read_to_end(&mut buf);
    let xml = String::from_utf8_lossy(&buf);
    (xml_tag(&xml, "friendlyName"), xml_tag(&xml, "manufacturer"), xml_tag(&xml, "modelName"))
}

pub fn upnp_discover(wait_ms: u64) -> Result<Vec<UpnpDevice>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
    let mut devs: BTreeMap<Ipv4Addr, UpnpDevice> = BTreeMap::new();
    let t0 = Instant::now();
    let mut buf = [0u8; 4096];
    let mut sent = 0;
    while t0.elapsed().as_millis() < wait_ms as u128 {
        if sent < 2 && t0.elapsed().as_millis() as u64 >= sent * 600 {
            sock.send_to(msg, dest).map_err(|e| e.to_string())?;
            sent += 1;
        }
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let IpAddr::V4(ip) = from.ip() else { continue };
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            let d = devs.entry(ip).or_insert_with(|| UpnpDevice { ip: ip.to_string(), ..Default::default() });
            if d.server.is_empty() {
                d.server = header(&resp, "server");
            }
            if d.location.is_empty() {
                d.location = header(&resp, "location");
            }
            let st = header(&resp, "st");
            if !st.is_empty() && !d.types.contains(&st) && d.types.len() < 12 {
                d.types.push(st);
            }
        }
    }
    let mut out: Vec<UpnpDevice> = devs.into_values().collect();
    for d in out.iter_mut() {
        if !d.location.is_empty() {
            let (n, m, model) = describe(&d.location);
            d.name = n;
            d.maker = m;
            d.model = model;
        }
    }
    Ok(out)
}

/// Una redirección de puertos que el router abre a Internet (UPnP).
#[derive(Clone, Debug)]
pub struct PortMap {
    pub external: u16,
    pub proto: String,
    pub internal_ip: String,
    pub internal_port: u16,
    pub description: String,
}

/// Petición HTTP sencilla (sin cifrar) a una URL `http://host:puerto/ruta`.
fn http_raw(url: &str, method: &str, extra: &str, body: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (hp, path) = rest.split_once('/').map(|(a, b)| (a, format!("/{}", b))).unwrap_or((rest, "/".into()));
    let addr = hp.parse::<SocketAddr>().or_else(|_| format!("{}:80", hp).parse::<SocketAddr>()).ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok();
    let req = format!("{} {} HTTP/1.0\r\nHost: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", method, path, hp, extra, body.len(), body);
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = s.take(512 * 1024).read_to_end(&mut buf);
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") {
        return path.to_string();
    }
    let host_end = base.strip_prefix("http://").and_then(|r| r.find('/')).map(|i| i + 7).unwrap_or(base.len());
    let p = if path.starts_with('/') { path.to_string() } else { format!("/{}", path) };
    format!("{}{}", &base[..host_end], p)
}

/// Pregunta al router (por UPnP) qué puertos tiene abiertos hacia Internet.
/// Ok(None) si no hay ningún router con UPnP en la red.
pub fn upnp_port_mappings() -> Result<Option<(String, Vec<PortMap>)>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
    let mut locations: Vec<String> = Vec::new();
    let t0 = Instant::now();
    let mut buf = [0u8; 4096];
    for st in ["urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2"] {
        let msg = format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {}\r\n\r\n", st);
        let _ = sock.send_to(msg.as_bytes(), dest);
    }
    while t0.elapsed() < Duration::from_millis(2500) {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            let loc = header(&String::from_utf8_lossy(&buf[..n]), "location");
            if !loc.is_empty() && !locations.contains(&loc) {
                locations.push(loc);
            }
        }
    }
    for loc in locations {
        let Some(xml) = http_raw(&loc, "GET", "", "") else { continue };
        // Busca el servicio WANIPConnection o WANPPPConnection y su controlURL
        for svc in ["WANIPConnection", "WANPPPConnection"] {
            let Some(i) = xml.find(&format!("service:{}:", svc)) else { continue };
            let urn_start = xml[..i].rfind('>').map(|j| j + 1).unwrap_or(i);
            let urn: String = xml[urn_start..].chars().take_while(|c| *c != '<').collect();
            let rest = &xml[i..];
            let ctrl = xml_tag(rest, "controlURL");
            if ctrl.is_empty() {
                continue;
            }
            let url = join_url(&loc, &ctrl);
            let mut maps = Vec::new();
            for idx in 0..64 {
                let body = format!(
                    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetGenericPortMappingEntry xmlns:u=\"{}\"><NewPortMappingIndex>{}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>",
                    urn.trim(), idx
                );
                let extra = format!("Content-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{}#GetGenericPortMappingEntry\"\r\n", urn.trim());
                let Some(resp) = http_raw(&url, "POST", &extra, &body) else { break };
                let ext = xml_tag(&resp, "NewExternalPort");
                if ext.is_empty() {
                    break;
                }
                maps.push(PortMap {
                    external: ext.parse().unwrap_or(0),
                    proto: xml_tag(&resp, "NewProtocol"),
                    internal_ip: xml_tag(&resp, "NewInternalClient"),
                    internal_port: xml_tag(&resp, "NewInternalPort").parse().unwrap_or(0),
                    description: xml_tag(&resp, "NewPortMappingDescription"),
                });
            }
            let router = loc.strip_prefix("http://").and_then(|r| r.split(':').next()).unwrap_or("").to_string();
            return Ok(Some((router, maps)));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------- Bonjour / mDNS

#[derive(Clone)]
pub struct MdnsService {
    pub kind: String,
    pub instance: String,
    pub ip: String,
}

/// Nombre sencillo para los tipos de servicio más comunes.
pub fn service_label(kind: &str) -> &'static str {
    let k = kind.to_lowercase();
    let table: &[(&str, &str)] = &[
        ("_ipp.", "Impresora"),
        ("_ipps.", "Impresora"),
        ("_printer.", "Impresora"),
        ("_pdl-datastream.", "Impresora"),
        ("_scanner.", "Escáner"),
        ("_uscan.", "Escáner"),
        ("_googlecast.", "Chromecast"),
        ("_airplay.", "AirPlay"),
        ("_raop.", "Altavoz (AirPlay)"),
        ("_spotify-connect.", "Spotify Connect"),
        ("_hap.", "HomeKit"),
        ("_smb.", "Archivos (SMB)"),
        ("_afpovertcp.", "Archivos (SMB)"),
        ("_ssh.", "SSH"),
        ("_sftp-ssh.", "SSH"),
        ("_http.", "Web"),
        ("_https.", "Web"),
        ("_workstation.", "Equipo"),
        ("_device-info.", "Equipo"),
        ("_companion-link.", "Equipo"),
    ];
    table.iter().find(|(p, _)| k.starts_with(p)).map(|(_, l)| *l).unwrap_or("")
}

fn mdns_query(sock: &UdpSocket, name: &str) {
    let mut q = crate::dns::build_query(0, name, 12, false);
    q[2] = 0;
    q[3] = 0;
    let n = q.len();
    q[n - 2] = 0x80; // bit QU: que respondan directamente a este puerto
    q[n - 1] = 0x01;
    let _ = sock.send_to(&q, (Ipv4Addr::new(224, 0, 0, 251), 5353));
}

fn collect(sock: &UdpSocket, ms: u64, mut f: impl FnMut(&crate::dns::DnsMsg, IpAddr)) {
    let t0 = Instant::now();
    let mut buf = [0u8; 9000];
    while t0.elapsed().as_millis() < ms as u128 {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Some(m) = crate::dns::parse(&buf[..n]) {
                f(&m, from.ip());
            }
        }
    }
}

pub fn mdns_discover() -> Result<Vec<MdnsService>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(150))).ok();
    sock.set_multicast_ttl_v4(255).ok();
    mdns_query(&sock, "_services._dns-sd._udp.local");
    let mut kinds: Vec<String> = Vec::new();
    collect(&sock, 1500, |m, _| {
        for rr in m.answers.iter().chain(m.additional.iter()) {
            if rr.rtype == 12 && rr.name.starts_with("_services.") && !kinds.contains(&rr.data) {
                kinds.push(rr.data.clone());
            }
        }
    });
    for k in ["_ipp._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local", "_smb._tcp.local", "_http._tcp.local", "_workstation._tcp.local"] {
        if !kinds.iter().any(|x| x == k) {
            kinds.push(k.to_string());
        }
    }
    let mut found: Vec<MdnsService> = Vec::new();
    for k in kinds.iter().take(40) {
        mdns_query(&sock, k);
    }
    collect(&sock, 2500, |m, ip| {
        for rr in m.answers.iter().chain(m.additional.iter()) {
            if rr.rtype == 12 && !rr.name.starts_with("_services.") && kinds.iter().any(|k| k.eq_ignore_ascii_case(&rr.name)) {
                let instance = rr.data.strip_suffix(&format!(".{}", rr.name)).unwrap_or(&rr.data).to_string();
                if !found.iter().any(|f| f.kind == rr.name && f.instance == instance) {
                    found.push(MdnsService { kind: rr.name.clone(), instance, ip: ip.to_string() });
                }
            }
        }
    });
    found.sort_by(|a, b| (service_label(&a.kind), &a.kind, &a.instance).cmp(&(service_label(&b.kind), &b.kind, &b.instance)));
    Ok(found)
}

// ---------------------------------------------------------------- configuración del sistema

pub fn system_interfaces() -> String {
    let out = if cfg!(windows) {
        run("ipconfig", &["/all"])
    } else if cfg!(target_os = "macos") {
        run("ifconfig", &[])
    } else {
        run("ip", &["-br", "addr"]).map(|a| a + "\n" + &run("ip", &["-br", "link"]).unwrap_or_default())
    };
    out.unwrap_or_default().trim().to_string()
}

pub fn system_routes() -> String {
    let out = if cfg!(windows) {
        run("route", &["print"])
    } else if cfg!(target_os = "macos") {
        run("netstat", &["-rn"])
    } else {
        run("ip", &["route"]).map(|a| a + "\n" + &run("ip", &["-6", "route"]).unwrap_or_default())
    };
    out.unwrap_or_default().trim().to_string()
}
