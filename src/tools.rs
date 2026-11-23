//! Utilidades: Wake-on-LAN, IP pública, calculadora de subredes y exportación a CSV.
use crate::util::*;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

/// Envía el "paquete mágico" (6 x FF + 16 x MAC) por difusión a los puertos 9 y 7.
pub fn wake_on_lan(mac: &str, broadcast: Option<Ipv4Addr>) -> Result<String, String> {
    let m = normalize_mac(mac.trim()).ok_or_else(|| crate::i18n::tr("MAC no válida").to_string())?;
    let bytes: Vec<u8> = m.split(':').filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
    let mut pkt = vec![0xFFu8; 6];
    for _ in 0..16 {
        pkt.extend_from_slice(&bytes);
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    let mut targets = vec![Ipv4Addr::BROADCAST];
    if let Some(b) = broadcast {
        targets.push(b);
    }
    for ip in targets {
        for port in [9u16, 7] {
            let _ = sock.send_to(&pkt, (ip, port));
        }
    }
    Ok(m)
}

fn json_field(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":", key);
    let i = body.find(&pat)? + pat.len();
    let rest = body[i..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        Some(r[..r.find('"')?].to_string())
    } else {
        Some(rest.split(|c| c == ',' || c == '}').next()?.trim().to_string())
    }
}

/// IP pública y datos del proveedor (servicio ip-api.com, sin cifrar y sin clave).
pub fn public_ip() -> Result<Vec<(&'static str, String)>, String> {
    let host = "ip-api.com";
    let addr = (host, 80).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("DNS")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(b"GET /json/?fields=status,message,query,country,city,isp,as,timezone HTTP/1.0\r\nHost: ip-api.com\r\nUser-Agent: RedVision\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let txt = String::from_utf8_lossy(&buf).to_string();
    let body = txt.split("\r\n\r\n").nth(1).unwrap_or("");
    if json_field(body, "status").as_deref() != Some("success") {
        return Err(json_field(body, "message").unwrap_or_else(|| "sin respuesta".into()));
    }
    Ok([("IP pública", "query"), ("País", "country"), ("Ciudad", "city"), ("Proveedor", "isp"), ("Sistema autónomo", "as"), ("Zona horaria", "timezone")]
        .iter()
        .map(|(label, k)| (*label, json_field(body, k).unwrap_or_default()))
        .collect())
}

/// Calcula los datos de una red a partir de "IP/prefijo" o "IP máscara".
pub fn subnet(input: &str) -> Option<Vec<(&'static str, String)>> {
    let input = input.trim();
    let (ip_s, p_s) = input.split_once('/').or_else(|| input.split_once(' '))?;
    let ip: Ipv4Addr = ip_s.trim().parse().ok()?;
    let p_s = p_s.trim();
    let prefix: u32 = match p_s.parse::<Ipv4Addr>() {
        Ok(m) => {
            let v = u32::from(m);
            if v.leading_ones() + v.trailing_zeros() != 32 {
                return None;
            }
            v.leading_ones()
        }
        Err(_) => p_s.parse().ok().filter(|p| *p <= 32)?,
    };
    let m = mask(prefix as u8);
    let net = u32::from(ip) & m;
    let bc = net | !m;
    let (first, last, usable) = match prefix {
        32 => (net, net, 1u64),
        31 => (net, bc, 2),
        _ => (net + 1, bc - 1, (1u64 << (32 - prefix)) - 2),
    };
    let o = ip.octets();
    let class = match o[0] {
        0..=127 => "A",
        128..=191 => "B",
        192..=223 => "C",
        224..=239 => "D (multicast)",
        _ => "E",
    };
    let scope = if ip.is_private() || ip.is_loopback() || ip.is_link_local() { crate::i18n::tr("privada") } else { crate::i18n::tr("pública") };
    Some(vec![
        ("Red", format!("{}/{}", Ipv4Addr::from(net), prefix)),
        ("Máscara", Ipv4Addr::from(m).to_string()),
        ("Comodín", Ipv4Addr::from(!m).to_string()),
        ("Difusión", Ipv4Addr::from(bc).to_string()),
        ("Primer equipo", Ipv4Addr::from(first).to_string()),
        ("Último equipo", Ipv4Addr::from(last).to_string()),
        ("Equipos utilizables", usable.to_string()),
        ("Clase / ámbito", format!("{} · {}", class, scope)),
    ])
}

fn whois_ask(server: &str, query: &str) -> Result<String, String> {
    let addr = (server, 43).to_socket_addrs().map_err(|e| format!("{}: {}", server, e))?.next().ok_or("DNS")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(6)).map_err(|e| format!("{}: {}", server, e))?;
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.write_all(format!("{}\r\n", query).as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let _ = s.take(256 * 1024).read_to_end(&mut buf);
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn whois_refer(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        let k = k.trim().to_lowercase();
        let v = v.trim().trim_start_matches("whois://").trim_start_matches("http://").trim_end_matches('/').to_string();
        if (k == "refer" || k == "whois" || k == "registrar whois server") && !v.is_empty() && !v.contains(' ') {
            Some(v)
        } else {
            None
        }
    })
}

/// Whois de un dominio o una IP: pregunta a IANA y sigue las referencias hasta el servidor del registro.
pub fn whois(query: &str) -> Result<String, String> {
    let q = query.trim();
    if q.is_empty() || q.contains(char::is_whitespace) {
        return Err(crate::i18n::tr("Escribe un dominio o una IP.").into());
    }
    let mut server = "whois.iana.org".to_string();
    let mut out = String::new();
    for _ in 0..3 {
        let text = whois_ask(&server, q)?;
        let next = whois_refer(&text).filter(|n| !n.eq_ignore_ascii_case(&server));
        out.push_str(&format!("### {}\n{}\n", server, text.trim()));
        match next {
            Some(n) => server = n,
            None => break,
        }
    }
    Ok(out)
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n', ';']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Guarda una tabla como CSV en la carpeta personal y devuelve la ruta.
pub fn export_csv(name: &str, header: &[&str], rows: &[Vec<String>]) -> Result<PathBuf, String> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = PathBuf::from(home).join(format!("RedVision-{}-{}.csv", name, stamp));
    let mut out = String::from("\u{feff}");
    out.push_str(&header.iter().map(|h| csv_cell(h)).collect::<Vec<_>>().join(","));
    out.push('\n');
    for r in rows {
        out.push_str(&r.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    std::fs::write(&path, out).map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    /// Whois real (necesita Internet): `cargo test -- --ignored --nocapture whois_live`
    #[test]
    #[ignore]
    fn whois_live() {
        for q in ["debian.org", "wikipedia.org", "8.8.8.8"] {
            let r = super::whois(q);
            let t = r.as_ref().map(|t| t.lines().filter(|l| l.starts_with("###") || l.to_lowercase().contains("registrar:") || l.to_lowercase().contains("orgname") || l.to_lowercase().contains("netname")).collect::<Vec<_>>().join(" | ")).unwrap_or_else(|e| e.clone());
            println!("{} -> {}", q, t);
            assert!(r.is_ok());
        }
    }
}
