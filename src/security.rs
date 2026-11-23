//! Auditoría de seguridad: servicios expuestos, configuraciones débiles y versiones antiguas.
use crate::i18n::{tr, tf};
use crate::egui;
use crate::ids::Sev;
use crate::netscan::{grab_banner, is_http_port};
use crate::ping::{resolve, tcp_probe, Probe};
use crate::util::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone)]
pub struct Finding {
    pub host: String,
    pub port: Option<u16>,
    pub sev: Sev,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

#[derive(Default)]
pub struct Audit {
    pub running: bool,
    pub step: String,
    pub hosts_done: usize,
    pub hosts_total: usize,
    pub findings: Vec<Finding>,
    pub open_ports: Vec<(String, u16, String)>,
    pub score: Option<i32>,
    pub finished: Option<f64>,
}

pub fn score(f: &[Finding]) -> i32 {
    let pen: i32 = f
        .iter()
        .map(|x| match x.sev {
            Sev::Critical => 30,
            Sev::High => 15,
            Sev::Medium => 7,
            Sev::Low => 2,
            Sev::Info => 0,
        })
        .sum();
    (100 - pen).max(0)
}

fn talk(addr: SocketAddr, send: &[u8], read_first: bool) -> String {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) else { return String::new() };
    s.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    let mut buf = [0u8; 2048];
    if read_first {
        let _ = s.read(&mut buf);
    }
    if s.write_all(send).is_err() {
        return String::new();
    }
    let mut out = Vec::new();
    for _ in 0..3 {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
        if out.len() > 64 {
            break;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn udp_ask(ip: IpAddr, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(1200))).ok();
    sock.send_to(payload, SocketAddr::new(ip, port)).ok()?;
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

const SNMP_PUBLIC: &[u8] = &[
    0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c, 0x02, 0x04, 0x12, 0x34,
    0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
    0x01, 0x01, 0x00, 0x05, 0x00,
];

fn audit_host(target: &str, gateway: Option<Ipv4Addr>, out: &mut Vec<Finding>, open_list: &mut Vec<(String, u16, String)>, stop: &AtomicBool) {
    let Some(ip) = resolve(target) else {
        out.push(Finding { host: target.into(), port: None, sev: Sev::Info, title: tr("No se pudo resolver").into(), detail: tr("El nombre no existe o no hay DNS.").into(), fix: String::new() });
        return;
    };
    let host = ip.to_string();
    let is_gw = matches!(ip, IpAddr::V4(v) if Some(v) == gateway);
    // Escaneo paralelo de los puertos más habituales
    let ports: Arc<Vec<u16>> = Arc::new(TOP_PORTS.to_vec());
    let idx = Arc::new(AtomicUsize::new(0));
    let found = shared(Vec::<u16>::new());
    let mut ws = Vec::new();
    for _ in 0..48 {
        let (ports, idx, found) = (ports.clone(), idx.clone(), found.clone());
        ws.push(thread::spawn(move || loop {
            let i = idx.fetch_add(1, Ordering::Relaxed);
            let Some(&p) = ports.get(i) else { break };
            if let Probe::Open(_) = tcp_probe(SocketAddr::new(ip, p), Duration::from_millis(500)) {
                lock(&found).push(p);
            }
        }));
    }
    for w in ws {
        let _ = w.join();
    }
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let mut open = lock(&found).clone();
    open.sort();
    let mut add = |port: Option<u16>, sev: Sev, title: &str, detail: String, fix: &str| {
        out.push(Finding { host: host.clone(), port, sev, title: title.into(), detail, fix: fix.into() });
    };
    for &p in &open {
        let addr = SocketAddr::new(ip, p);
        let banner = grab_banner(addr, Duration::from_millis(1000));
        open_list.push((host.clone(), p, banner.clone()));
        match p {
            23 => add(Some(p), Sev::High, tr("Telnet activo"), tr("Telnet envía usuario y contraseña sin cifrar.").into(), tr("Desactiva Telnet y usa SSH.")),
            21 => {
                let r = talk(addr, b"USER anonymous\r\nPASS anon@example.com\r\n", true);
                if r.contains("230") {
                    add(Some(p), Sev::High, tr("FTP con acceso anónimo"), tr("Cualquiera puede entrar al FTP sin contraseña.").into(), tr("Desactiva el acceso anónimo."));
                } else {
                    add(Some(p), Sev::Medium, tr("FTP sin cifrar"), format!("Banner: {}", banner), tr("Usa SFTP o FTPS."));
                }
            }
            445 | 139 => add(Some(p), Sev::Medium, tr("Compartición de archivos (SMB) expuesta"), tr("SMB ha sido vía de ataques graves (p. ej. WannaCry).").into(), tr("Limita SMB a la red local y mantén el sistema actualizado.")),
            3389 => add(Some(p), Sev::Medium, tr("Escritorio remoto (RDP) abierto"), tr("Los ataques de fuerza bruta contra RDP son muy comunes.").into(), tr("Usa VPN o activa la autenticación a nivel de red.")),
            5900 | 5901 => add(Some(p), Sev::High, tr("VNC abierto"), tf("Control remoto accesible. {}", &[&(banner)]), tr("Protégelo con contraseña fuerte o túnel SSH.")),
            6379 => {
                let r = talk(addr, b"PING\r\n", false);
                if r.starts_with("+PONG") {
                    add(Some(p), Sev::Critical, tr("Redis sin contraseña"), tr("La base de datos Redis responde sin autenticación.").into(), tr("Activa requirepass y no la expongas a la red."));
                } else {
                    add(Some(p), Sev::Low, tr("Redis expuesto"), tr("Redis acepta conexiones desde la red.").into(), tr("Limítalo a localhost."));
                }
            }
            11211 => {
                let r = talk(addr, b"stats\r\n", false);
                if r.contains("STAT") {
                    add(Some(p), Sev::High, tr("Memcached sin protección"), tr("Memcached responde a cualquiera y puede usarse para ataques de amplificación.").into(), tr("Escucha solo en localhost."));
                }
            }
            9200 => {
                let r = talk(addr, format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host).as_bytes(), false);
                if r.contains("cluster_name") {
                    add(Some(p), Sev::High, tr("Elasticsearch sin autenticación"), tr("Los datos del índice son accesibles.").into(), tr("Activa la seguridad de Elasticsearch."));
                }
            }
            2375 => {
                let r = talk(addr, format!("GET /version HTTP/1.0\r\nHost: {}\r\n\r\n", host).as_bytes(), false);
                if r.contains("ApiVersion") {
                    add(Some(p), Sev::Critical, tr("API de Docker sin protección"), tr("Quien acceda puede controlar todo el equipo.").into(), tr("Cierra el puerto 2375 o usa TLS (2376)."));
                }
            }
            27017 => add(Some(p), Sev::Medium, tr("MongoDB expuesto"), tr("La base de datos acepta conexiones de la red.").into(), tr("Activa autenticación y limita el acceso.")),
            3306 | 5432 | 1433 | 1521 => add(Some(p), Sev::Medium, tr("Base de datos accesible en la red"), tf("{} escucha en {}. {}", &[&(service_name(p)), &(p), &(banner)]), tr("Permite solo los equipos que la necesitan.")),
            4444 | 31337 | 12345 | 6667 => add(Some(p), Sev::High, tr("Puerto típico de puerta trasera"), tf("El puerto {} suele usarlo malware. {}", &[&(p), &(banner)]), tr("Revisa qué programa lo abre y analiza el equipo.")),
            1883 => add(Some(p), Sev::Medium, tr("MQTT sin cifrar"), tr("Mensajería IoT accesible sin TLS.").into(), tr("Usa 8883 con TLS y usuario/contraseña.")),
            161 => {}
            _ => {}
        }
        if p == 22 {
            if banner.starts_with("SSH-1") {
                add(Some(p), Sev::High, tr("SSH versión 1"), tr("SSH-1 tiene fallos criptográficos.").into(), tr("Usa solo SSH-2."));
            } else if let Some(v) = banner.split("OpenSSH_").nth(1) {
                let major: u32 = v.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(99);
                if major < 8 {
                    add(Some(p), Sev::Medium, tr("OpenSSH antiguo"), tf("Versión {}.", &[&(banner)]), tr("Actualiza OpenSSH a una versión reciente."));
                }
            }
        }
        if is_http_port(p) || p == 443 {
            if let Some(sv) = banner.split("Servidor: ").nth(1) {
                if sv.chars().any(|c| c.is_ascii_digit()) {
                    add(Some(p), Sev::Low, tr("El servidor web muestra su versión"), tf("Cabecera Server: {}", &[&(sv)]), tr("Oculta la versión para no dar pistas a atacantes."));
                }
            }
            if [8080, 8000, 8888, 81, 8081].contains(&p) {
                add(Some(p), Sev::Low, tr("Panel web en puerto alternativo"), tf("Servicio web en {}: {}", &[&(p), &(banner)]), tr("Comprueba que tenga contraseña y esté actualizado."));
            }
        }
    }
    // Certificado HTTPS: caducidad, nombre, firma débil, TLS antiguo
    if open.contains(&443) {
        let rep = crate::tlscheck::check(&host, 443);
        for f in rep.findings.iter().filter(|f| f.sev > Sev::Low || f.title.contains("TLS")) {
            add(Some(443), f.sev, &f.title, f.detail.clone(), &f.fix);
        }
    }
    if open.contains(&80) && !open.contains(&443) {
        add(Some(80), Sev::Low, tr("Web sin HTTPS"), tr("El equipo ofrece web sin cifrar.").into(), tr("Activa HTTPS."));
    }
    // Comprobaciones UDP
    if let Some(r) = udp_ask(ip, 161, SNMP_PUBLIC) {
        let txt = printable(&r, 120);
        add(Some(161), Sev::High, tr("SNMP con comunidad «public»"), tf("Responde con la comunidad por defecto: {}", &[&(txt)]), tr("Cambia la comunidad o usa SNMPv3."));
    }
    if udp_ask(ip, 1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").is_some() {
        add(Some(1900), if is_gw { Sev::Low } else { Sev::Info }, tr("UPnP activo"), tr("El equipo anuncia servicios UPnP; algunos programas pueden abrir puertos solos.").into(), tr("Desactiva UPnP en el router si no lo necesitas."));
    }
    if let Ok((m, _)) = crate::dns::query(ip, "example.com", 1, false, Duration::from_millis(1200)) {
        if !m.answers.is_empty() {
            if is_gw {
                add(Some(53), Sev::Info, tr("El router resuelve DNS"), tr("Normal en redes domésticas.").into(), "");
            } else {
                add(Some(53), Sev::Medium, tr("Resolvedor DNS abierto"), tr("Responde consultas recursivas de cualquiera; puede usarse para ataques de amplificación.").into(), tr("Limita la recursión a tus equipos."));
            }
        }
    }
    if open.is_empty() {
        add(None, Sev::Info, tr("Sin puertos habituales abiertos"), tr("No se encontraron servicios en los puertos comprobados.").into(), "");
    }
}

pub fn start_audit(targets: Vec<String>, gateway: Option<Ipv4Addr>, state: Shared<Audit>, stop: Arc<AtomicBool>, ctx: egui::Context) {
    stop.store(false, Ordering::Relaxed);
    {
        let mut s = lock(&state);
        *s = Audit { running: true, hosts_total: targets.len(), ..Default::default() };
    }
    thread::spawn(move || {
        for t in targets {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            lock(&state).step = tf("Auditando {}…", &[&(t)]);
            ctx.request_repaint();
            let mut f = Vec::new();
            let mut o = Vec::new();
            audit_host(&t, gateway, &mut f, &mut o, &stop);
            let mut s = lock(&state);
            s.findings.extend(f);
            s.findings.sort_by(|a, b| b.sev.cmp(&a.sev));
            s.open_ports.extend(o);
            s.hosts_done += 1;
            s.score = Some(score(&s.findings));
            ctx.request_repaint();
        }
        let mut s = lock(&state);
        s.running = false;
        s.step = tr("Auditoría terminada").into();
        s.score = Some(score(&s.findings));
        s.finished = Some(now_secs());
        ctx.request_repaint();
    });
}
