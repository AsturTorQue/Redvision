//! Detección de intrusos y anomalías a partir del tráfico capturado y del estado de la red.
use crate::packet::Summary;
use crate::util::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Sev {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Sev {
    pub fn label(&self) -> &'static str {
        match self {
            Sev::Info => "Info",
            Sev::Low => "Baja",
            Sev::Medium => "Media",
            Sev::High => "Alta",
            Sev::Critical => "Crítica",
        }
    }
    pub fn all() -> [Sev; 5] {
        [Sev::Critical, Sev::High, Sev::Medium, Sev::Low, Sev::Info]
    }
}

#[derive(Clone)]
pub struct Alert {
    pub ts: f64,
    pub sev: Sev,
    pub cat: String,
    pub src: String,
    pub msg: String,
}

pub const RULES: &[(&str, &str)] = &[
    ("Escaneo de puertos", "Un equipo prueba 20 o más puertos distintos en 10 segundos."),
    ("Escaneo sigiloso", "Paquetes TCP NULL, FIN o XMAS, típicos de herramientas de escaneo."),
    ("Barrido de red", "Un equipo contacta 25 o más direcciones distintas en 10 segundos."),
    ("Inundación SYN", "Más de 300 intentos de conexión por segundo a un mismo destino."),
    ("Inundación ICMP", "Más de 50 pings por segundo desde un mismo equipo."),
    ("Suplantación ARP", "Una IP cambia de MAC o una MAC se hace pasar por la puerta de enlace."),
    ("DHCP no autorizado", "Ofertas DHCP de un servidor que no es el router."),
    ("Túnel DNS", "Nombres DNS muy largos o aleatorios, típicos de exfiltración de datos."),
    ("Puertos sospechosos", "Tráfico hacia puertos usados por troyanos o botnets (4444, 31337, 6667…)."),
    ("Credenciales en claro", "Usuarios y contraseñas enviados sin cifrar (FTP, Telnet, POP3, HTTP Basic)."),
    ("Nuevo dispositivo", "Aparece en la red una MAC que no se había visto."),
    ("Pico de tráfico", "El tráfico de una interfaz supera mucho su comportamiento normal."),
    ("Equipo caído", "Un equipo vigilado deja de responder."),
];

const BAD_PORTS: &[u16] = &[4444, 31337, 1337, 6666, 6667, 12345, 27374, 5554, 9001, 1080];

struct Window {
    start: f64,
    ports: HashSet<u16>,
    hosts: HashSet<IpAddr>,
}

pub struct Ids {
    pub enabled: bool,
    pub alerts: Vec<Alert>,
    pub packets_seen: u64,
    pub gateway: Option<Ipv4Addr>,
    last: HashMap<String, f64>,
    windows: HashMap<IpAddr, Window>,
    syn: HashMap<IpAddr, (i64, u32)>,
    icmp: HashMap<IpAddr, (i64, u32)>,
    arp: HashMap<Ipv4Addr, String>,
    known_macs: HashSet<String>,
    baseline_done: bool,
}

impl Default for Ids {
    fn default() -> Self {
        Ids {
            enabled: true,
            alerts: Vec::new(),
            packets_seen: 0,
            gateway: None,
            last: HashMap::new(),
            windows: HashMap::new(),
            syn: HashMap::new(),
            icmp: HashMap::new(),
            arp: HashMap::new(),
            known_macs: HashSet::new(),
            baseline_done: false,
        }
    }
}

impl Ids {
    /// Registra una alerta; la misma clave no se repite en 30 segundos.
    pub fn raise(&mut self, sev: Sev, cat: &str, src: &str, msg: String, key: &str) {
        let now = now_secs();
        let k = format!("{}|{}", cat, key);
        if let Some(t) = self.last.get(&k) {
            if now - t < 30.0 {
                return;
            }
        }
        self.last.insert(k, now);
        self.alerts.push(Alert { ts: now, sev, cat: cat.into(), src: src.into(), msg });
        if self.alerts.len() > 5000 {
            self.alerts.drain(..500);
        }
    }

    pub fn count(&self, sev: Sev) -> usize {
        self.alerts.iter().filter(|a| a.sev == sev).count()
    }

    pub fn inspect(&mut self, s: &Summary, payload: &[u8], ts: f64) {
        self.packets_seen += 1;
        if !self.enabled {
            return;
        }
        let sec = ts as i64;
        if let Some(a) = &s.arp {
            self.check_arp_pair(a.sip, &a.smac);
        }
        if let (Some((2, _)), Some(IpAddr::V4(src))) = (&s.dhcp, s.src_ip) {
            if let Some(gw) = self.gateway {
                if src != gw && !src.is_unspecified() {
                    self.raise(Sev::High, "DHCP no autorizado", &src.to_string(),
                        format!("{} está ofreciendo direcciones DHCP y no es el router ({}).", src, gw), &src.to_string());
                }
            }
        }
        let (Some(src), Some(dst)) = (s.src_ip, s.dst_ip) else { return };
        let srcs = src.to_string();
        // Escaneos
        let is_syn = s.l4 == 6 && s.tcp_flags & 0x02 != 0 && s.tcp_flags & 0x10 == 0;
        if s.l4 == 6 && (s.tcp_flags == 0 || s.tcp_flags == 0x01 || s.tcp_flags & 0x29 == 0x29) {
            let kind = if s.tcp_flags == 0 { "NULL" } else if s.tcp_flags == 0x01 { "FIN" } else { "XMAS" };
            self.raise(Sev::High, "Escaneo sigiloso", &srcs, format!("Escaneo TCP {} desde {} hacia {}:{}", kind, src, dst, s.dport), &srcs);
        }
        if is_syn || (s.l4 == 17 && s.dport < 49152 && !matches!(s.dport, 53 | 123 | 443 | 5353 | 1900 | 137 | 138 | 67 | 68)) {
            let w = self.windows.entry(src).or_insert(Window { start: ts, ports: HashSet::new(), hosts: HashSet::new() });
            if ts - w.start > 10.0 {
                w.start = ts;
                w.ports.clear();
                w.hosts.clear();
            }
            w.ports.insert(s.dport);
            w.hosts.insert(dst);
            let (np, nh) = (w.ports.len(), w.hosts.len());
            if np >= 20 {
                self.raise(Sev::High, "Escaneo de puertos", &srcs, format!("{} probó {} puertos distintos en 10 s (último destino {}).", src, np, dst), &srcs);
            }
            if nh >= 25 {
                self.raise(Sev::Medium, "Barrido de red", &srcs, format!("{} contactó {} equipos distintos en 10 s.", src, nh), &srcs);
            }
        }
        if is_syn {
            let e = self.syn.entry(dst).or_insert((sec, 0));
            if e.0 != sec {
                *e = (sec, 0);
            }
            e.1 += 1;
            if e.1 > 300 {
                self.raise(Sev::Critical, "Inundación SYN", &srcs, format!("Más de 300 conexiones/s hacia {} (posible ataque de denegación de servicio).", dst), &dst.to_string());
            }
        }
        if matches!(s.icmp_type, Some(8) | Some(128)) {
            let e = self.icmp.entry(src).or_insert((sec, 0));
            if e.0 != sec {
                *e = (sec, 0);
            }
            e.1 += 1;
            if e.1 > 50 {
                self.raise(Sev::Medium, "Inundación ICMP", &srcs, format!("{} envía más de 50 pings por segundo.", src), &srcs);
            }
        }
        // DNS
        if let (Some(q), false) = (&s.dns_qname, s.dns_response) {
            let longest = q.split('.').map(|l| l.len()).max().unwrap_or(0);
            let first = q.split('.').next().unwrap_or("");
            if q.len() > 70 || (longest > 40 && entropy(first) > 3.8) {
                self.raise(Sev::Medium, "Túnel DNS", &srcs, format!("Consulta DNS anómala ({} caracteres): {}", q.len(), &q[..q.len().min(90)]), &srcs);
            }
        }
        // Puertos sospechosos
        if s.l4 == 6 || s.l4 == 17 {
            for p in [s.dport, s.sport] {
                if BAD_PORTS.contains(&p) {
                    self.raise(Sev::Medium, "Puertos sospechosos", &srcs, format!("Tráfico {} → {} en el puerto {}, usado a menudo por malware.", src, dst, p), &format!("{}-{}", srcs, p));
                    break;
                }
            }
        }
        // Credenciales en texto claro
        if s.l4 == 6 && !payload.is_empty() {
            let up = String::from_utf8_lossy(&payload[..payload.len().min(256)]).to_uppercase();
            let clear_port = matches!(s.dport, 21 | 23 | 110 | 143 | 25);
            if (clear_port && (up.starts_with("PASS ") || up.contains(" LOGIN ") || up.starts_with("AUTH PLAIN")))
                || up.contains("AUTHORIZATION: BASIC")
            {
                self.raise(Sev::High, "Credenciales en claro", &srcs,
                    format!("{} envió una contraseña sin cifrar a {}:{} ({}).", src, dst, s.dport, service_name(s.dport)), &format!("{}-{}", srcs, s.dport));
            }
        }
    }

    fn check_arp_pair(&mut self, ip: Ipv4Addr, mac: &str) {
        if ip.is_unspecified() || mac == "00:00:00:00:00:00" {
            return;
        }
        if let Some(prev) = self.arp.get(&ip) {
            if prev != mac {
                let sev = if Some(ip) == self.gateway { Sev::Critical } else { Sev::High };
                let msg = format!("La IP {} cambió de MAC: {} → {}. Puede ser un ataque de intermediario (ARP spoofing).", ip, prev, mac);
                self.raise(sev, "Suplantación ARP", &ip.to_string(), msg, &ip.to_string());
            }
        }
        self.arp.insert(ip, mac.to_string());
    }

    /// Revisa la tabla ARP del sistema: cambios de MAC, MAC duplicada del router y equipos nuevos.
    pub fn check_arp_table(&mut self, table: &[(Ipv4Addr, String)]) {
        if !self.enabled {
            return;
        }
        for (ip, mac) in table {
            self.check_arp_pair(*ip, mac);
        }
        if let Some(gw) = self.gateway {
            if let Some((_, gmac)) = table.iter().find(|(ip, _)| *ip == gw) {
                let others: Vec<String> = table.iter().filter(|(ip, m)| m == gmac && *ip != gw).map(|(ip, _)| ip.to_string()).collect();
                if !others.is_empty() {
                    self.raise(Sev::Medium, "Suplantación ARP", &others.join(", "),
                        format!("La MAC del router ({}) también aparece en {}. Puede ser un router con varias IP o un ataque de intermediario.", gmac, others.join(", ")), gmac);
                }
            }
        }
        for (ip, mac) in table {
            if self.known_macs.insert(mac.clone()) && self.baseline_done {
                self.raise(Sev::Info, "Nuevo dispositivo", &ip.to_string(), format!("Nuevo equipo en la red: {} ({}) {}", ip, mac, vendor(mac)), mac);
            }
        }
        self.baseline_done = true;
    }
}
