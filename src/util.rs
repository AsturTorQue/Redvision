//! Utilidades comunes: hora, formato, comandos del sistema y datos de la red local.
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type Shared<T> = Arc<Mutex<T>>;

pub fn shared<T>(v: T) -> Shared<T> {
    Arc::new(Mutex::new(v))
}

pub fn lock<T>(s: &Shared<T>) -> MutexGuard<'_, T> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn fmt_clock(ts: f64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, (ts.fract() * 1e9) as u32)
        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

pub fn fmt_clock_ms(ts: f64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, (ts.fract() * 1e9) as u32)
        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}

pub fn fmt_bytes(b: f64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{:.0} {}", v, units[i])
    } else {
        format!("{:.1} {}", v, units[i])
    }
}

/// Bytes por segundo -> texto en bits por segundo.
pub fn fmt_bps(bytes_per_sec: f64) -> String {
    let bits = bytes_per_sec * 8.0;
    if bits >= 1e9 {
        format!("{:.2} Gbps", bits / 1e9)
    } else if bits >= 1e6 {
        format!("{:.1} Mbps", bits / 1e6)
    } else if bits >= 1e3 {
        format!("{:.1} kbps", bits / 1e3)
    } else {
        format!("{:.0} bps", bits)
    }
}

pub fn sleep_while(ms: u64, stop: &AtomicBool) {
    let mut left = ms;
    while left > 0 && !stop.load(Ordering::Relaxed) {
        let step = left.min(100);
        std::thread::sleep(Duration::from_millis(step));
        left -= step;
    }
}

pub fn rand_u64() -> u64 {
    static S: AtomicU64 = AtomicU64::new(0);
    let mut x = S.load(Ordering::Relaxed);
    if x == 0 {
        x = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(88172645463325252)
            | 1;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    S.store(x, Ordering::Relaxed);
    x
}

/// Entropía de Shannon en bits por carácter.
pub fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let b = s.as_bytes();
    if b.is_empty() {
        return 0.0;
    }
    for &c in b {
        counts[c as usize] += 1;
    }
    let n = b.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

pub fn printable(b: &[u8], max: usize) -> String {
    let mut s = String::new();
    for &c in b.iter().take(max) {
        if c == b'\r' || c == b'\n' {
            if !s.ends_with(' ') {
                s.push(' ');
            }
        } else if (0x20..0x7f).contains(&c) {
            s.push(c as char);
        } else {
            s.push('.');
        }
    }
    s.trim().to_string()
}

// ---------------------------------------------------------------- comandos

pub fn command(program: &str) -> Command {
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    c.stdin(Stdio::null());
    c
}

/// Ejecuta un programa y devuelve su salida (estándar + errores).
pub fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = command(program).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

pub fn ipv4s_in(s: &str) -> Vec<Ipv4Addr> {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter_map(|t| {
            let t = t.trim_matches('.');
            if t.matches('.').count() == 3 {
                t.parse().ok()
            } else {
                None
            }
        })
        .collect()
}

pub fn normalize_mac(t: &str) -> Option<String> {
    let parts: Vec<&str> = t.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = Vec::new();
    for p in parts {
        if p.is_empty() || p.len() > 2 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        out.push(format!("{:0>2}", p.to_uppercase()));
    }
    Some(out.join(":"))
}

fn mac_in(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '[' || c == ']')
        .find_map(normalize_mac)
}

// ---------------------------------------------------------------- red local

#[derive(Clone, Default)]
pub struct NetInfo {
    pub ready: bool,
    pub hostname: String,
    pub os: String,
    pub local_ip: Option<Ipv4Addr>,
    pub prefix: u8,
    pub iface: String,
    pub gateway: Option<Ipv4Addr>,
    pub gateway_guessed: bool,
    pub dns: Vec<IpAddr>,
    pub admin: bool,
}

impl NetInfo {
    pub fn network_label(&self) -> String {
        match self.local_ip {
            Some(ip) => {
                let p = effective_prefix(self.prefix);
                let net = u32::from(ip) & mask(p);
                format!("{}/{}", Ipv4Addr::from(net), p)
            }
            None => "sin red".into(),
        }
    }
}

pub fn os_name() -> String {
    match std::env::consts::OS {
        "linux" => "Linux".into(),
        "windows" => "Windows".into(),
        "macos" => "macOS".into(),
        o => o.into(),
    }
}

pub fn hostname() -> String {
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        return h;
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            return h.into();
        }
    }
    run("hostname", &[]).map(|s| s.trim().to_string()).unwrap_or_else(|| "equipo".into())
}

pub fn local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v) if !v.is_unspecified() => Some(v),
        _ => None,
    }
}

fn mask_prefix(m: Ipv4Addr) -> Option<u8> {
    let v = u32::from(m);
    if v == 0 {
        return None;
    }
    if v.leading_ones() + v.trailing_zeros() == 32 {
        Some(v.leading_ones() as u8)
    } else {
        None
    }
}

pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// Redes mayores que /22 se limitan a /24 para que el barrido sea rápido.
pub fn effective_prefix(p: u8) -> u8 {
    if p < 22 || p > 30 {
        24
    } else {
        p
    }
}

pub fn subnet_hosts(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let p = effective_prefix(prefix);
    let m = mask(p);
    let net = u32::from(ip) & m;
    let bcast = net | !m;
    ((net + 1)..bcast).map(Ipv4Addr::from).collect()
}

fn prefix_of(ip: Ipv4Addr) -> Option<(u8, String)> {
    let ips = ip.to_string();
    if cfg!(target_os = "linux") {
        let out = run("ip", &["-o", "-4", "addr", "show"])?;
        let pre = format!("{}/", ips);
        for line in out.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            for t in &toks {
                if let Some(rest) = t.strip_prefix(&pre) {
                    if let Ok(p) = rest.parse::<u8>() {
                        let iface = toks.get(1).unwrap_or(&"").trim_end_matches(':').to_string();
                        return Some((p, iface));
                    }
                }
            }
        }
        None
    } else if cfg!(windows) {
        let out = run("ipconfig", &[])?;
        let lines: Vec<&str> = out.lines().collect();
        let mut iface = String::new();
        for (i, l) in lines.iter().enumerate() {
            if !l.starts_with(' ') && !l.trim().is_empty() {
                iface = l.trim().trim_end_matches(':').to_string();
            }
            if ipv4s_in(l).contains(&ip) {
                for l2 in lines.iter().skip(i + 1).take(3) {
                    for m in ipv4s_in(l2) {
                        if let Some(p) = mask_prefix(m) {
                            return Some((p, iface));
                        }
                    }
                }
            }
        }
        None
    } else {
        let out = run("ifconfig", &[])?;
        let mut iface = String::new();
        for l in out.lines() {
            if !l.starts_with(char::is_whitespace) {
                iface = l.split(':').next().unwrap_or("").to_string();
            }
            let toks: Vec<&str> = l.split_whitespace().collect();
            if toks.len() >= 4 && toks[0] == "inet" && toks[1] == ips {
                if let Some(i) = toks.iter().position(|t| *t == "netmask") {
                    let m = toks.get(i + 1)?;
                    if let Some(h) = m.strip_prefix("0x") {
                        if let Ok(v) = u32::from_str_radix(h, 16) {
                            return Some((v.count_ones() as u8, iface));
                        }
                    }
                    if let Ok(mip) = m.parse::<Ipv4Addr>() {
                        return mask_prefix(mip).map(|p| (p, iface));
                    }
                }
            }
        }
        None
    }
}

pub fn gateway() -> Option<Ipv4Addr> {
    if cfg!(target_os = "linux") {
        let txt = std::fs::read_to_string("/proc/net/route").ok()?;
        for l in txt.lines().skip(1) {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() > 2 && t[1] == "00000000" {
                if let Ok(v) = u32::from_str_radix(t[2], 16) {
                    if v != 0 {
                        return Some(Ipv4Addr::from(v.to_le_bytes()));
                    }
                }
            }
        }
        None
    } else if cfg!(windows) {
        let out = run("route", &["print", "-4"])?;
        for l in out.lines() {
            if l.trim_start().starts_with("0.0.0.0") {
                let ips = ipv4s_in(l);
                if ips.len() >= 3 && !ips[2].is_unspecified() {
                    return Some(ips[2]);
                }
            }
        }
        None
    } else {
        let out = run("route", &["-n", "get", "default"])?;
        for l in out.lines() {
            if l.trim_start().starts_with("gateway:") {
                return ipv4s_in(l).first().copied();
            }
        }
        None
    }
}

pub fn dns_servers() -> Vec<IpAddr> {
    let mut v = Vec::new();
    if cfg!(windows) {
        if let Some(out) = run("ipconfig", &["/all"]) {
            let mut in_dns = false;
            for l in out.lines() {
                if l.contains("DNS") && l.contains(':') {
                    let ips = ipv4s_in(l.split_once(':').map(|x| x.1).unwrap_or(""));
                    in_dns = !ips.is_empty();
                    v.extend(ips.into_iter().map(IpAddr::V4));
                } else if in_dns {
                    let ips = ipv4s_in(l);
                    if ips.len() == 1 && l.trim().parse::<Ipv4Addr>().is_ok() {
                        v.push(IpAddr::V4(ips[0]));
                    } else {
                        in_dns = false;
                    }
                }
            }
        }
    } else if let Ok(txt) = std::fs::read_to_string("/etc/resolv.conf") {
        for l in txt.lines() {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() >= 2 && t[0] == "nameserver" {
                if let Ok(ip) = t[1].split('%').next().unwrap_or("").parse::<IpAddr>() {
                    v.push(ip);
                }
            }
        }
    }
    v.dedup();
    v
}

pub fn is_admin() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        command("net")
            .arg("session")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

pub fn detect() -> NetInfo {
    let mut n = NetInfo {
        os: os_name(),
        hostname: hostname(),
        local_ip: local_ipv4(),
        prefix: 24,
        ..Default::default()
    };
    if let Some(ip) = n.local_ip {
        if let Some((p, iface)) = prefix_of(ip) {
            n.prefix = p;
            n.iface = iface;
        }
    }
    n.gateway = gateway();
    if n.gateway.is_none() {
        if let Some(ip) = n.local_ip {
            let o = ip.octets();
            n.gateway = Some(Ipv4Addr::new(o[0], o[1], o[2], 1));
            n.gateway_guessed = true;
        }
    }
    n.dns = dns_servers();
    if n.dns.is_empty() {
        if let Some(g) = n.gateway {
            n.dns.push(IpAddr::V4(g));
        }
        n.dns.push(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }
    n.admin = is_admin();
    n.ready = true;
    n
}

/// Tabla ARP del sistema: (IP, MAC).
pub fn arp_table() -> Vec<(Ipv4Addr, String)> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        if let Ok(txt) = std::fs::read_to_string("/proc/net/arp") {
            for l in txt.lines().skip(1) {
                let t: Vec<&str> = l.split_whitespace().collect();
                if t.len() >= 4 {
                    if let (Ok(ip), Some(mac)) = (t[0].parse::<Ipv4Addr>(), normalize_mac(t[3])) {
                        if mac != "00:00:00:00:00:00" {
                            v.push((ip, mac));
                        }
                    }
                }
            }
        }
        return v;
    }
    let out = if cfg!(windows) { run("arp", &["-a"]) } else { run("arp", &["-an"]) };
    if let Some(out) = out {
        for l in out.lines() {
            let ips = ipv4s_in(l);
            if let (Some(ip), Some(mac)) = (ips.first(), mac_in(l)) {
                if mac != "FF:FF:FF:FF:FF:FF" && !mac.starts_with("01:00:5E") {
                    v.push((*ip, mac));
                }
            }
        }
    }
    v
}

const OUI: &[(&str, &str)] = &[
    ("00:50:56", "VMware"), ("00:0C:29", "VMware"), ("00:05:69", "VMware"),
    ("08:00:27", "VirtualBox"), ("52:54:00", "QEMU/KVM"), ("00:15:5D", "Hyper-V"),
    ("B8:27:EB", "Raspberry Pi"), ("DC:A6:32", "Raspberry Pi"), ("E4:5F:01", "Raspberry Pi"),
    ("D8:3A:DD", "Raspberry Pi"), ("28:CD:C1", "Raspberry Pi"),
    ("00:03:93", "Apple"), ("00:1B:63", "Apple"), ("00:25:00", "Apple"), ("F0:18:98", "Apple"),
    ("A4:83:E7", "Apple"), ("3C:22:FB", "Apple"), ("AC:BC:32", "Apple"),
    ("3C:5A:B4", "Google"), ("F4:F5:D8", "Google"), ("54:60:09", "Google"), ("18:B4:30", "Google Nest"),
    ("00:17:88", "Philips Hue"),
    ("24:0A:C4", "Espressif (IoT)"), ("30:AE:A4", "Espressif (IoT)"), ("84:F3:EB", "Espressif (IoT)"),
    ("A4:CF:12", "Espressif (IoT)"), ("24:6F:28", "Espressif (IoT)"), ("EC:FA:BC", "Espressif (IoT)"),
    ("5C:CF:7F", "Espressif (IoT)"), ("BC:DD:C2", "Espressif (IoT)"),
    ("00:09:5B", "Netgear"), ("00:14:6C", "Netgear"),
    ("50:C7:BF", "TP-Link"), ("F4:F2:6D", "TP-Link"), ("EC:08:6B", "TP-Link"), ("C0:4A:00", "TP-Link"),
    ("14:CC:20", "TP-Link"), ("98:DA:C4", "TP-Link"),
    ("00:00:0C", "Cisco"), ("00:1B:54", "Cisco"),
    ("00:15:6D", "Ubiquiti"), ("04:18:D6", "Ubiquiti"), ("24:A4:3C", "Ubiquiti"), ("68:72:51", "Ubiquiti"),
    ("F0:9F:C2", "Ubiquiti"), ("78:8A:20", "Ubiquiti"), ("FC:EC:DA", "Ubiquiti"), ("80:2A:A8", "Ubiquiti"),
    ("00:1B:21", "Intel"), ("00:1E:0B", "HP"), ("3C:D9:2B", "HP"),
    ("F0:27:2D", "Amazon"), ("74:C2:46", "Amazon"), ("FC:65:DE", "Amazon"), ("44:65:0D", "Amazon"),
    ("00:E0:FC", "Huawei"), ("00:18:82", "Huawei"),
    ("00:0E:58", "Sonos"), ("5C:AA:FD", "Sonos"), ("94:9F:3E", "Sonos"), ("B8:E9:37", "Sonos"),
    ("B0:A7:37", "Roku"), ("DC:3A:5E", "Roku"),
    ("00:04:0E", "AVM"), ("3C:A6:2F", "AVM"), ("C0:25:06", "AVM"), ("2C:91:AB", "AVM"),
];

/// Fabricante aproximado a partir del prefijo de la MAC.
pub fn vendor(mac: &str) -> String {
    if mac.len() < 8 {
        return String::new();
    }
    let p = &mac[..8];
    if let Some((_, v)) = OUI.iter().find(|(o, _)| *o == p) {
        return v.to_string();
    }
    if let Ok(b) = u8::from_str_radix(&mac[..2], 16) {
        if b & 0x02 != 0 {
            return crate::i18n::tr("MAC privada (aleatoria)").into();
        }
    }
    String::new()
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 | 8080 | 8000 | 8008 | 8888 | 81 => "HTTP",
        110 | 995 => "POP3",
        111 => "RPC",
        119 => "NNTP",
        123 => "NTP",
        135 => "MS-RPC",
        137 | 138 | 139 => "NetBIOS",
        143 | 993 => "IMAP",
        161 | 162 => "SNMP",
        179 => "BGP",
        389 | 636 => "LDAP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        500 | 4500 => "IPsec/IKE",
        514 => "Syslog",
        515 => "LPD",
        548 => "AFP",
        554 => "RTSP",
        631 => "IPP",
        853 => "DNS-TLS",
        873 => "rsync",
        1080 => "SOCKS",
        1194 => "OpenVPN",
        1433 => "MSSQL",
        1521 => "Oracle",
        1723 => "PPTP",
        1883 | 8883 => "MQTT",
        1900 => "SSDP/UPnP",
        2049 => "NFS",
        2375 | 2376 => "Docker",
        3000 => "Dev-HTTP",
        3306 => "MySQL",
        3389 => "RDP",
        3478 => "STUN",
        5000 => "UPnP/HTTP",
        5060 | 5061 => "SIP",
        5353 => "mDNS",
        5355 => "LLMNR",
        5432 => "PostgreSQL",
        5900..=5903 => "VNC",
        6379 => "Redis",
        6667 => "IRC",
        8009 => "Cast",
        9000 => "HTTP-alt",
        9100 => "Impresora",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        27017 => "MongoDB",
        51820 => "WireGuard",
        62078 => "iPhone-sync",
        _ => "",
    }
}

pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 515, 548, 554, 587,
    631, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2375, 3000, 3306, 3389, 4444,
    5000, 5060, 5432, 5900, 5901, 6379, 6667, 8000, 8008, 8009, 8080, 8081, 8443, 8883, 8888, 9000,
    9100, 9200, 11211, 12345, 27017, 31337, 49152, 62078,
];
