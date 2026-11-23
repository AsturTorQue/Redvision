//! «Seguridad de este equipo»: revisa la configuración del propio ordenador con las herramientas
//! del sistema (sin permisos especiales): cortafuegos, antivirus, cifrado de disco, servicios de
//! acceso remoto abiertos a la red, DNS, proxy, archivo hosts, Wi-Fi, SSH y tiempo sin reiniciar.
use crate::egui;
use crate::i18n::{tf, tr};
use crate::ids::Sev;
use crate::lanaudit::{LanAudit, LanFinding};
use crate::util::*;
use std::net::IpAddr;

struct C {
    findings: Vec<LanFinding>,
    facts: Vec<(String, String)>,
}

impl C {
    fn add(&mut self, sev: Sev, title: String, detail: String, fix: &str) {
        self.findings.push(LanFinding { sev, title, detail, fix: tr(fix).to_string() });
    }
    fn fact(&mut self, k: &str, v: String) {
        self.facts.push((tr(k).to_string(), v));
    }
}

fn yes_no(b: Option<bool>) -> String {
    match b {
        Some(true) => tr("sí").into(),
        Some(false) => tr("no").into(),
        None => tr("no se pudo comprobar").into(),
    }
}

fn firewall() -> Option<bool> {
    if cfg!(windows) {
        let out = run("netsh", &["advfirewall", "show", "allprofiles", "state"])?;
        let states: Vec<String> = out
            .lines()
            .filter(|l| {
                let l = l.to_lowercase();
                l.starts_with("estado") || l.starts_with("state") || l.starts_with("état") || l.starts_with("status")
            })
            .map(|l| l.to_lowercase())
            .collect();
        if states.is_empty() {
            return None;
        }
        // «DESACTIVAR» contiene «activ»: mirar primero si alguno está apagado
        let off = states.iter().any(|l| l.contains("off") || l.contains("desactiv") || l.contains("inactif") || l.contains("aus"));
        Some(!off)
    } else if cfg!(target_os = "macos") {
        let out = run("/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"])?;
        Some(out.contains("enabled") || out.contains("State = 1") || out.contains("State = 2"))
    } else {
        let out = run("systemctl", &["is-active", "firewalld", "ufw", "nftables", "iptables"])?;
        Some(out.lines().any(|l| l.trim() == "active"))
    }
}

fn antivirus() -> Option<bool> {
    if !cfg!(windows) {
        return None;
    }
    let out = run("powershell", &["-NoProfile", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled"])?;
    match out.trim().to_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn disk_encrypted() -> Option<bool> {
    if cfg!(windows) {
        let out = run(
            "powershell",
            &["-NoProfile", "-Command", "(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')"],
        )?;
        // 1 = activado, 3 = activado y desbloqueado; 2 = desactivado
        match out.trim() {
            "1" | "3" | "5" => Some(true),
            "2" | "0" => Some(false),
            _ => None,
        }
    } else if cfg!(target_os = "macos") {
        let out = run("fdesetup", &["status"])?;
        Some(out.contains("FileVault is On"))
    } else {
        let out = run("lsblk", &["-rno", "TYPE,FSTYPE"])?;
        Some(out.lines().any(|l| l.contains("crypt")))
    }
}

/// Días desde el último arranque.
fn uptime_days() -> Option<f64> {
    if cfg!(target_os = "linux") {
        let t = std::fs::read_to_string("/proc/uptime").ok()?;
        t.split_whitespace().next()?.parse::<f64>().ok().map(|s| s / 86400.0)
    } else if cfg!(target_os = "macos") {
        let out = run("sysctl", &["-n", "kern.boottime"])?;
        let sec: f64 = out.split("sec = ").nth(1)?.split(',').next()?.trim().parse().ok()?;
        Some((now_secs() - sec) / 86400.0)
    } else {
        let out = run("powershell", &["-NoProfile", "-Command", "[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours"])?;
        out.trim().parse::<f64>().ok().map(|h| h / 24.0)
    }
}

fn proxy() -> Option<String> {
    for v in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"] {
        if let Ok(p) = std::env::var(v) {
            if !p.trim().is_empty() {
                return Some(p);
            }
        }
    }
    if cfg!(windows) {
        let out = run("reg", &["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"])?;
        let enabled = out.lines().any(|l| l.contains("ProxyEnable") && l.trim_end().ends_with("0x1"));
        if enabled {
            let server = out.lines().find(|l| l.contains("ProxyServer")).and_then(|l| l.split_whitespace().last()).unwrap_or("?");
            return Some(server.to_string());
        }
    } else if cfg!(target_os = "macos") {
        let out = run("scutil", &["--proxy"])?;
        if out.lines().any(|l| l.trim() == "HTTPEnable : 1" || l.trim() == "HTTPSEnable : 1") {
            let host = out.lines().find(|l| l.trim().starts_with("HTTPSProxy") || l.trim().starts_with("HTTPProxy")).and_then(|l| l.split(':').nth(1)).unwrap_or("?");
            return Some(host.trim().to_string());
        }
    }
    None
}

/// Entradas del archivo hosts que no son de este equipo.
fn hosts_entries() -> Vec<String> {
    let path = if cfg!(windows) { r"C:\Windows\System32\drivers\etc\hosts" } else { "/etc/hosts" };
    let Ok(t) = std::fs::read_to_string(path) else { return Vec::new() };
    t.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter(|l| {
            let mut f = l.split_whitespace();
            let ip = f.next().unwrap_or("");
            let names: Vec<&str> = f.collect();
            let local_ip = ip.starts_with("127.") || ip == "::1" || ip.starts_with("ff0") || ip.starts_with("fe00") || ip == "0.0.0.0";
            let local_names = names.iter().all(|n| n.contains("localhost") || n.starts_with("ip6-") || *n == hostname() || n.starts_with(&hostname()));
            !(local_ip && local_names) && !(ip == "0.0.0.0" || ip.starts_with("127."))
        })
        .map(|l| l.to_string())
        .collect()
}

/// Servidores DNS conocidos y de confianza.
fn known_dns(ip: &IpAddr) -> bool {
    let s = ip.to_string();
    [
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
        "76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9", "2606:4700:4700::1111", "2001:4860:4860::8888", "2620:fe::fe",
    ]
    .contains(&s.as_str())
}

fn dns_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn secure_boot() -> Option<bool> {
    if cfg!(windows) {
        let out = run("reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "/v", "UEFISecureBootEnabled"])?;
        let l = out.lines().find(|l| l.contains("UEFISecureBootEnabled"))?;
        Some(l.trim_end().ends_with("0x1"))
    } else if cfg!(target_os = "linux") {
        let dir = std::fs::read_dir("/sys/firmware/efi/efivars").ok()?;
        for e in dir.flatten() {
            if e.file_name().to_string_lossy().starts_with("SecureBoot-") {
                let b = std::fs::read(e.path()).ok()?;
                return b.last().map(|v| *v == 1);
            }
        }
        None
    } else {
        None
    }
}

fn auto_updates() -> Option<bool> {
    if cfg!(windows) {
        let out = run("reg", &["query", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "/v", "NoAutoUpdate"])?;
        let l = out.lines().find(|l| l.contains("NoAutoUpdate"));
        Some(!l.map(|l| l.trim_end().ends_with("0x1")).unwrap_or(false))
    } else if cfg!(target_os = "macos") {
        let out = run("defaults", &["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])?;
        match out.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    } else {
        None
    }
}

/// Programas de control remoto que están en marcha.
fn remote_tools() -> Vec<String> {
    const KNOWN: &[(&str, &str)] = &[
        ("teamviewer", "TeamViewer"), ("anydesk", "AnyDesk"), ("rustdesk", "RustDesk"), ("splashtop", "Splashtop"),
        ("logmein", "LogMeIn"), ("screenconnect", "ScreenConnect"), ("connectwise", "ScreenConnect"), ("ammyy", "Ammyy Admin"),
        ("supremo", "Supremo"), ("remoting_host", "Chrome Remote Desktop"), ("chrome-remote-desktop", "Chrome Remote Desktop"),
        ("x11vnc", "VNC"), ("vncserver", "VNC"), ("winvnc", "VNC"), ("tvnserver", "VNC"), ("meshagent", "MeshCentral"),
        ("ultraviewer", "UltraViewer"), ("quickassist", "Asistencia rápida"), ("parsecd", "Parsec"), ("ateraagent", "Atera"),
    ];
    let names: Vec<String> = if cfg!(target_os = "linux") {
        std::fs::read_dir("/proc").map(|rd| rd.flatten().filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok()).collect()).unwrap_or_default()
    } else if cfg!(windows) {
        run("tasklist", &["/fo", "csv", "/nh"]).unwrap_or_default().lines().map(|l| l.split(',').next().unwrap_or("").trim_matches('"').to_string()).collect()
    } else {
        run("ps", &["-axco", "comm"]).unwrap_or_default().lines().map(|l| l.to_string()).collect()
    };
    let mut found: Vec<String> = Vec::new();
    for n in names {
        let n = n.trim().to_lowercase();
        if let Some((_, label)) = KNOWN.iter().find(|(k, _)| n.contains(k)) {
            let label = tr(label).to_string();
            if !found.contains(&label) {
                found.push(label);
            }
        }
    }
    found
}

fn sshd_config() -> Option<(bool, bool)> {
    let t = std::fs::read_to_string("/etc/ssh/sshd_config").ok()?;
    let get = |key: &str| -> Option<String> {
        t.lines().map(|l| l.trim()).filter(|l| !l.starts_with('#')).find_map(|l| {
            let mut f = l.split_whitespace();
            if f.next()?.eq_ignore_ascii_case(key) {
                f.next().map(|v| v.to_lowercase())
            } else {
                None
            }
        })
    };
    let root = get("PermitRootLogin").map(|v| v == "yes").unwrap_or(false);
    let password = get("PasswordAuthentication").map(|v| v == "yes").unwrap_or(true);
    Some((root, password))
}

pub fn check(info: &NetInfo) -> (Vec<LanFinding>, Vec<(String, String)>) {
    let mut c = C { findings: Vec::new(), facts: Vec::new() };
    c.fact("Sistema", format!("{} · {}", info.os, info.hostname));

    // Cortafuegos
    let fw = firewall();
    c.fact("Cortafuegos activo", yes_no(fw));
    if fw == Some(false) {
        c.add(Sev::High, tr("El cortafuegos está desactivado").into(), tr("Sin cortafuegos, cualquier servicio que abras queda expuesto a toda la red.").into(), "Activa el cortafuegos del sistema (firewalld/ufw en Linux, Firewall de Windows o de macOS).");
    }
    // Antivirus (Windows)
    if cfg!(windows) {
        let av = antivirus();
        c.fact("Antivirus en tiempo real", yes_no(av));
        if av == Some(false) {
            c.add(Sev::High, tr("La protección antivirus en tiempo real está apagada").into(), tr("Windows no está analizando los archivos que abres o descargas.").into(), "Actívala en Seguridad de Windows > Protección antivirus y contra amenazas.");
        }
    }
    // Cifrado de disco
    let enc = disk_encrypted();
    c.fact("Disco cifrado", yes_no(enc));
    if enc == Some(false) {
        c.add(Sev::Medium, tr("El disco no está cifrado").into(), tr("Si pierdes el equipo o te lo roban, cualquiera puede leer tus archivos.").into(), "Activa BitLocker (Windows), FileVault (macOS) o el cifrado LUKS al instalar Linux.");
    }
    // Servicios abiertos a toda la red
    let conns = crate::ports::connections();
    let exposed: Vec<&crate::ports::Conn> = conns.iter().filter(|x| x.listening() && (x.local == "0.0.0.0" || x.local == "::" || x.local == "*") && x.proto.starts_with("TCP")).collect();
    let mut ports: Vec<u16> = exposed.iter().map(|x| x.lport).collect();
    ports.sort();
    ports.dedup();
    c.fact("Puertos abiertos a la red", if ports.is_empty() { tr("ninguno").into() } else { ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ") });
    let prog = |p: u16| exposed.iter().find(|x| x.lport == p).map(|x| x.process.clone()).filter(|s| !s.is_empty()).map(|s| format!(" ({})", s)).unwrap_or_default();
    for &p in &ports {
        let (sev, what) = match p {
            23 => (Sev::High, "Telnet"),
            5900..=5903 => (Sev::High, "VNC"),
            3389 => (Sev::Medium, "Escritorio remoto (RDP)"),
            21 => (Sev::Medium, "FTP"),
            3306 | 5432 | 6379 | 27017 | 1433 | 9200 | 11211 => (Sev::Medium, "Base de datos"),
            2375 => (Sev::Critical, "API de Docker"),
            445 | 139 if !cfg!(windows) => (Sev::Low, "Compartición de archivos (SMB)"),
            22 => (Sev::Info, "SSH"),
            _ => continue,
        };
        c.add(sev, tf("{} abierto a toda la red en el puerto {}{}", &[&tr(what), &p, &prog(p)]),
            tr("Cualquier equipo de tu red (o de Internet, si el router lo deja pasar) puede intentar entrar.").into(),
            "Si no lo usas, desactívalo; si lo usas, limítalo a los equipos que lo necesitan con el cortafuegos.");
    }
    if ports.len() > 15 {
        c.add(Sev::Low, tf("{} puertos abiertos a la red", &[&ports.len()]), tr("Cuantos más servicios escuchan, más puertas hay que vigilar.").into(), "Revisa en «Puertos» qué programas los abren y cierra los que no uses.");
    }
    // SSH
    if ports.contains(&22) {
        if let Some((root, password)) = sshd_config() {
            if root {
                c.add(Sev::Medium, tr("SSH permite entrar como root").into(), tr("Un atacante solo necesita adivinar una contraseña para tener el control total.").into(), "Pon «PermitRootLogin no» en /etc/ssh/sshd_config y reinicia SSH.");
            }
            if password {
                c.add(Sev::Low, tr("SSH acepta contraseñas").into(), tr("Las contraseñas se pueden adivinar por fuerza bruta; las claves SSH no.").into(), "Usa claves SSH y pon «PasswordAuthentication no».");
            }
        }
    }
    // DNS
    let dns_list = if info.dns.is_empty() { dns_servers() } else { info.dns.clone() };
    c.fact("Servidores DNS", dns_list.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
    let strange: Vec<String> = dns_list.iter().filter(|d| !dns_private(d) && !known_dns(d)).map(|d| d.to_string()).collect();
    if !strange.is_empty() {
        c.add(Sev::Medium, tf("DNS poco habitual: {}", &[&strange.join(", ")]),
            tr("No es el router ni un DNS público conocido. Puede ser el de tu proveedor, pero algunos programas maliciosos cambian el DNS para desviar tu navegación.").into(),
            "Comprueba que es el DNS de tu proveedor o tu empresa; si no lo reconoces, cámbialo por el del router o uno público (1.1.1.1, 9.9.9.9).");
    }
    // Proxy
    let px = proxy();
    c.fact("Proxy del sistema", px.clone().unwrap_or_else(|| tr("ninguno").into()));
    if let Some(p) = px {
        c.add(Sev::Medium, tf("Hay un proxy configurado: {}", &[&p]), tr("Todo tu tráfico web pasa por él. Si no lo pusiste tú (o tu empresa), podría estar espiándolo.").into(), "Si no lo reconoces, quítalo de la configuración de red del sistema.");
    }
    // Archivo hosts
    let hosts = hosts_entries();
    c.fact("Entradas en el archivo hosts", hosts.len().to_string());
    let sensitive = ["google", "microsoft", "windowsupdate", "apple", "bank", "banco", "paypal", "amazon", "facebook", "update", "antivirus", "kaspersky", "eset", "avast", "norton", "mcafee"];
    let bad: Vec<&String> = hosts.iter().filter(|l| sensitive.iter().any(|s| l.to_lowercase().contains(s))).collect();
    if !bad.is_empty() {
        c.add(Sev::High, tr("El archivo hosts redirige sitios importantes").into(),
            tf("Entradas: {}. Es un truco habitual del malware para bloquear actualizaciones o falsificar webs.", &[&bad.iter().take(4).map(|s| s.as_str()).collect::<Vec<_>>().join(" · ")]),
            "Revisa el archivo hosts y borra las líneas que no hayas añadido tú.");
    } else if !hosts.is_empty() {
        c.add(Sev::Info, tf("{} entradas propias en el archivo hosts", &[&hosts.len()]), tr("Normalmente las añade un administrador o un programa de bloqueo de anuncios.").into(), "");
    }
    // Wi-Fi actual
    let w = crate::wifi::scan(false);
    if let Some(l) = &w.current {
        let sec = w.aps.iter().find(|a| a.in_use).or_else(|| w.aps.iter().find(|a| a.ssid == l.ssid)).map(|a| (a.open(), a.security.to_uppercase()));
        c.fact("Red Wi-Fi", format!("{} · {}", l.ssid, sec.as_ref().map(|s| s.1.clone()).unwrap_or_default()));
        match sec {
            Some((true, _)) => c.add(Sev::High, tr("Estás conectado a una Wi-Fi abierta").into(), tr("Cualquiera cerca puede ver lo que envías sin cifrar.").into(), "Usa una red con contraseña o una VPN."),
            Some((_, s)) if s.contains("WEP") => c.add(Sev::High, tr("Tu red usa WEP").into(), tr("WEP se rompe en minutos.").into(), "Cambia a WPA2 o WPA3 en el router."),
            _ => {}
        }
    }
    // DNS: ¿responde a dominios que no existen? ¿valida DNSSEC?
    if let Some(&server) = dns_list.first() {
        let t = std::time::Duration::from_millis(2500);
        let nx = format!("rv{}-no-existe.example.com", (now_secs() * 1000.0) as u64 % 100_000_000);
        if let Ok((m, _)) = crate::dns::query(server, &nx, 1, false, t) {
            if m.rcode == 0 && m.answers.iter().any(|a| a.rtype == 1) {
                let ip = m.answers.iter().find(|a| a.rtype == 1).map(|a| a.data.clone()).unwrap_or_default();
                c.add(Sev::Medium, tr("Tu DNS responde a webs que no existen").into(),
                    tf("Al pedir un dominio inventado devuelve {}. Lo hacen algunos proveedores para mostrar publicidad, pero también es la señal de un DNS manipulado.", &[&ip]),
                    "Usa el DNS del router o uno público de confianza (1.1.1.1, 9.9.9.9).");
            }
        }
        let dnssec = crate::dns::query(server, "dnssec-failed.org", 1, false, t);
        if dnssec.is_err() {
            c.fact("El DNS valida DNSSEC", yes_no(None));
        }
        if let Ok((m, _)) = dnssec {
            let validates = m.rcode == 2;
            c.fact("El DNS valida DNSSEC", yes_no(Some(validates)));
            if !validates && m.rcode == 0 {
                c.add(Sev::Low, tr("Tu DNS no comprueba las firmas DNSSEC").into(),
                    tr("Acepta respuestas con la firma rota, así que no te protege de respuestas falsificadas.").into(),
                    "Usa un DNS que valide DNSSEC, como 1.1.1.1, 9.9.9.9 u 8.8.8.8.");
            }
        }
    }
    // Arranque seguro (Secure Boot)
    if let Some(sb) = secure_boot() {
        c.fact("Arranque seguro (Secure Boot)", yes_no(Some(sb)));
        if !sb {
            c.add(Sev::Low, tr("El arranque seguro está desactivado").into(),
                tr("Sin Secure Boot, un programa malicioso puede instalarse antes que el sistema y esconderse del antivirus.").into(),
                "Actívalo en la configuración UEFI/BIOS del equipo (si tu sistema lo admite).");
        }
    }
    // Actualizaciones automáticas
    if let Some(au) = auto_updates() {
        c.fact("Actualizaciones automáticas", yes_no(Some(au)));
        if !au {
            c.add(Sev::Medium, tr("Las actualizaciones automáticas están desactivadas").into(),
                tr("Los fallos de seguridad corregidos no llegan a tu equipo hasta que actualizas a mano.").into(),
                "Activa las actualizaciones automáticas del sistema.");
        }
    }
    // Programas de control remoto en marcha
    let remote = remote_tools();
    c.fact("Programas de control remoto", if remote.is_empty() { tr("ninguno").into() } else { remote.join(", ") });
    if !remote.is_empty() {
        c.add(Sev::Medium, tf("Programas de control remoto en marcha: {}", &[&remote.join(", ")]),
            tr("Permiten manejar este equipo a distancia. Son útiles, pero los estafadores los usan para robar: nunca dejes entrar a quien te llama diciendo ser soporte técnico.").into(),
            "Si no los usas, ciérralos y desinstálalos.");
    }
    // Puertos que el router abre a Internet (UPnP)
    match crate::netdiscover::upnp_port_mappings() {
        Ok(Some((router, maps))) => {
            c.fact("Puertos abiertos a Internet por UPnP", if maps.is_empty() { tr("ninguno").into() } else { maps.len().to_string() });
            if !maps.is_empty() {
                let list: Vec<String> = maps.iter().take(8).map(|m| {
                    let d = if m.description.is_empty() { String::new() } else { format!(" «{}»", m.description) };
                    format!("{} {} -> {}:{}{}", m.proto, m.external, m.internal_ip, m.internal_port, d)
                }).collect();
                c.add(if maps.len() > 3 { Sev::Medium } else { Sev::Low }, tf("El router abre {} puertos a Internet por UPnP", &[&maps.len()]),
                    tf("Desde Internet se puede llegar a: {}. Los abren los propios programas (juegos, consolas, P2P) sin preguntar.", &[&list.join(" · ")]),
                    "Si no reconoces alguno, apaga el programa que lo abrió o desactiva UPnP en el router.");
            } else {
                c.add(Sev::Info, tr("El router tiene UPnP activado").into(),
                    tf("Ahora no hay puertos abiertos, pero cualquier programa de tu red ({}) puede abrir uno hacia Internet sin preguntar.", &[&router]),
                    "Si no juegas en línea ni usas programas que lo necesiten, desactiva UPnP en el router.");
            }
        }
        Ok(None) => c.fact("Puertos abiertos a Internet por UPnP", tr("UPnP desactivado").into()),
        Err(_) => {}
    }
    // Días sin reiniciar
    if let Some(d) = uptime_days() {
        c.fact("Días sin reiniciar", format!("{:.0}", d));
        if d > 30.0 {
            c.add(Sev::Low, tf("El equipo lleva {:.0} días sin reiniciarse", &[&d]), tr("Muchas actualizaciones de seguridad no se aplican hasta reiniciar.").into(), "Reinicia el equipo y comprueba que no quedan actualizaciones pendientes.");
        }
    }
    // Ejecutando como superusuario todo el tiempo
    if info.admin {
        c.add(Sev::Info, tr("La app se está ejecutando como administrador").into(), tr("Solo hace falta para capturar paquetes; para lo demás es más seguro abrirla como usuario normal.").into(), "");
    }
    if c.findings.iter().all(|f| f.sev == Sev::Info) {
        c.add(Sev::Info, tr("No se han encontrado problemas en este equipo").into(), tr("Todo lo comprobado está dentro de lo normal.").into(), "");
    }
    c.findings.sort_by(|a, b| b.sev.cmp(&a.sev));
    (c.findings, c.facts)
}

pub fn start(state: Shared<LanAudit>, info: NetInfo, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        *s = LanAudit { running: true, step: tr("Revisando este equipo…").into(), ..Default::default() };
    }
    std::thread::spawn(move || {
        let (f, facts) = check(&info);
        let score = 100
            - f.iter()
                .map(|x| match x.sev {
                    Sev::Critical => 35,
                    Sev::High => 18,
                    Sev::Medium => 8,
                    Sev::Low => 3,
                    Sev::Info => 0,
                })
                .sum::<i32>()
                .min(100);
        let mut s = lock(&state);
        s.findings = f;
        s.facts = facts;
        s.score = Some(score);
        s.running = false;
        s.progress = 1.0;
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn dns_probe() {
        let t = std::time::Duration::from_millis(2500);
        for s in crate::util::dns_servers() {
            for (n, d) in [("rv123-no-existe.example.com", false), ("dnssec-failed.org", false)] {
                match crate::dns::query(s, n, 1, d, t) {
                    Ok((m, _)) => println!("{} {} rcode={} answers={}", s, n, m.rcode, m.answers.len()),
                    Err(e) => println!("{} {} err {}", s, n, e),
                }
            }
        }
    }
    /// Revisión real de este equipo: `cargo test -- --ignored --nocapture host_here`
    #[test]
    #[ignore]
    fn host_here() {
        let (f, facts) = super::check(&crate::util::detect());
        for (k, v) in facts {
            println!("  {} = {}", k, v);
        }
        for x in f {
            println!("  [{:?}] {} — {}", x.sev, x.title, x.detail);
        }
    }
}
