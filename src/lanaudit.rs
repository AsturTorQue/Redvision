//! Diagnóstico de la red local: busca las causas habituales de una LAN lenta o inestable.
use crate::egui;
use crate::i18n::{tf, tr};
use crate::ids::Sev;
use crate::ping::{measure, stats, Method};
use crate::util::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct LanFinding {
    pub sev: Sev,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

#[derive(Default)]
pub struct LanAudit {
    pub running: bool,
    pub step: String,
    pub progress: f32,
    pub findings: Vec<LanFinding>,
    pub facts: Vec<(String, String)>,
    pub score: Option<i32>,
}

fn score(f: &[LanFinding]) -> i32 {
    100 - f
        .iter()
        .map(|x| match x.sev {
            Sev::Critical => 35,
            Sev::High => 18,
            Sev::Medium => 8,
            Sev::Low => 3,
            Sev::Info => 0,
        })
        .sum::<i32>()
        .min(100)
}

struct Ctx {
    state: Shared<LanAudit>,
    ui: egui::Context,
    findings: Vec<LanFinding>,
    facts: Vec<(String, String)>,
}

impl Ctx {
    fn step(&self, text: &str, p: f32) {
        let mut s = lock(&self.state);
        s.step = text.to_string();
        s.progress = p;
        s.findings = self.findings.clone();
        s.facts = self.facts.clone();
        drop(s);
        self.ui.request_repaint();
    }
    fn add(&mut self, sev: Sev, title: String, detail: String, fix: &str) {
        self.findings.push(LanFinding { sev, title, detail, fix: tr(fix).to_string() });
    }
    fn fact(&mut self, k: &str, v: String) {
        self.facts.push((tr(k).to_string(), v));
    }
}

/// Velocidad del enlace, dúplex, señal Wi-Fi y errores de la interfaz (lo que el sistema deja ver).
fn link_checks(c: &mut Ctx, iface: &str) {
    if cfg!(target_os = "linux") && !iface.is_empty() {
        let base = format!("/sys/class/net/{}", iface);
        let wireless = std::path::Path::new(&format!("{}/wireless", base)).exists()
            || std::fs::read_to_string("/proc/net/wireless").map(|t| t.contains(&format!("{}:", iface))).unwrap_or(false);
        c.fact("Tipo de conexión", tr(if wireless { "Wi-Fi" } else { "Cable (Ethernet)" }).into());
        if let Ok(sp) = std::fs::read_to_string(format!("{}/speed", base)) {
            if let Ok(mbps) = sp.trim().parse::<i64>() {
                if mbps > 0 {
                    c.fact("Velocidad del enlace", format!("{} Mb/s", mbps));
                    if !wireless && mbps <= 100 {
                        c.add(Sev::Medium, tf("El enlace va a {} Mb/s", &[&mbps]),
                            tr("La tarjeta y el router o switch han negociado una velocidad baja: el cable o el puerto limitan la red.").into(),
                            "Usa un cable de categoría 5e o superior y prueba otro puerto del router o del switch.");
                    }
                }
            }
        }
        if let Ok(d) = std::fs::read_to_string(format!("{}/duplex", base)) {
            let d = d.trim().to_string();
            if !d.is_empty() && d != "unknown" {
                c.fact("Dúplex", d.clone());
            }
            if d == "half" {
                c.add(Sev::High, tr("Conexión en dúplex medio").into(),
                    tr("El enlace solo puede enviar o recibir a la vez; suele deberse a un fallo de negociación y provoca colisiones y lentitud.").into(),
                    "Deja la tarjeta y el switch en negociación automática y cambia el cable.");
            }
        }
        if wireless {
            if let Ok(t) = std::fs::read_to_string("/proc/net/wireless") {
                if let Some(l) = t.lines().find(|l| l.trim_start().starts_with(&format!("{}:", iface))) {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    if let Some(dbm) = f.get(3).and_then(|x| x.trim_end_matches('.').parse::<f64>().ok()) {
                        let dbm = if dbm > 0.0 { dbm - 256.0 } else { dbm };
                        c.fact("Señal Wi-Fi", format!("{:.0} dBm", dbm));
                        if dbm < -75.0 {
                            c.add(Sev::High, tf("Señal Wi-Fi débil ({:.0} dBm)", &[&dbm]),
                                tr("Con esta señal la conexión es lenta y se corta.").into(),
                                "Acércate al router, quita obstáculos o añade un repetidor o un sistema mesh.");
                        } else if dbm < -67.0 {
                            c.add(Sev::Medium, tf("Señal Wi-Fi justa ({:.0} dBm)", &[&dbm]),
                                tr("Suficiente para navegar, pero no para videollamadas o juegos estables.").into(),
                                "Acércate al router o usa la banda de 5 GHz si está disponible.");
                        }
                    }
                }
            }
        }
        if let Ok(txt) = std::fs::read_to_string("/proc/net/dev") {
            if let Some(l) = txt.lines().find(|l| l.trim_start().starts_with(&format!("{}:", iface))) {
                let f: Vec<u64> = l.split(':').nth(1).unwrap_or("").split_whitespace().filter_map(|x| x.parse().ok()).collect();
                if f.len() >= 12 {
                    let pkts = (f[1] + f[9]).max(1);
                    let errs = f[2] + f[10];
                    let drops = f[3] + f[11];
                    c.fact("Errores / descartes", format!("{} / {}", errs, drops));
                    if errs as f64 / pkts as f64 > 0.001 {
                        c.add(Sev::Medium, tr("Errores de transmisión en la interfaz").into(),
                            tf("{} errores en {} paquetes: suele ser un cable dañado, un conector flojo o interferencias.", &[&errs, &pkts]),
                            "Cambia el cable o el puerto y aleja la conexión de fuentes de interferencia.");
                    }
                    if drops as f64 / pkts as f64 > 0.01 {
                        c.add(Sev::Low, tr("Paquetes descartados en la interfaz").into(),
                            tf("{} paquetes descartados: el equipo o el controlador no dan abasto.", &[&drops]),
                            "Actualiza el controlador de red y revisa programas que saturen la red.");
                    }
                }
            }
        }
    } else if cfg!(windows) {
        if let Some(out) = run("netsh", &["wlan", "show", "interfaces"]) {
            for l in out.lines() {
                let low = l.to_lowercase();
                if (low.contains("señal") || low.contains("signal")) && l.contains('%') {
                    let n: String = l.split(':').nth(1).unwrap_or("").chars().filter(|c| c.is_ascii_digit()).collect();
                    if let Ok(p) = n.parse::<u32>() {
                        c.fact("Tipo de conexión", tr("Wi-Fi").into());
                        c.fact("Señal Wi-Fi", format!("{}%", p));
                        if p < 40 {
                            c.add(Sev::High, tf("Señal Wi-Fi débil ({}%)", &[&p]), tr("Con esta señal la conexión es lenta y se corta.").into(),
                                "Acércate al router, quita obstáculos o añade un repetidor o un sistema mesh.");
                        } else if p < 60 {
                            c.add(Sev::Medium, tf("Señal Wi-Fi justa ({}%)", &[&p]), tr("Suficiente para navegar, pero no para videollamadas o juegos estables.").into(),
                                "Acércate al router o usa la banda de 5 GHz si está disponible.");
                        }
                    }
                }
                if (low.contains("velocidad de recepción") || low.contains("receive rate")) && l.contains(':') {
                    c.fact("Velocidad del enlace", format!("{} Mb/s", l.split(':').nth(1).unwrap_or("").trim()));
                }
            }
        }
    }
}

fn default_routes() -> usize {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/net/route")
            .map(|t| t.lines().skip(1).filter(|l| l.split_whitespace().nth(1) == Some("00000000")).count())
            .unwrap_or(0)
    } else if cfg!(windows) {
        run("route", &["print", "-4"])
            .map(|o| o.lines().filter(|l| l.trim_start().starts_with("0.0.0.0") && ipv4s_in(l).len() >= 3).count())
            .unwrap_or(0)
    } else {
        run("netstat", &["-rn", "-f", "inet"]).map(|o| o.lines().filter(|l| l.starts_with("default")).count()).unwrap_or(0)
    }
}

/// Interfaces (sin loopback) con una dirección en la misma red que la nuestra.
fn same_subnet_ifaces(local: Ipv4Addr, prefix: u8) -> Vec<String> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let m = mask(prefix);
    let mut v = Vec::new();
    for l in run("ip", &["-o", "-4", "addr", "show"]).unwrap_or_default().lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.len() < 4 || t[1] == "lo" {
            continue;
        }
        if let Some((ip, p)) = t[3].split_once('/') {
            if let (Ok(ip), Ok(p)) = (ip.parse::<Ipv4Addr>(), p.parse::<u8>()) {
                if p == prefix && u32::from(ip) & m == u32::from(local) & m && !v.contains(&t[1].to_string()) {
                    v.push(t[1].to_string());
                }
            }
        }
    }
    v
}

fn http_status(host: &str, path: &str) -> Option<String> {
    let addr = (host, 80).to_socket_addrs().ok()?.next()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(4)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok();
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host).as_bytes()).ok()?;
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).ok()?;
    String::from_utf8_lossy(&buf[..n]).lines().next().map(|l| l.to_string())
}

fn has_ipv6() -> bool {
    let Ok(s) = UdpSocket::bind("[::]:0") else { return false };
    if s.connect(SocketAddr::new(IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()), 53)).is_err() {
        return false;
    }
    matches!(s.local_addr().map(|a| a.ip()), Ok(IpAddr::V6(v)) if (v.segments()[0] & 0xe000) == 0x2000)
}

/// Descarga durante `secs` para cargar la línea (prueba de bufferbloat).
fn load_line(url: &str, secs: f64, stop: Arc<AtomicBool>) -> thread::JoinHandle<u64> {
    let url = url.to_string();
    thread::spawn(move || {
        let Some(rest) = url.strip_prefix("http://") else { return 0 };
        let (host, path) = rest.split_once('/').map(|(h, p)| (h.to_string(), format!("/{}", p))).unwrap_or((rest.to_string(), "/".into()));
        let Some(addr) = (host.as_str(), 80).to_socket_addrs().ok().and_then(|mut a| a.next()) else { return 0 };
        let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else { return 0 };
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let _ = s.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host).as_bytes());
        let mut buf = vec![0u8; 65536];
        let t0 = Instant::now();
        let mut total = 0u64;
        while t0.elapsed().as_secs_f64() < secs && !stop.load(Ordering::Relaxed) {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n as u64,
            }
        }
        total
    })
}

pub fn start(state: Shared<LanAudit>, info: NetInfo, load_url: Option<String>, ui: egui::Context) {
    {
        let mut s = lock(&state);
        *s = LanAudit { running: true, ..Default::default() };
    }
    thread::spawn(move || {
        let mut c = Ctx { state: state.clone(), ui, findings: Vec::new(), facts: Vec::new() };
        c.step(tr("Revisando la dirección del equipo…"), 0.05);
        // 1. Dirección
        match info.local_ip {
            None => {
                c.add(Sev::Critical, tr("Sin conexión de red").into(), tr("El equipo no tiene una dirección IPv4 con salida.").into(),
                    "Comprueba el cable o la conexión Wi-Fi y que el router esté encendido.");
            }
            Some(ip) => {
                c.fact("Dirección IP", format!("{}/{}", ip, info.prefix));
                c.fact("Interfaz", info.iface.clone());
                if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                    c.add(Sev::High, tr("Sin dirección del DHCP").into(),
                        tr("El equipo se ha puesto una dirección automática 169.254.x.x: el router no le ha dado IP.").into(),
                        "Reinicia el router y comprueba que su servidor DHCP esté activo.");
                }
                if info.prefix < 16 {
                    c.add(Sev::Low, tf("Red muy grande (/{})", &[&info.prefix]),
                        tr("Una red tan amplia genera mucho tráfico de difusión.").into(), "Usa una máscara /24 salvo que necesites más equipos.");
                }
                let others = same_subnet_ifaces(ip, info.prefix);
                if others.len() > 1 {
                    c.add(Sev::Low, tr("Dos conexiones a la misma red").into(),
                        tf("Las interfaces {} están en la misma red; el tráfico puede salir por la más lenta.", &[&others.join(", ")]),
                        "Desactiva el Wi-Fi cuando uses cable (o al revés).");
                }
            }
        }
        // 2. Enlace físico
        c.step(tr("Revisando el enlace y la señal…"), 0.15);
        link_checks(&mut c, &info.iface);
        // 3. Rutas
        let routes = default_routes();
        if routes > 1 {
            c.add(Sev::Low, tf("{} rutas por defecto", &[&routes]),
                tr("Hay varias salidas a Internet configuradas (VPN, Wi-Fi y cable…); el tráfico puede ir por la que no esperas.").into(),
                "Deja una sola conexión activa o ajusta las prioridades (métricas).");
        }
        // 4. Router
        c.step(tr("Midiendo el router (20 pings)…"), 0.25);
        let mut gw_avg = None;
        if let Some(gw) = info.gateway {
            c.fact("Puerta de enlace", gw.to_string());
            let v: Vec<Option<f64>> = (0..20)
                .map(|_| {
                    let r = measure(IpAddr::V4(gw), Method::Icmp, 1000);
                    thread::sleep(Duration::from_millis(100));
                    r
                })
                .collect();
            let st = stats(&v);
            if st.recv == 0 {
                c.add(Sev::Critical, tr("El router no responde").into(), tr("No hay respuesta de la puerta de enlace: sin ella no hay red.").into(),
                    "Comprueba el cable o el Wi-Fi y reinicia el router.");
            } else {
                gw_avg = Some(st.avg);
                c.fact("Router: latencia / jitter / pérdida", format!("{:.1} ms / {:.1} ms / {:.0}%", st.avg, st.jitter, st.loss));
                if st.loss >= 5.0 {
                    c.add(Sev::High, tf("Pérdida del {:.0}% hasta el router", &[&st.loss]),
                        tr("Se pierden paquetes dentro de tu propia red: cortes en llamadas, juegos y descargas.").into(),
                        "Si es Wi-Fi, acércate o cambia de canal; si es cable, cámbialo.");
                } else if st.loss > 0.0 {
                    c.add(Sev::Medium, tf("Pérdida del {:.0}% hasta el router", &[&st.loss]),
                        tr("Alguna pérdida dentro de la red local; puede notarse en llamadas y juegos.").into(),
                        "Si es Wi-Fi, acércate o cambia de canal; si es cable, cámbialo.");
                }
                if st.avg > 20.0 {
                    c.add(Sev::Medium, tf("Latencia alta en la red local ({:.0} ms)", &[&st.avg]),
                        tr("Lo normal hasta el router es menos de 5 ms por cable y menos de 20 ms por Wi-Fi.").into(),
                        "Revisa la señal Wi-Fi o si algún equipo está saturando la red.");
                }
                if st.jitter > 10.0 {
                    c.add(Sev::Low, tf("Latencia inestable en la red local (jitter {:.0} ms)", &[&st.jitter]),
                        tr("La latencia varía mucho: típico de Wi-Fi con interferencias o red congestionada.").into(),
                        "Cambia el canal Wi-Fi o usa cable para los equipos importantes.");
                }
            }
            // ARP: MAC del router repetida
            let arp = arp_table();
            if let Some((_, gmac)) = arp.iter().find(|(ip, _)| *ip == gw) {
                c.fact("MAC del router", format!("{} {}", gmac, vendor(gmac)));
                let dup: Vec<String> = arp.iter().filter(|(ip, m)| m == gmac && *ip != gw).map(|(ip, _)| ip.to_string()).collect();
                if !dup.is_empty() {
                    c.add(Sev::Medium, tr("La MAC del router aparece en otras IP").into(),
                        tf("También en {}: puede ser un router con varias IP o alguien suplantándolo.", &[&dup.join(", ")]),
                        "Comprueba en el router qué direcciones tiene; si no son suyas, revisa la red.");
                }
            }
            c.fact("Equipos en la tabla ARP", arp.len().to_string());
        }
        // 5. DNS
        c.step(tr("Comprobando el DNS…"), 0.45);
        if let Some(d) = info.dns.first() {
            c.fact("Servidor DNS", info.dns.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
            let times: Vec<f64> = ["example.com", "wikipedia.org", "debian.org"]
                .iter()
                .filter_map(|n| crate::dns::query(*d, n, 1, false, Duration::from_secs(2)).ok().map(|x| x.1))
                .collect();
            if times.is_empty() {
                c.add(Sev::High, tr("El DNS del sistema no responde").into(), tr("Las páginas tardarán en abrir o no abrirán. Revisa el router o usa un DNS público.").into(),
                    "Configura un DNS público (1.1.1.1 o 9.9.9.9) en el router o en el equipo.");
            } else {
                let avg = times.iter().sum::<f64>() / times.len() as f64;
                c.fact("Tiempo de DNS", format!("{:.0} ms", avg));
                if avg > 100.0 {
                    c.add(Sev::Medium, tf("DNS del sistema lento ({:.0} ms)", &[&avg]), tr("Un DNS por encima de 150 ms ralentiza la navegación.").into(),
                        "Configura un DNS público (1.1.1.1 o 9.9.9.9) en el router o en el equipo.");
                }
            }
        }
        // 6. Internet
        c.step(tr("Comprobando la salida a Internet…"), 0.55);
        let inet = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let v: Vec<Option<f64>> = (0..6).map(|_| measure(inet, Method::Icmp, 1000).or_else(|| measure(inet, Method::Tcp(443), 1000))).collect();
        let st = stats(&v);
        let idle = if st.recv > 0 { Some(st.avg) } else { None };
        match idle {
            None => c.add(Sev::High, tr("Sin salida a Internet").into(), tr("La red local funciona pero no se alcanza Internet.").into(),
                "Reinicia el router y comprueba con tu proveedor si hay una avería."),
            Some(a) => {
                c.fact("Internet: latencia", format!("{:.0} ms", a));
                if let Some(g) = gw_avg {
                    if g > a * 0.5 && a > 30.0 {
                        c.add(Sev::Medium, tr("Gran parte del retardo está ya en tu red local (router o Wi-Fi).").into(),
                            tf("Router {:.0} ms de un total de {:.0} ms.", &[&g, &a]), "Revisa la señal Wi-Fi o si algún equipo está saturando la red.");
                    }
                }
            }
        }
        match http_status("connectivitycheck.gstatic.com", "/generate_204") {
            Some(l) if l.contains(" 204") => c.fact("Acceso web directo", tr("sí").into()),
            Some(l) => c.add(Sev::Medium, tr("Portal cautivo o proxy en la red").into(),
                tf("Una petición web de prueba devolvió «{}» en lugar de 204.", &[&l]),
                "Si es una red de invitados, inicia sesión en su portal; si no, revisa el proxy del router."),
            None => {}
        }
        // 7. MTU e IPv6
        c.step(tr("Midiendo la MTU de la ruta…"), 0.65);
        if idle.is_some() {
            if let Ok(m) = crate::netdiscover::path_mtu("1.1.1.1", &|_| {}) {
                c.fact("MTU de la ruta", format!("{} bytes", m));
                if m < 1400 {
                    c.add(Sev::Low, tf("MTU de la ruta: {} bytes", &[&m]),
                        tr("Menor de 1500: hay un túnel, VPN o PPPoE en el camino. Si algunas webs no cargan, baja la MTU del equipo a este valor.").into(),
                        "Ajusta la MTU del equipo o del router a este valor.");
                }
            }
        }
        let v6 = has_ipv6();
        c.fact("IPv6", tr(if v6 { "sí" } else { "no" }).into());
        if !v6 {
            c.add(Sev::Info, tr("Sin IPv6").into(), tr("La red solo usa IPv4. Funciona, pero algunos servicios van mejor con IPv6.").into(),
                "Actívalo en el router si tu proveedor lo ofrece.");
        }
        // 8. Bufferbloat
        if let (Some(url), Some(idle)) = (load_url, idle) {
            c.step(tr("Cargando la línea para medir el bufferbloat (10 s)…"), 0.75);
            let stop = Arc::new(AtomicBool::new(false));
            let loads: Vec<_> = (0..4).map(|_| load_line(&url, 10.0, stop.clone())).collect();
            thread::sleep(Duration::from_millis(1500));
            let mut lv = Vec::new();
            let t0 = Instant::now();
            while t0.elapsed().as_secs_f64() < 8.0 {
                lv.push(measure(inet, Method::Icmp, 1500).or_else(|| measure(inet, Method::Tcp(443), 1500)));
                thread::sleep(Duration::from_millis(200));
            }
            stop.store(true, Ordering::Relaxed);
            let bytes: u64 = loads.into_iter().filter_map(|h| h.join().ok()).sum();
            let ls = stats(&lv);
            if ls.recv > 0 && bytes > 1_000_000 {
                let extra = (ls.avg - idle).max(0.0);
                let grade = if extra < 5.0 { "A+" } else if extra < 30.0 { "A" } else if extra < 60.0 { "B" } else if extra < 200.0 { "C" } else if extra < 400.0 { "D" } else { "F" };
                c.fact("Bufferbloat", tf("{} (+{:.0} ms con carga)", &[&grade, &extra]));
                if extra >= 200.0 {
                    c.add(Sev::High, tf("Bufferbloat alto: +{:.0} ms al usar la línea", &[&extra]),
                        tr("Cuando alguien descarga o sube algo, la latencia se dispara y las llamadas y juegos se resienten.").into(),
                        "Activa SQM / QoS (fq_codel o CAKE) en el router, limitando un 5-10 % por debajo de tu velocidad.");
                } else if extra >= 60.0 {
                    c.add(Sev::Medium, tf("Bufferbloat moderado: +{:.0} ms al usar la línea", &[&extra]),
                        tr("Cuando alguien descarga o sube algo, la latencia se dispara y las llamadas y juegos se resienten.").into(),
                        "Activa SQM / QoS (fq_codel o CAKE) en el router, limitando un 5-10 % por debajo de tu velocidad.");
                }
            } else {
                c.fact("Bufferbloat", tr("no medido (no se pudo cargar la línea)").into());
            }
        }
        if c.findings.iter().all(|f| f.sev == Sev::Info) {
            c.add(Sev::Info, tr("No se han encontrado problemas en la red local").into(), tr("Todo lo comprobado está dentro de lo normal.").into(), "");
        }
        c.findings.sort_by(|a, b| b.sev.cmp(&a.sev));
        c.step(tr("Diagnóstico terminado"), 1.0);
        let mut s = lock(&state);
        s.score = Some(score(&c.findings).max(0));
        s.running = false;
        c.ui.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Diagnóstico real de la red de quien lo ejecuta: `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn runs_on_this_network() {
        let st = shared(LanAudit::default());
        start(st.clone(), detect(), None, egui::Context::default());
        let t0 = Instant::now();
        while lock(&st).running && t0.elapsed().as_secs() < 120 {
            thread::sleep(Duration::from_millis(200));
        }
        let s = lock(&st);
        println!("puntuación {:?}", s.score);
        for (k, v) in &s.facts {
            println!("  {} = {}", k, v);
        }
        for f in &s.findings {
            println!("  [{:?}] {} — {}", f.sev, f.title, f.detail);
        }
        assert!(s.score.is_some());
    }
}
