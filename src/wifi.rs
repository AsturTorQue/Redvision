//! Analizador Wi-Fi: redes cercanas, conexión actual, ocupación de canales y riesgos.
//! Usa las herramientas del sistema que no piden permisos: nmcli/iw (Linux),
//! netsh (Windows) y system_profiler (macOS).
use crate::egui;
use crate::i18n::{tf, tr};
use crate::ids::Sev;
use crate::lanaudit::LanFinding;
use crate::util::*;
use std::collections::VecDeque;
use std::thread;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum Band {
    #[default]
    G24,
    G5,
    G6,
}

impl Band {
    pub fn label(&self) -> &'static str {
        match self {
            Band::G24 => "2.4 GHz",
            Band::G5 => "5 GHz",
            Band::G6 => "6 GHz",
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Ap {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub band: Band,
    pub dbm: i32,
    pub security: String,
    pub rate: String,
    pub in_use: bool,
}

impl Ap {
    pub fn pct(&self) -> u32 {
        ((self.dbm + 100) * 2).clamp(0, 100) as u32
    }
    pub fn open(&self) -> bool {
        let s = self.security.trim().to_lowercase();
        s.is_empty() || s == "--" || s == "none" || s == "ninguna" || s == "abierta" || s == "open"
    }
}

#[derive(Clone, Default)]
pub struct Link {
    pub iface: String,
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub band: Band,
    pub dbm: Option<i32>,
    pub rate: String,
}

#[derive(Clone, Default)]
pub struct ScanResult {
    pub ifaces: Vec<String>,
    pub aps: Vec<Ap>,
    pub current: Option<Link>,
    pub source: String,
    pub error: Option<String>,
    pub time: f64,
}

#[derive(Default)]
pub struct WifiState {
    pub running: bool,
    pub last: Option<ScanResult>,
    pub history: VecDeque<Option<f64>>,
}

pub fn pct_to_dbm(p: u32) -> i32 {
    p.min(100) as i32 / 2 - 100
}

pub fn freq_to_channel(f: u32) -> (u32, Band) {
    match f {
        2484 => (14, Band::G24),
        2400..=2483 => ((f - 2407) / 5, Band::G24),
        5000..=5899 => ((f - 5000) / 5, Band::G5),
        5925..=7125 => ((f - 5950) / 5, Band::G6),
        _ => (0, Band::G24),
    }
}

fn band_of_channel(ch: u32) -> Band {
    if ch <= 14 {
        Band::G24
    } else {
        Band::G5
    }
}

fn digits(s: &str) -> Option<u32> {
    let d: String = s.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    d.parse().ok()
}

// ---------------------------------------------------------------- Linux

fn linux_ifaces() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().join("wireless").exists() || e.path().join("phy80211").exists())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Separa una línea «terse» de nmcli: los dos puntos dentro de un campo van escapados con «\».
fn split_terse(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut esc = false;
    for c in line.chars() {
        if esc {
            out.last_mut().unwrap().push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == ':' {
            out.push(String::new());
        } else {
            out.last_mut().unwrap().push(c);
        }
    }
    out
}

fn linux_link(iface: &str) -> Option<Link> {
    let out = run("iw", &["dev", iface, "link"])?;
    if !out.contains("Connected to") {
        return None;
    }
    let mut l = Link { iface: iface.into(), ..Default::default() };
    for line in out.lines() {
        let t = line.trim();
        if let Some(r) = t.strip_prefix("Connected to ") {
            l.bssid = r.split_whitespace().next().unwrap_or("").to_uppercase();
        } else if let Some(r) = t.strip_prefix("SSID: ") {
            l.ssid = r.to_string();
        } else if let Some(r) = t.strip_prefix("freq: ") {
            let f = r.split('.').next().and_then(|x| x.trim().parse().ok()).unwrap_or(0);
            let (ch, b) = freq_to_channel(f);
            l.channel = ch;
            l.band = b;
        } else if let Some(r) = t.strip_prefix("signal: ") {
            l.dbm = r.split_whitespace().next().and_then(|x| x.parse().ok());
        } else if let Some(r) = t.strip_prefix("tx bitrate: ") {
            l.rate = r.split(" MBit/s").next().map(|x| format!("{} Mbit/s", x.trim())).unwrap_or_default();
        }
    }
    Some(l)
}

fn scan_linux(rescan: bool) -> ScanResult {
    let mut r = ScanResult { ifaces: linux_ifaces(), source: "nmcli".into(), ..Default::default() };
    let fields = "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY";
    let mut args = vec!["-t", "-f", fields, "dev", "wifi", "list"];
    if rescan {
        args.extend_from_slice(&["--rescan", "yes"]);
    }
    let out = run("nmcli", &args).or_else(|| run("nmcli", &["-t", "-f", fields, "dev", "wifi", "list"]));
    match out {
        None => r.error = Some(tr("No se encontró «nmcli» (NetworkManager). Instálalo para ver las redes cercanas.").into()),
        Some(out) => {
            for line in out.lines() {
                let f = split_terse(line);
                if f.len() < 8 {
                    continue;
                }
                let freq = digits(&f[4]).unwrap_or(0);
                let (fch, band) = freq_to_channel(freq);
                let channel = f[3].trim().parse().unwrap_or(fch);
                let pct = f[6].trim().parse().unwrap_or(0);
                r.aps.push(Ap {
                    in_use: f[0].trim() == "*",
                    bssid: f[1].trim().to_uppercase(),
                    ssid: f[2].clone(),
                    channel,
                    band: if freq > 0 { band } else { band_of_channel(channel) },
                    rate: f[5].trim().to_string(),
                    dbm: pct_to_dbm(pct),
                    security: f[7].trim().to_string(),
                });
            }
        }
    }
    for i in &r.ifaces {
        if let Some(l) = linux_link(i) {
            r.current = Some(l);
            break;
        }
    }
    if r.current.is_none() {
        if let Some(ap) = r.aps.iter().find(|a| a.in_use) {
            r.current = Some(Link {
                iface: r.ifaces.first().cloned().unwrap_or_default(),
                ssid: ap.ssid.clone(),
                bssid: ap.bssid.clone(),
                channel: ap.channel,
                band: ap.band,
                dbm: Some(ap.dbm),
                rate: ap.rate.clone(),
            });
        }
    }
    r
}

// ---------------------------------------------------------------- Windows

fn kv(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim().to_lowercase(), v.trim().to_string()))
}

fn scan_windows() -> ScanResult {
    let mut r = ScanResult { source: "netsh".into(), ..Default::default() };
    let ifs = run("netsh", &["wlan", "show", "interfaces"]).unwrap_or_default();
    let mut link = Link::default();
    let mut connected = false;
    for line in ifs.lines() {
        let Some((k, v)) = kv(line) else { continue };
        if k == "name" || k == "nombre" {
            r.ifaces.push(v.clone());
            link.iface = v;
        } else if k == "ssid" {
            link.ssid = v;
            connected = true;
        } else if k.contains("bssid") {
            link.bssid = v.to_uppercase();
        } else if (k.contains("señal") || k.contains("signal")) && v.contains('%') {
            link.dbm = digits(&v).map(pct_to_dbm);
        } else if k == "canal" || k == "channel" {
            link.channel = digits(&v).unwrap_or(0);
            link.band = band_of_channel(link.channel);
        } else if k.contains("recepción") || k.contains("receive rate") {
            link.rate = format!("{} Mbit/s", v);
        }
    }
    if connected {
        r.current = Some(link);
    }
    let Some(out) = run("netsh", &["wlan", "show", "networks", "mode=bssid"]) else {
        r.error = Some(tr("No se pudo ejecutar «netsh».").into());
        return r;
    };
    let mut ssid = String::new();
    let mut security = String::new();
    for line in out.lines() {
        let t = line.trim();
        let Some((k, v)) = kv(t) else { continue };
        if k.starts_with("ssid") {
            ssid = v;
            security.clear();
        } else if k.contains("autenticación") || k.contains("authentication") {
            security = v;
        } else if k.starts_with("bssid") {
            r.aps.push(Ap { ssid: ssid.clone(), bssid: v.to_uppercase(), security: security.clone(), ..Default::default() });
        } else if let Some(ap) = r.aps.last_mut() {
            if (k.contains("señal") || k.contains("signal")) && v.contains('%') {
                ap.dbm = digits(&v).map(pct_to_dbm).unwrap_or(-100);
            } else if k == "canal" || k == "channel" {
                ap.channel = digits(&v).unwrap_or(0);
                ap.band = band_of_channel(ap.channel);
            } else if k == "banda" || k == "band" {
                if v.starts_with('6') {
                    ap.band = Band::G6;
                }
            }
        }
    }
    if let Some(c) = &r.current {
        for ap in r.aps.iter_mut() {
            ap.in_use = !c.bssid.is_empty() && ap.bssid == c.bssid;
        }
    }
    if r.aps.is_empty() && out.to_lowercase().contains("location") {
        r.error = Some(tr("Windows necesita el permiso de ubicación para listar redes Wi-Fi (Configuración > Privacidad > Ubicación).").into());
    }
    r
}

// ---------------------------------------------------------------- macOS

fn scan_macos() -> ScanResult {
    let mut r = ScanResult { source: "system_profiler".into(), ..Default::default() };
    let Some(out) = run("system_profiler", &["SPAirPortDataType"]) else {
        r.error = Some(tr("No se pudo ejecutar «system_profiler».").into());
        return r;
    };
    #[derive(PartialEq)]
    enum Sect {
        None,
        Current,
        Other,
    }
    let mut sect = Sect::None;
    let mut net_indent = 0usize;
    let mut cur: Option<Ap> = None;
    let mut link: Option<Link> = None;
    let flush = |cur: &mut Option<Ap>, aps: &mut Vec<Ap>| {
        if let Some(a) = cur.take() {
            aps.push(a);
        }
    };
    for line in out.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if t.starts_with("Interfaces:") {
            continue;
        }
        if t == "Current Network Information:" {
            flush(&mut cur, &mut r.aps);
            sect = Sect::Current;
            net_indent = indent + 2;
            continue;
        }
        if t == "Other Local Wi-Fi Networks:" {
            flush(&mut cur, &mut r.aps);
            sect = Sect::Other;
            net_indent = indent + 2;
            continue;
        }
        if sect == Sect::None {
            if t.ends_with(':') && !t.contains(' ') && indent <= 8 && t.starts_with("en") {
                r.ifaces.push(t.trim_end_matches(':').to_string());
            }
            continue;
        }
        if indent < net_indent && !t.is_empty() {
            flush(&mut cur, &mut r.aps);
            sect = Sect::None;
            continue;
        }
        if indent == net_indent && t.ends_with(':') {
            flush(&mut cur, &mut r.aps);
            cur = Some(Ap { ssid: t.trim_end_matches(':').to_string(), in_use: sect == Sect::Current, dbm: -100, ..Default::default() });
            continue;
        }
        let Some(ap) = cur.as_mut() else { continue };
        let Some((k, v)) = t.split_once(": ") else { continue };
        match k {
            "Channel" => {
                ap.channel = digits(v).unwrap_or(0);
                ap.band = if v.contains("6GHz") { Band::G6 } else if v.contains("5GHz") { Band::G5 } else { band_of_channel(ap.channel) };
            }
            "Security" => ap.security = v.to_string(),
            "Signal / Noise" => ap.dbm = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(-100),
            "Transmit Rate" => ap.rate = format!("{} Mbit/s", v),
            "BSSID" => ap.bssid = v.to_uppercase(),
            _ => {}
        }
        if ap.in_use {
            link = Some(Link {
                iface: r.ifaces.first().cloned().unwrap_or_default(),
                ssid: ap.ssid.clone(),
                bssid: ap.bssid.clone(),
                channel: ap.channel,
                band: ap.band,
                dbm: Some(ap.dbm),
                rate: ap.rate.clone(),
            });
        }
    }
    flush(&mut cur, &mut r.aps);
    r.current = link;
    r
}

pub fn scan(rescan: bool) -> ScanResult {
    let mut r = if cfg!(windows) {
        scan_windows()
    } else if cfg!(target_os = "macos") {
        scan_macos()
    } else {
        scan_linux(rescan)
    };
    r.aps.sort_by(|a, b| b.dbm.cmp(&a.dbm));
    r.time = now_secs();
    r
}

pub fn start_scan(state: Shared<WifiState>, rescan: bool, ctx: egui::Context) {
    lock(&state).running = true;
    thread::spawn(move || {
        let r = scan(rescan);
        let mut s = lock(&state);
        s.history.push_back(r.current.as_ref().and_then(|c| c.dbm).map(|d| d as f64 + 100.0));
        if s.history.len() > 120 {
            s.history.pop_front();
        }
        s.last = Some(r);
        s.running = false;
        ctx.request_repaint();
    });
}

// ---------------------------------------------------------------- análisis

pub const CH24: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
pub const CH5: &[u32] = &[36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];

/// Ocupación de cada canal: suma de la intensidad de las redes que lo pisan (de 0 a 1 por red).
pub fn congestion(aps: &[Ap], band: Band) -> Vec<(u32, f64)> {
    let chans = if band == Band::G24 { CH24 } else { CH5 };
    chans
        .iter()
        .map(|&ch| {
            let score: f64 = aps
                .iter()
                .filter(|a| a.band == band)
                .map(|a| {
                    let w = a.pct() as f64 / 100.0;
                    if band == Band::G24 {
                        let d = (a.channel as i32 - ch as i32).abs();
                        if d <= 4 {
                            w * (1.0 - d as f64 / 5.0)
                        } else {
                            0.0
                        }
                    } else if a.channel == ch {
                        w
                    } else {
                        0.0
                    }
                })
                .sum();
            (ch, score)
        })
        .collect()
}

pub fn best_channel(aps: &[Ap], band: Band) -> Option<u32> {
    let cands: &[u32] = if band == Band::G24 { &[1, 6, 11] } else { &[36, 40, 44, 48, 149, 153, 157, 161] };
    let c = congestion(aps, band);
    cands
        .iter()
        .filter_map(|ch| c.iter().find(|(x, _)| x == ch).copied())
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(ch, _)| ch)
}

pub fn findings(r: &ScanResult) -> Vec<LanFinding> {
    let mut v = Vec::new();
    let add = |v: &mut Vec<LanFinding>, sev: Sev, title: String, detail: String, fix: &str| {
        v.push(LanFinding { sev, title, detail, fix: tr(fix).to_string() });
    };
    let open: Vec<&Ap> = r.aps.iter().filter(|a| a.open() && !a.ssid.is_empty()).collect();
    if let Some(c) = &r.current {
        let mine: Vec<&Ap> = r.aps.iter().filter(|a| a.ssid == c.ssid && !c.ssid.is_empty()).collect();
        let my_sec = r.aps.iter().find(|a| a.in_use).or(mine.first().copied()).map(|a| a.security.clone()).unwrap_or_default();
        let up = my_sec.to_uppercase();
        if mine.first().map(|a| a.open()).unwrap_or(false) {
            add(&mut v, Sev::High, tr("Tu red Wi-Fi está abierta").into(), tr("Cualquiera cerca puede conectarse y ver el tráfico sin cifrar.").into(),
                "Activa WPA2 o WPA3 con una contraseña larga en el router.");
        } else if up.contains("WEP") {
            add(&mut v, Sev::High, tr("Tu red usa WEP").into(), tr("WEP se rompe en minutos.").into(), "Cambia a WPA2 o WPA3 en el router.");
        } else if up.contains("WPA") && !up.contains("WPA2") && !up.contains("WPA3") && !up.contains("RSN") {
            add(&mut v, Sev::Medium, tr("Tu red usa WPA (versión 1)").into(), tr("WPA1 con TKIP está obsoleto y es vulnerable.").into(), "Cambia a WPA2 o WPA3 en el router.");
        } else if up.contains("WPA2") && !up.contains("WPA3") {
            add(&mut v, Sev::Info, tr("Tu red usa WPA2").into(), tr("Es seguro con una contraseña larga; WPA3 añade más protección.").into(),
                "Si todos tus dispositivos lo admiten, activa WPA3 (o WPA2/WPA3) en el router.");
        }
        let secs: Vec<String> = mine.iter().map(|a| a.security.clone()).collect();
        if mine.iter().any(|a| a.security != my_sec) {
            add(&mut v, Sev::High, tr("Posible punto de acceso falso (evil twin)").into(),
                tf("Hay redes con tu mismo nombre «{}» pero distinta seguridad: {}.", &[&c.ssid, &secs.join(" / ")]),
                "Comprueba en el router cuántos puntos de acceso tienes; si uno no es tuyo, no te conectes a él.");
        }
        if let Some(d) = c.dbm {
            if d < -75 {
                add(&mut v, Sev::High, tf("Señal Wi-Fi débil ({:.0} dBm)", &[&(d as f64)]), tr("Con esta señal la conexión es lenta y se corta.").into(),
                    "Acércate al router, quita obstáculos o añade un repetidor o un sistema mesh.");
            } else if d < -67 {
                add(&mut v, Sev::Medium, tf("Señal Wi-Fi justa ({:.0} dBm)", &[&(d as f64)]), tr("Suficiente para navegar, pero no para videollamadas o juegos estables.").into(),
                    "Acércate al router o usa la banda de 5 GHz si está disponible.");
            }
        }
        if c.band == Band::G24 && mine.iter().any(|a| a.band != Band::G24) {
            add(&mut v, Sev::Low, tr("Estás en 2.4 GHz y tu red también emite en 5 GHz").into(),
                tr("La banda de 5 GHz es más rápida y tiene menos interferencias a corta distancia.").into(), "Conéctate a la red de 5 GHz o activa el cambio automático de banda en el router.");
        }
        if c.channel > 0 {
            if let Some(best) = best_channel(&r.aps, c.band) {
                let cong = congestion(&r.aps, c.band);
                let mine_score = cong.iter().find(|(ch, _)| *ch == c.channel).map(|x| x.1).unwrap_or(0.0);
                let best_score = cong.iter().find(|(ch, _)| *ch == best).map(|x| x.1).unwrap_or(0.0);
                let own = r.aps.iter().find(|a| a.in_use).map(|a| a.pct() as f64 / 100.0).unwrap_or(0.0);
                if best != c.channel && mine_score - own > best_score + 0.6 {
                    add(&mut v, Sev::Low, tf("El canal {} está saturado", &[&c.channel]),
                        tf("Hay muchas redes cerca en tu canal; el canal {} está más libre.", &[&best]),
                        "Cambia el canal Wi-Fi en la configuración del router.");
                }
            }
        }
    }
    if !open.is_empty() {
        let names: Vec<String> = open.iter().take(5).map(|a| a.ssid.clone()).collect();
        add(&mut v, Sev::Low, tf("{} redes abiertas cerca", &[&open.len()]),
            tf("Sin contraseña: {}. Lo que se envía por ellas puede ser visto por otros.", &[&names.join(", ")]),
            "Evita conectarte a redes abiertas o usa una VPN.");
    }
    let hidden = r.aps.iter().filter(|a| a.ssid.is_empty()).count();
    if hidden > 0 {
        add(&mut v, Sev::Info, tf("{} redes ocultas", &[&hidden]), tr("No anuncian su nombre; ocultar el nombre no aporta seguridad real.").into(), "");
    }
    v.sort_by(|a, b| b.sev.cmp(&a.sev));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_terse_and_channels() {
        let f = split_terse(r"*:AA\:BB\:CC\:DD\:EE\:FF:Mi red\: casa:6:2437 MHz:130 Mbit/s:72:WPA2");
        assert_eq!(f[1], "AA:BB:CC:DD:EE:FF");
        assert_eq!(f[2], "Mi red: casa");
        assert_eq!(freq_to_channel(2437), (6, Band::G24));
        assert_eq!(freq_to_channel(5180), (36, Band::G5));
        assert_eq!(pct_to_dbm(72), -64);
        let aps = vec![
            Ap { ssid: "a".into(), channel: 1, band: Band::G24, dbm: -40, ..Default::default() },
            Ap { ssid: "b".into(), channel: 6, band: Band::G24, dbm: -40, ..Default::default() },
        ];
        assert_eq!(best_channel(&aps, Band::G24), Some(11));
    }
}

#[cfg(test)]
mod live {
    /// Búsqueda real en este equipo: `cargo test -- --ignored --nocapture wifi_scan`.
    #[test]
    #[ignore]
    fn wifi_scan_here() {
        let r = super::scan(false);
        println!("fuente {} · interfaces {:?} · error {:?}", r.source, r.ifaces, r.error);
        for a in r.aps.iter().take(15) {
            println!("  {:<24} {} ch{:>3} {:?} {} dBm {}", a.ssid, a.bssid, a.channel, a.band, a.dbm, a.security);
        }
        println!("actual: {:?}", r.current.as_ref().map(|c| (&c.ssid, c.dbm, c.channel)));
        for f in super::findings(&r) {
            println!("  [{:?}] {}", f.sev, f.title);
        }
    }
}
