//! Monitorización continua: tráfico por interfaz, latencia al router, equipos vigilados,
//! conexiones y tabla ARP (para el detector de intrusos).
use crate::i18n::{tr, tf};
use crate::ids::{Ids, Sev};
use crate::ping::{measure, resolve, Method};
use crate::ports::{connections, Conn};
use crate::util::*;
use crate::egui;
use std::collections::{BTreeMap, VecDeque};
use std::thread;
use std::time::{Duration, Instant};

pub const HIST: usize = 120;

#[derive(Default, Clone)]
pub struct IfaceStat {
    pub rx: u64,
    pub tx: u64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub hist: VecDeque<(f64, f64)>,
    mean: f64,
    var: f64,
    n: u32,
}

#[derive(Clone)]
pub struct Watched {
    pub host: String,
    pub up: Option<bool>,
    pub last_rtt: Option<f64>,
    pub checks: u64,
    pub ok: u64,
    pub hist: VecDeque<Option<f64>>,
    pub since: f64,
}

impl Watched {
    pub fn new(host: String) -> Self {
        Watched { host, up: None, last_rtt: None, checks: 0, ok: 0, hist: VecDeque::new(), since: now_secs() }
    }
}

#[derive(Default)]
pub struct MonitorState {
    pub ifaces: BTreeMap<String, IfaceStat>,
    pub gw_latency: VecDeque<Option<f64>>,
    pub watched: Vec<Watched>,
    pub conns: Vec<Conn>,
    pub conns_time: f64,
    pub ticks: u64,
}

impl MonitorState {
    pub fn total_rates(&self) -> (f64, f64) {
        self.ifaces
            .iter()
            .filter(|(n, _)| !is_loopback(n))
            .fold((0.0, 0.0), |a, (_, s)| (a.0 + s.rx_rate, a.1 + s.tx_rate))
    }
    pub fn total_hist(&self) -> Vec<(f64, f64)> {
        let mut out = vec![(0.0, 0.0); HIST];
        for (n, s) in &self.ifaces {
            if is_loopback(n) {
                continue;
            }
            let off = HIST - s.hist.len().min(HIST);
            for (i, v) in s.hist.iter().enumerate() {
                if off + i < HIST {
                    out[off + i].0 += v.0;
                    out[off + i].1 += v.1;
                }
            }
        }
        out
    }
}

pub fn is_loopback(n: &str) -> bool {
    n == "lo" || n.starts_with("lo0") || n.to_lowercase().contains("loopback")
}

pub fn read_counters() -> Vec<(String, u64, u64)> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        if let Ok(txt) = std::fs::read_to_string("/proc/net/dev") {
            for l in txt.lines().skip(2) {
                if let Some((name, rest)) = l.split_once(':') {
                    let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
                    if f.len() >= 9 {
                        v.push((name.trim().to_string(), f[0], f[8]));
                    }
                }
            }
        }
    } else if cfg!(windows) {
        if let Some(out) = run("netstat", &["-e"]) {
            for l in out.lines() {
                if l.trim_start().starts_with("Bytes") {
                    let nums: Vec<u64> = l.split_whitespace().filter_map(|x| x.parse().ok()).collect();
                    if nums.len() >= 2 {
                        v.push(("Total".into(), nums[0], nums[1]));
                    }
                }
            }
        }
    } else if let Some(out) = run("netstat", &["-ib"]) {
        for l in out.lines().skip(1) {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() >= 7 && t.get(2).is_some_and(|x| x.starts_with("<Link")) {
                let n = t.len();
                if let (Ok(ib), Ok(ob)) = (t[n - 5].parse::<u64>(), t[n - 2].parse::<u64>()) {
                    v.push((t[0].to_string(), ib, ob));
                }
            }
        }
    }
    v
}

pub fn start_monitor(state: Shared<MonitorState>, info: Shared<NetInfo>, ids: Shared<Ids>, ctx: egui::Context) {
    thread::spawn(move || {
        let mut last = Instant::now();
        let mut tick: u64 = 0;
        loop {
            let dt = last.elapsed().as_secs_f64().max(0.2);
            last = Instant::now();
            // 1. Contadores de interfaces
            let counters = read_counters();
            let mut spikes = Vec::new();
            {
                let mut s = lock(&state);
                for (name, rx, tx) in counters {
                    let st = s.ifaces.entry(name.clone()).or_default();
                    if st.rx > 0 || st.tx > 0 {
                        st.rx_rate = rx.saturating_sub(st.rx) as f64 / dt;
                        st.tx_rate = tx.saturating_sub(st.tx) as f64 / dt;
                        st.hist.push_back((st.rx_rate, st.tx_rate));
                        if st.hist.len() > HIST {
                            st.hist.pop_front();
                        }
                        let total = st.rx_rate + st.tx_rate;
                        if st.n > 30 && !is_loopback(&name) {
                            let sd = st.var.sqrt();
                            if total > st.mean + 6.0 * sd && total > 2_000_000.0 {
                                spikes.push((name.clone(), total, st.mean));
                            }
                        }
                        let a = 0.05;
                        let d = total - st.mean;
                        st.mean += a * d;
                        st.var = (1.0 - a) * (st.var + a * d * d);
                        st.n += 1;
                    }
                    st.rx = rx;
                    st.tx = tx;
                }
                s.ticks = tick;
            }
            if !spikes.is_empty() {
                let mut ids = lock(&ids);
                for (n, v, m) in spikes {
                    ids.raise(Sev::Low, tr("Pico de tráfico"), &n, tf("La interfaz {} alcanzó {} (lo normal es {}).", &[&(n), &(fmt_bps(v)), &(fmt_bps(m))]), &n);
                }
            }
            // 2. Latencia al router cada 2 s
            if tick % 2 == 0 {
                let gw = lock(&info).gateway;
                if let Some(gw) = gw {
                    let st = state.clone();
                    let c = ctx.clone();
                    thread::spawn(move || {
                        let r = measure(std::net::IpAddr::V4(gw), Method::Icmp, 1000);
                        let mut s = lock(&st);
                        s.gw_latency.push_back(r);
                        if s.gw_latency.len() > HIST {
                            s.gw_latency.pop_front();
                        }
                        c.request_repaint();
                    });
                }
            }
            // 3. Equipos vigilados cada 5 s
            if tick % 5 == 1 {
                let hosts: Vec<String> = lock(&state).watched.iter().map(|w| w.host.clone()).collect();
                for h in hosts {
                    let st = state.clone();
                    let ids = ids.clone();
                    let c = ctx.clone();
                    thread::spawn(move || {
                        let r = resolve(&h).and_then(|ip| measure(ip, Method::Icmp, 1500));
                        let mut s = lock(&st);
                        if let Some(w) = s.watched.iter_mut().find(|w| w.host == h) {
                            w.checks += 1;
                            let up = r.is_some();
                            if up {
                                w.ok += 1;
                            }
                            if w.up.is_some() && w.up != Some(up) {
                                w.since = now_secs();
                                let (sev, msg) = if up { (Sev::Info, tf("{} vuelve a responder.", &[&(h)])) } else { (Sev::High, tf("{} ha dejado de responder.", &[&(h)])) };
                                lock(&ids).raise(sev, tr("Equipo caído"), &h, msg, &format!("{}-{}", h, up));
                            }
                            w.up = Some(up);
                            w.last_rtt = r;
                            w.hist.push_back(r);
                            if w.hist.len() > 60 {
                                w.hist.pop_front();
                            }
                        }
                        c.request_repaint();
                    });
                }
            }
            // 4. Conexiones cada 3 s y tabla ARP cada 10 s
            if tick % 3 == 0 {
                let c = connections();
                let mut s = lock(&state);
                s.conns = c;
                s.conns_time = now_secs();
            }
            // Cada 30 s: ¿ha cambiado el router o el DNS? (el malware que secuestra la navegación lo hace)
            if tick % 30 == 15 {
                let (gw_now, dns_now) = (gateway(), dns_servers());
                let mut inf = lock(&info);
                if inf.ready {
                    if let (Some(old), Some(new)) = (inf.gateway, gw_now) {
                        if old != new && !inf.gateway_guessed {
                            lock(&ids).raise(Sev::High, tr("Cambio de router"), &new.to_string(),
                                tf("La puerta de enlace ha cambiado de {} a {}. Es normal si cambiaste de red; si no, alguien podría estar desviando tu tráfico.", &[&old, &new]), &new.to_string());
                        }
                    }
                    if !dns_now.is_empty() && !inf.dns.is_empty() && dns_now != inf.dns {
                        let fmt = |v: &[std::net::IpAddr]| v.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ");
                        lock(&ids).raise(Sev::High, tr("Cambio de DNS"), &fmt(&dns_now),
                            tf("Los servidores DNS han cambiado de {} a {}. Si no lo hiciste tú ni cambiaste de red, revísalo: es un truco habitual para desviar la navegación.", &[&fmt(&inf.dns), &fmt(&dns_now)]), &fmt(&dns_now));
                    }
                    if gw_now.is_some() {
                        inf.gateway = gw_now;
                    }
                    if !dns_now.is_empty() {
                        inf.dns = dns_now;
                    }
                }
            }
            if tick % 10 == 2 {
                let table = arp_table();
                let gw = lock(&info).gateway;
                let mut ids = lock(&ids);
                ids.gateway = gw;
                ids.check_arp_table(&table);
            }
            ctx.request_repaint();
            tick += 1;
            let el = last.elapsed();
            if el < Duration::from_secs(1) {
                thread::sleep(Duration::from_secs(1) - el);
            }
        }
    });
}
