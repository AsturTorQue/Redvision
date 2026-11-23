//! Puertos abiertos y conexiones activas de este equipo.
use crate::util::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct Conn {
    pub proto: String,
    pub local: String,
    pub lport: u16,
    pub remote: String,
    pub rport: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process: String,
}

impl Conn {
    pub fn listening(&self) -> bool {
        self.state == "ESCUCHANDO"
    }
}

fn state_es(s: &str) -> String {
    let u = s.to_uppercase();
    match u.as_str() {
        "LISTEN" | "LISTENING" | "ESCUCHANDO" | "0A" => "ESCUCHANDO",
        "ESTABLISHED" | "ESTABLECIDO" | "01" => "ESTABLECIDA",
        "SYN_SENT" | "02" => "SYN ENVIADO",
        "SYN_RECV" | "SYN_RECEIVED" | "03" => "SYN RECIBIDO",
        "FIN_WAIT1" | "FIN_WAIT_1" | "04" => "FIN_WAIT1",
        "FIN_WAIT2" | "FIN_WAIT_2" | "05" => "FIN_WAIT2",
        "TIME_WAIT" | "06" => "TIME_WAIT",
        "CLOSE" | "CLOSED" | "07" => "CERRADA",
        "CLOSE_WAIT" | "08" => "CLOSE_WAIT",
        "LAST_ACK" | "09" => "LAST_ACK",
        "CLOSING" | "0B" => "CERRANDO",
        _ => return u,
    }
    .to_string()
}

fn hex_addr(s: &str) -> Option<(String, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    if a.len() == 8 {
        let v = u32::from_str_radix(a, 16).ok()?;
        Some((Ipv4Addr::from(v.to_le_bytes()).to_string(), port))
    } else if a.len() == 32 {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let v = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let ip = Ipv6Addr::from(bytes);
        Some((ip.to_ipv4_mapped().map(|v| v.to_string()).unwrap_or_else(|| ip.to_string()), port))
    } else {
        None
    }
}

fn linux_inode_map() -> HashMap<u64, (u32, String)> {
    let mut m = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return m };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default().trim().to_string();
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else { continue };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let l = link.to_string_lossy();
                if let Some(inode) = l.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                    if let Ok(i) = inode.parse::<u64>() {
                        m.insert(i, (pid, comm.clone()));
                    }
                }
            }
        }
    }
    m
}

fn split_addr(s: &str, dot_style: bool) -> (String, u16) {
    let sep = if dot_style { s.rfind('.') } else { s.rfind(':') };
    match sep {
        Some(i) => (
            s[..i].trim_matches(|c| c == '[' || c == ']').to_string(),
            s[i + 1..].parse().unwrap_or(0),
        ),
        None => (s.to_string(), 0),
    }
}

pub fn connections() -> Vec<Conn> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        let inodes = linux_inode_map();
        for (file, proto) in [("tcp", "TCP"), ("tcp6", "TCP6"), ("udp", "UDP"), ("udp6", "UDP6")] {
            let Ok(txt) = std::fs::read_to_string(format!("/proc/net/{}", file)) else { continue };
            for l in txt.lines().skip(1) {
                let t: Vec<&str> = l.split_whitespace().collect();
                if t.len() < 10 {
                    continue;
                }
                let (Some((la, lp)), Some((ra, rp))) = (hex_addr(t[1]), hex_addr(t[2])) else { continue };
                let mut st = state_es(t[3]);
                if proto.starts_with("UDP") {
                    st = if rp == 0 { "ESCUCHANDO".into() } else { "ESTABLECIDA".into() };
                }
                let inode: u64 = t[9].parse().unwrap_or(0);
                let (pid, process) = inodes.get(&inode).cloned().map(|(p, n)| (Some(p), n)).unwrap_or((None, String::new()));
                v.push(Conn { proto: proto.into(), local: la, lport: lp, remote: ra, rport: rp, state: st, pid, process });
            }
        }
        return v;
    }
    let windows = cfg!(windows);
    let out = if windows { run("netstat", &["-ano"]) } else { run("netstat", &["-an"]) };
    let names: HashMap<u32, String> = if windows {
        run("tasklist", &["/fo", "csv", "/nh"])
            .map(|o| {
                o.lines()
                    .filter_map(|l| {
                        let f: Vec<&str> = l.split("\",\"").collect();
                        if f.len() > 1 {
                            Some((f[1].parse().ok()?, f[0].trim_matches('"').to_string()))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    for l in out.unwrap_or_default().lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.is_empty() {
            continue;
        }
        let p = t[0].to_lowercase();
        if !(p.starts_with("tcp") || p.starts_with("udp")) {
            continue;
        }
        let is_udp = p.starts_with("udp");
        let (li, ri, si) = if windows { (1, 2, 3) } else { (3, 4, 5) };
        if t.len() <= ri {
            continue;
        }
        let (la, lp) = split_addr(t[li], !windows);
        let (ra, rp) = split_addr(t[ri], !windows);
        let mut st = t.get(si).map(|s| state_es(s)).unwrap_or_default();
        let mut pid = None;
        if windows {
            let pid_tok = if is_udp { t.get(3) } else { t.get(4) };
            pid = pid_tok.and_then(|x| x.parse().ok());
        }
        if is_udp {
            st = if rp == 0 || ra == "*" { "ESCUCHANDO".into() } else { "ESTABLECIDA".into() };
        }
        let process = pid.and_then(|p| names.get(&p).cloned()).unwrap_or_default();
        v.push(Conn { proto: p.to_uppercase(), local: la, lport: lp, remote: ra, rport: rp, state: st, pid, process });
    }
    v
}
