//! Captura de paquetes en vivo (socket propio en Linux, tcpdump/dumpcap en los demás)
//! y lectura/escritura de archivos pcap y pcapng.
use crate::i18n::{tr, tf};
use crate::ids::Ids;
use crate::packet::{dissect, Packet, Summary};
use crate::util::*;
use crate::egui;
use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

#[derive(Default)]
pub struct CaptureState {
    pub packets: Vec<Packet>,
    pub running: bool,
    pub error: Option<String>,
    pub source: String,
    pub total: u64,
    pub bytes: u64,
    pub start: f64,
    pub last: f64,
    pub protos: HashMap<String, (u64, u64)>,
    pub talkers: HashMap<String, (u64, u64)>,
    pub convs: HashMap<(String, String, String), (u64, u64)>,
    pub dns: HashMap<String, u64>,
    pub sni: HashMap<String, u64>,
    pub http: VecDeque<(f64, String, String)>,
    pub dhcp: VecDeque<(f64, String)>,
    pub per_sec: VecDeque<(i64, u64, u64)>,
    pub syn: u64,
    pub synack: u64,
    pub rst: u64,
    next_no: u64,
}

const MAX_PACKETS: usize = 50_000;

impl CaptureState {
    pub fn reset(&mut self, source: String) {
        *self = CaptureState { source, start: now_secs(), ..Default::default() };
    }

    pub fn add(&mut self, ts: f64, data: Vec<u8>, orig_len: u32) -> (Summary, Vec<u8>) {
        let (s, _) = dissect(&data);
        self.next_no += 1;
        self.total += 1;
        let len = orig_len as u64;
        self.bytes += len;
        if self.start == 0.0 {
            self.start = ts;
        }
        self.last = ts;
        let e = self.protos.entry(s.proto.clone()).or_insert((0, 0));
        e.0 += 1;
        e.1 += len;
        if s.src_ip.is_some() {
            self.talkers.entry(s.src.clone()).or_insert((0, 0)).0 += len;
            self.talkers.entry(s.dst.clone()).or_insert((0, 0)).1 += len;
            let (a, b) = if s.src < s.dst { (s.src.clone(), s.dst.clone()) } else { (s.dst.clone(), s.src.clone()) };
            let c = self.convs.entry((a, b, s.proto.clone())).or_insert((0, 0));
            c.0 += 1;
            c.1 += len;
        }
        if s.l4 == 6 {
            if s.tcp_flags & 0x12 == 0x02 {
                self.syn += 1;
            }
            if s.tcp_flags & 0x12 == 0x12 {
                self.synack += 1;
            }
            if s.tcp_flags & 0x04 != 0 {
                self.rst += 1;
            }
        }
        if let (Some(q), false) = (&s.dns_qname, s.dns_response) {
            *self.dns.entry(q.clone()).or_insert(0) += 1;
        }
        if let Some(n) = &s.sni {
            *self.sni.entry(n.clone()).or_insert(0) += 1;
        }
        if let Some(h) = &s.http {
            self.http.push_back((ts, s.src.clone(), h.clone()));
            if self.http.len() > 500 {
                self.http.pop_front();
            }
        }
        if let Some((_, d)) = &s.dhcp {
            self.dhcp.push_back((ts, d.clone()));
            if self.dhcp.len() > 200 {
                self.dhcp.pop_front();
            }
        }
        let k = ts.floor() as i64;
        match self.per_sec.back_mut() {
            Some(last) if last.0 == k => {
                last.1 += len;
                last.2 += 1;
            }
            _ => {
                self.per_sec.push_back((k, len, 1));
                if self.per_sec.len() > 600 {
                    self.per_sec.pop_front();
                }
            }
        }
        let pay = data.get(s.payload_start..(s.payload_start + s.payload_len).min(s.payload_start + 512)).unwrap_or(&[]).to_vec();
        self.packets.push(Packet { no: self.next_no, ts, data, orig_len, s: s.clone() });
        if self.packets.len() > MAX_PACKETS {
            self.packets.drain(..MAX_PACKETS / 10);
        }
        (s, pay)
    }
}

pub struct CaptureCtl {
    pub stop: Arc<AtomicBool>,
    pub child: Arc<Mutex<Option<Child>>>,
}

impl Default for CaptureCtl {
    fn default() -> Self {
        CaptureCtl { stop: Arc::new(AtomicBool::new(false)), child: Arc::new(Mutex::new(None)) }
    }
}

impl CaptureCtl {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(c) = self.child.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let _ = c.kill();
        }
    }
}

struct Sink {
    state: Shared<CaptureState>,
    ids: Shared<Ids>,
    ctx: egui::Context,
    buf: Vec<(f64, Vec<u8>, u32)>,
    last: Instant,
    count: u64,
}

impl Sink {
    fn push(&mut self, ts: f64, frame: Vec<u8>, orig: u32) {
        self.buf.push((ts, frame, orig));
        self.count += 1;
        if self.buf.len() >= 256 || self.last.elapsed().as_millis() > 120 {
            self.flush();
        }
    }
    fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let mut sums = Vec::with_capacity(self.buf.len());
        {
            let mut st = lock(&self.state);
            for (ts, f, o) in self.buf.drain(..) {
                let (s, p) = st.add(ts, f, o);
                sums.push((s, p, ts));
            }
        }
        {
            let mut ids = lock(&self.ids);
            for (s, p, ts) in &sums {
                ids.inspect(s, p, *ts);
            }
        }
        self.last = Instant::now();
        self.ctx.request_repaint();
    }
}

/// Convierte una trama de cualquier tipo de enlace a Ethernet para tratarlas todas igual.
fn to_ethernet(linktype: u32, d: &[u8]) -> Option<Vec<u8>> {
    let fake = |et: u16, rest: &[u8]| {
        let mut v = vec![0u8; 12];
        v.extend_from_slice(&et.to_be_bytes());
        v.extend_from_slice(rest);
        v
    };
    let by_version = |rest: &[u8]| -> Vec<u8> {
        let et = match rest.first().map(|b| b >> 4) {
            Some(6) => 0x86DD,
            _ => 0x0800,
        };
        fake(et, rest)
    };
    match linktype {
        1 => Some(d.to_vec()),
        113 if d.len() >= 16 => Some(fake(u16::from_be_bytes([d[14], d[15]]), &d[16..])),
        276 if d.len() >= 20 => Some(fake(u16::from_be_bytes([d[0], d[1]]), &d[20..])),
        0 | 108 if d.len() >= 4 => Some(by_version(&d[4..])),
        101 | 12 | 14 | 228 | 229 => Some(by_version(d)),
        _ => Some(fake(0xFFFF, d)),
    }
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, String> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => return if got == 0 { Ok(false) } else { Err(tr("Archivo cortado").into()) },
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(true)
}

fn read_pcap_stream<R: Read>(mut r: R, sink: &mut Sink, stop: &AtomicBool) -> Result<(), String> {
    let mut magic = [0u8; 4];
    if !read_exact_or_eof(&mut r, &mut magic)? {
        return Err(tr("Sin datos").into());
    }
    let m = u32::from_le_bytes(magic);
    if m == 0x0A0D0D0A {
        return read_pcapng(r, magic, sink, stop);
    }
    let (le, nanos) = match m {
        0xa1b2c3d4 => (true, false),
        0xa1b23c4d => (true, true),
        0xd4c3b2a1 => (false, false),
        0x4d3cb2a1 => (false, true),
        _ => return Err(tr("No es un archivo pcap/pcapng válido").into()),
    };
    let rd = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    let mut hdr = [0u8; 20];
    if !read_exact_or_eof(&mut r, &mut hdr)? {
        return Err(tr("Cabecera pcap incompleta").into());
    }
    let linktype = rd(&hdr[16..20]) & 0xFFFF;
    let mut rec = [0u8; 16];
    while !stop.load(Ordering::Relaxed) {
        if !read_exact_or_eof(&mut r, &mut rec)? {
            break;
        }
        let secs = rd(&rec[0..4]) as f64;
        let frac = rd(&rec[4..8]) as f64;
        let incl = rd(&rec[8..12]) as usize;
        let orig = rd(&rec[12..16]);
        if incl > 262_144 {
            return Err(tr("Registro pcap demasiado grande").into());
        }
        let mut data = vec![0u8; incl];
        if !read_exact_or_eof(&mut r, &mut data)? {
            break;
        }
        let ts = secs + if nanos { frac / 1e9 } else { frac / 1e6 };
        if let Some(f) = to_ethernet(linktype, &data) {
            sink.push(ts, f, orig);
        }
    }
    sink.flush();
    Ok(())
}

fn read_pcapng<R: Read>(mut r: R, first: [u8; 4], sink: &mut Sink, stop: &AtomicBool) -> Result<(), String> {
    let mut links: Vec<u32> = Vec::new();
    let mut le = true;
    let mut btype = first;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut lenb = [0u8; 4];
        if !read_exact_or_eof(&mut r, &mut lenb)? {
            break;
        }
        let t = u32::from_le_bytes(btype);
        let mut blen = if le { u32::from_le_bytes(lenb) } else { u32::from_be_bytes(lenb) } as usize;
        if t == 0x0A0D0D0A {
            // Bloque de sección: averiguar el orden de bytes
            let mut bom = [0u8; 4];
            read_exact_or_eof(&mut r, &mut bom)?;
            le = u32::from_le_bytes(bom) == 0x1A2B3C4D;
            blen = if le { u32::from_le_bytes(lenb) } else { u32::from_be_bytes(lenb) } as usize;
            if blen < 16 || blen > 1 << 24 {
                return Err(tr("Bloque pcapng no válido").into());
            }
            let mut rest = vec![0u8; blen - 12];
            read_exact_or_eof(&mut r, &mut rest)?;
            links.clear();
        } else {
            if blen < 12 || blen > 1 << 24 {
                return Err(tr("Bloque pcapng no válido").into());
            }
            let mut body = vec![0u8; blen - 8];
            if !read_exact_or_eof(&mut r, &mut body)? {
                break;
            }
            let rd = |i: usize| -> u32 {
                let a = [body[i], body[i + 1], body[i + 2], body[i + 3]];
                if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
            };
            let bt = if le { t } else { t.swap_bytes() };
            match bt {
                1 if body.len() >= 4 => {
                    let lt = if le { u16::from_le_bytes([body[0], body[1]]) } else { u16::from_be_bytes([body[0], body[1]]) };
                    links.push(lt as u32);
                }
                6 if body.len() >= 20 => {
                    let iface = rd(0) as usize;
                    let ts = (((rd(4) as u64) << 32) | rd(8) as u64) as f64 / 1e6;
                    let cap = (rd(12) as usize).min(body.len() - 20);
                    let orig = rd(16);
                    let lt = links.get(iface).copied().unwrap_or(1);
                    if let Some(f) = to_ethernet(lt, &body[20..20 + cap]) {
                        sink.push(ts, f, orig);
                    }
                }
                3 if body.len() >= 4 => {
                    let orig = rd(0);
                    let cap = (orig as usize).min(body.len() - 4);
                    let lt = links.first().copied().unwrap_or(1);
                    if let Some(f) = to_ethernet(lt, &body[4..4 + cap]) {
                        sink.push(now_secs(), f, orig);
                    }
                }
                _ => {}
            }
        }
        if !read_exact_or_eof(&mut r, &mut btype)? {
            break;
        }
    }
    sink.flush();
    Ok(())
}

pub fn list_interfaces() -> Vec<String> {
    if cfg!(target_os = "linux") {
        let mut v = vec!["any".to_string()];
        if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
            let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            names.sort();
            v.extend(names);
        }
        v
    } else if cfg!(windows) {
        let prog = dumpcap_path();
        run(&prog, &["-D"])
            .map(|o| o.lines().filter(|l| l.chars().next().is_some_and(|c| c.is_ascii_digit())).map(|l| l.trim().to_string()).collect())
            .unwrap_or_default()
    } else {
        run("ifconfig", &["-l"]).map(|o| o.split_whitespace().map(String::from).collect()).unwrap_or_default()
    }
}

fn dumpcap_path() -> String {
    for p in ["C:\\Program Files\\Wireshark\\dumpcap.exe", "C:\\Program Files (x86)\\Wireshark\\dumpcap.exe"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    "dumpcap".into()
}

pub fn start_live(iface: String, state: Shared<CaptureState>, ids: Shared<Ids>, ctl: &CaptureCtl, ctx: egui::Context) {
    ctl.stop.store(false, Ordering::Relaxed);
    let stop = ctl.stop.clone();
    let child_slot = ctl.child.clone();
    {
        let mut s = lock(&state);
        s.reset(tf("En vivo · {}", &[&(if iface.is_empty() { tr("todas") } else { &iface })]));
        s.running = true;
    }
    thread::spawn(move || {
        let mut sink = Sink { state: state.clone(), ids, ctx: ctx.clone(), buf: Vec::new(), last: Instant::now(), count: 0 };
        let res = if cfg!(target_os = "linux") {
            live_linux(&iface, &mut sink, &stop)
        } else {
            live_external(&iface, &mut sink, &stop, &child_slot)
        };
        sink.flush();
        let mut s = lock(&state);
        s.running = false;
        if let Err(e) = res {
            s.error = Some(e);
        }
        ctx.request_repaint();
    });
}

pub fn open_file(path: String, state: Shared<CaptureState>, ids: Shared<Ids>, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        s.reset(tf("Archivo · {}", &[&(path)]));
        s.running = true;
    }
    thread::spawn(move || {
        let stop = AtomicBool::new(false);
        let mut sink = Sink { state: state.clone(), ids, ctx: ctx.clone(), buf: Vec::new(), last: Instant::now(), count: 0 };
        let res = std::fs::File::open(path.trim())
            .map_err(|e| tf("No se pudo abrir el archivo: {}", &[&(e)]))
            .and_then(|f| read_pcap_stream(BufReader::new(f), &mut sink, &stop));
        let mut s = lock(&state);
        s.running = false;
        if let Err(e) = res {
            s.error = Some(e);
        }
        ctx.request_repaint();
    });
}

pub fn save_pcap(path: &str, packets: &[Packet]) -> Result<usize, String> {
    let mut f = std::io::BufWriter::new(std::fs::File::create(path.trim()).map_err(|e| e.to_string())?);
    let mut h = Vec::new();
    h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&[0u8; 8]);
    h.extend_from_slice(&262144u32.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    f.write_all(&h).map_err(|e| e.to_string())?;
    for p in packets {
        let mut r = Vec::with_capacity(16);
        r.extend_from_slice(&(p.ts as u32).to_le_bytes());
        r.extend_from_slice(&((p.ts.fract() * 1e6) as u32).to_le_bytes());
        r.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        r.extend_from_slice(&p.orig_len.max(p.data.len() as u32).to_le_bytes());
        f.write_all(&r).map_err(|e| e.to_string())?;
        f.write_all(&p.data).map_err(|e| e.to_string())?;
    }
    f.flush().map_err(|e| e.to_string())?;
    Ok(packets.len())
}

fn live_external(iface: &str, sink: &mut Sink, stop: &AtomicBool, slot: &Arc<Mutex<Option<Child>>>) -> Result<(), String> {
    let (prog, args): (String, Vec<String>) = if cfg!(windows) {
        let n = iface.split('.').next().unwrap_or("1").trim().to_string();
        (dumpcap_path(), vec!["-i".into(), if n.is_empty() { "1".into() } else { n }, "-F".into(), "pcap".into(), "-q".into(), "-w".into(), "-".into()])
    } else {
        let mut a = vec!["-U".to_string(), "-s".into(), "0".into(), "-w".into(), "-".into()];
        if !iface.is_empty() {
            a.insert(0, iface.to_string());
            a.insert(0, "-i".into());
        }
        ("tcpdump".into(), a)
    };
    let mut child = command(&prog)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            if cfg!(windows) {
                tr("Para capturar en Windows instala Wireshark (incluye Npcap y dumpcap) y vuelve a intentarlo.").to_string()
            } else {
                tr("No se encontró «tcpdump». Instálalo para capturar paquetes.").to_string()
            }
        })?;
    let out = child.stdout.take().ok_or("Sin salida")?;
    let mut err = child.stderr.take();
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
    let res = read_pcap_stream(BufReader::new(out), sink, stop);
    let mut msg = String::new();
    if let Some(e) = err.as_mut() {
        let _ = e.read_to_string(&mut msg);
    }
    if let Some(mut c) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    if sink.count == 0 && !stop.load(Ordering::Relaxed) {
        let hint = if cfg!(windows) { tr("Ejecuta la app como administrador.") } else { tr("Ejecuta la app con sudo.") };
        return Err(tf("La captura no arrancó. {} {}", &[&(hint), &(msg.lines().last().unwrap_or(""))]));
    }
    if let Err(e) = res {
        if !stop.load(Ordering::Relaxed) && sink.count == 0 {
            return Err(e);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn live_linux(iface: &str, sink: &mut Sink, stop: &AtomicBool) -> Result<(), String> {
    use std::mem::{size_of, zeroed};
    unsafe {
        let proto = (libc::ETH_P_ALL as u16).to_be();
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto as i32);
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(tf("No hay permiso para capturar ({}). Ejecuta la app con sudo, o dale permiso una vez con: sudo setcap cap_net_raw,cap_net_admin=eip <ruta de la app>", &[&(e)]));
        }
        if !iface.is_empty() && iface != "any" {
            let cname = std::ffi::CString::new(iface).unwrap_or_default();
            let idx = libc::if_nametoindex(cname.as_ptr());
            if idx == 0 {
                libc::close(fd);
                return Err(tf("La interfaz «{}» no existe", &[&(iface)]));
            }
            let mut sll: libc::sockaddr_ll = zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = proto;
            sll.sll_ifindex = idx as i32;
            libc::bind(fd, &sll as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_ll>() as u32);
        }
        let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, size_of::<libc::timeval>() as u32);
        let mut buf = vec![0u8; 65536];
        let mut result = Ok(());
        while !stop.load(Ordering::Relaxed) {
            let mut sll: libc::sockaddr_ll = zeroed();
            let mut len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let n = libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_TRUNC, &mut sll as *mut _ as *mut libc::sockaddr, &mut len);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted => {
                        sink.flush();
                        continue;
                    }
                    _ => {
                        result = Err(e.to_string());
                        break;
                    }
                }
            }
            let orig = n as usize;
            let cap = orig.min(buf.len());
            let frame = &buf[..cap];
            let ht = sll.sll_hatype;
            let eth = if ht == 1 || ht == 772 { Some(frame.to_vec()) } else { to_ethernet(101, frame) };
            if let Some(f) = eth {
                sink.push(now_secs(), f, orig as u32);
            }
        }
        libc::close(fd);
        result
    }
}

#[cfg(not(target_os = "linux"))]
fn live_linux(_iface: &str, _sink: &mut Sink, _stop: &AtomicBool) -> Result<(), String> {
    Err("No disponible".into())
}
