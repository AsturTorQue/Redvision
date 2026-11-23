//! Ventana principal: navegación lateral y una página por herramienta.
use crate::i18n::{tr, tf};
use crate::capture::{self, CaptureCtl, CaptureState};
use crate::config;
use crate::dns::{self, DnsState};
use crate::ids::{Ids, Sev, RULES};
use crate::monitor::{self, MonitorState, Watched};
use crate::netscan::{self, Host, Kind, PortScan, SubnetScan};
use crate::packet;
use crate::ping::{self, LatencyState, Method, TraceState};
use crate::qoe::{self, QoeState};
use crate::security::{self, Audit};
use crate::util::*;
use crate::widgets::*;
use eframe::egui::{self, Align2, Color32, FontId, Pos2, RichText, Sense, Stroke, Ui, Vec2};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Tab {
    Dashboard,
    Network,
    Ports,
    Capture,
    Dpi,
    Latency,
    Qoe,
    Dns,
    Security,
    Ids,
    Monitor,
    Speed,
    LanAudit,
    Tools,
    Settings,
    Help,
}

const TABS: &[(Tab, &str, &str)] = &[
    (Tab::Dashboard, "🏠", "Panel"),
    (Tab::Network, "🌐", "Red y topología"),
    (Tab::Ports, "🔌", "Puertos"),
    (Tab::Capture, "📦", "Captura de paquetes"),
    (Tab::Dpi, "🔬", "Análisis profundo"),
    (Tab::Latency, "⏱", "Latencia y pérdida"),
    (Tab::Qoe, "⭐", "Calidad (QoE)"),
    (Tab::Dns, "🔎", "Análisis DNS"),
    (Tab::Security, "🛡", "Vulnerabilidades"),
    (Tab::Ids, "🚨", "Intrusos y anomalías"),
    (Tab::Monitor, "📈", "Monitorización"),
    (Tab::Speed, "⚡", "Velocidad entre equipos"),
    (Tab::LanAudit, "📋", "Diagnóstico de la LAN"),
    (Tab::Tools, "🔧", "Herramientas"),
    (Tab::Settings, "⚙", "Ajustes"),
    (Tab::Help, "📖", "Manual de uso"),
];

pub struct NetApp {
    pub(crate) tab: Tab,
    pub(crate) info: Shared<NetInfo>,
    pub(crate) ids: Shared<Ids>,
    pub(crate) monitor: Shared<MonitorState>,
    pub(crate) subnet: Shared<SubnetScan>,
    pub(crate) subnet_stop: Arc<AtomicBool>,
    pub(crate) selected_host: Option<Ipv4Addr>,
    pub(crate) map_view: bool,
    pub(crate) ports_sub: u8,
    pub(crate) conn_filter: String,
    pub(crate) conn_all: bool,
    pub(crate) portscan: Shared<PortScan>,
    pub(crate) ps_stop: Arc<AtomicBool>,
    pub(crate) ps_target: String,
    pub(crate) ps_spec: String,
    pub(crate) ps_timeout: u64,
    pub(crate) ps_banners: bool,
    pub(crate) ps_error: Option<String>,
    pub(crate) capture: Shared<CaptureState>,
    pub(crate) cap_ctl: CaptureCtl,
    pub(crate) cap_ifaces: Vec<String>,
    pub(crate) cap_iface: String,
    pub(crate) cap_file: String,
    pub(crate) cap_save: String,
    pub(crate) cap_filter: String,
    pub(crate) cap_selected: Option<u64>,
    pub(crate) cap_autoscroll: bool,
    pub(crate) cap_msg: Option<String>,
    pub(crate) cap_cache: (u64, usize, String, Vec<usize>),
    pub(crate) latency: Shared<LatencyState>,
    pub(crate) lat_stop: Arc<AtomicBool>,
    pub(crate) lat_target: String,
    pub(crate) lat_tcp: bool,
    pub(crate) lat_port: u16,
    pub(crate) lat_interval: u64,
    pub(crate) trace: Shared<TraceState>,
    pub(crate) trace_target: String,
    pub(crate) qoe: Shared<QoeState>,
    pub(crate) qoe_url: String,
    pub(crate) dns: Shared<DnsState>,
    pub(crate) dns_name: String,
    pub(crate) dns_type: u16,
    pub(crate) dns_server: usize,
    pub(crate) dns_custom: String,
    pub(crate) audit: Shared<Audit>,
    pub(crate) audit_stop: Arc<AtomicBool>,
    pub(crate) audit_target: String,
    pub(crate) ids_min: Sev,
    pub(crate) mon_iface: String,
    pub(crate) watch_input: String,
    pub(crate) screenshot: Option<PathBuf>,
    pub(crate) frames: u64,
    pub(crate) settings: config::Settings,
    pub(crate) saved: config::Settings,
    pub(crate) settings_msg: Option<String>,
    pub(crate) export_msg: Option<String>,
    pub(crate) wol_mac: String,
    pub(crate) wol_msg: Option<(bool, String)>,
    pub(crate) pubip: Shared<Option<Result<Vec<(&'static str, String)>, String>>>,
    pub(crate) pubip_running: Arc<AtomicBool>,
    pub(crate) subnet_input: String,
    pub(crate) mac_lookup: String,
    pub(crate) tx: crate::pages_extra::ToolsState,
    pub(crate) lan: crate::pages_lan::LanState,
    pub(crate) help_search: String,
    pub(crate) help_jump: Option<usize>,
}

impl NetApp {
    pub fn new(cc: &eframe::CreationContext<'_>, screenshot: Option<PathBuf>) -> Self {
        let settings = config::load();
        crate::i18n::set_lang(settings.lang);
        set_theme(settings.theme);
        cc.egui_ctx.set_zoom_factor(settings.zoom);
        apply_style(&cc.egui_ctx);
        let info = shared(NetInfo::default());
        let ids = shared(Ids::default());
        let monitor = shared(MonitorState::default());
        let subnet = shared(SubnetScan::default());
        {
            let (info, ids, ctx) = (info.clone(), ids.clone(), cc.egui_ctx.clone());
            std::thread::spawn(move || {
                let n = detect();
                lock(&ids).gateway = n.gateway;
                *lock(&info) = n;
                ctx.request_repaint();
            });
        }
        lock(&monitor).watched = settings.watched.iter().cloned().map(Watched::new).collect();
        monitor::start_monitor(monitor.clone(), info.clone(), ids.clone(), cc.egui_ctx.clone());
        if settings.scan_on_start && screenshot.is_none() {
            let (info, subnet, ids, ctx) = (info.clone(), subnet.clone(), ids.clone(), cc.egui_ctx.clone());
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let i = lock(&info).clone();
                    if i.ready {
                        netscan::start_subnet_scan(i, subnet, Arc::new(AtomicBool::new(false)), ids, ctx);
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            });
        }
        NetApp {
            tab: Self::initial_tab(),
            info,
            ids,
            monitor,
            subnet,
            subnet_stop: Arc::new(AtomicBool::new(false)),
            selected_host: None,
            map_view: true,
            ports_sub: 0,
            conn_filter: String::new(),
            conn_all: false,
            portscan: shared(PortScan::default()),
            ps_stop: Arc::new(AtomicBool::new(false)),
            ps_target: String::new(),
            ps_spec: "comunes".into(),
            ps_timeout: 400,
            ps_banners: true,
            ps_error: None,
            capture: shared(CaptureState::default()),
            cap_ctl: CaptureCtl::default(),
            cap_ifaces: capture::list_interfaces(),
            cap_iface: if cfg!(target_os = "linux") { "any".into() } else { String::new() },
            cap_file: String::new(),
            cap_save: default_save_path(),
            cap_filter: String::new(),
            cap_selected: None,
            cap_autoscroll: true,
            cap_msg: None,
            cap_cache: (0, 0, String::new(), Vec::new()),
            latency: shared(LatencyState::default()),
            lat_stop: Arc::new(AtomicBool::new(false)),
            lat_target: "1.1.1.1".into(),
            lat_tcp: false,
            lat_port: 443,
            lat_interval: 1000,
            trace: shared(TraceState::default()),
            trace_target: "1.1.1.1".into(),
            qoe: shared(QoeState::default()),
            qoe_url: "http://speedtest.tele2.net/100MB.zip".into(),
            dns: shared(DnsState::default()),
            dns_name: "example.com".into(),
            dns_type: 1,
            dns_server: 0,
            dns_custom: String::new(),
            audit: shared(Audit::default()),
            audit_stop: Arc::new(AtomicBool::new(false)),
            audit_target: String::new(),
            ids_min: Sev::Info,
            mon_iface: String::new(),
            watch_input: String::new(),
            screenshot,
            frames: 0,
            settings: settings.clone(),
            saved: settings,
            settings_msg: None,
            export_msg: None,
            wol_mac: String::new(),
            wol_msg: None,
            pubip: shared(None),
            pubip_running: Arc::new(AtomicBool::new(false)),
            subnet_input: String::new(),
            mac_lookup: String::new(),
            tx: Default::default(),
            lan: Default::default(),
            help_search: std::env::var("REDVISION_HELP_SEARCH").unwrap_or_default(),
            help_jump: None,
        }
    }

    /// Página inicial forzada con REDVISION_TAB (para las capturas de prueba).
    fn initial_tab() -> Tab {
        match std::env::var("REDVISION_TAB").unwrap_or_default().as_str() {
            "network" => Tab::Network,
            "ports" => Tab::Ports,
            "capture" => Tab::Capture,
            "latency" => Tab::Latency,
            "dns" => Tab::Dns,
            "security" => Tab::Security,
            "ids" => Tab::Ids,
            "monitor" => Tab::Monitor,
            "speed" => Tab::Speed,
            "lanaudit" => Tab::LanAudit,
            "tools" => Tab::Tools,
            "settings" => Tab::Settings,
            "help" => Tab::Help,
            _ => Tab::Dashboard,
        }
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some(path) = self.screenshot.clone() else { return };
        self.frames += 1;
        ctx.request_repaint();
        let shot = ctx.input(|i| {
            i.raw.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(img) = shot {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let [w, h] = img.size;
            if let Err(e) = image::save_buffer(&path, img.as_raw(), w as u32, h as u32, image::ExtendedColorType::Rgba8) {
                eprintln!("No se pudo guardar la captura: {}", e);
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if self.frames >= 120 && self.frames % 120 == 0 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
    }

    fn start_subnet(&mut self, ctx: &egui::Context) {
        let info = lock(&self.info).clone();
        if info.local_ip.is_some() && !lock(&self.subnet).running {
            netscan::start_subnet_scan(info, self.subnet.clone(), self.subnet_stop.clone(), self.ids.clone(), ctx.clone());
        }
    }

    fn start_portscan(&mut self, ctx: &egui::Context) {
        match netscan::parse_ports(&self.ps_spec) {
            Ok(ports) if !self.ps_target.trim().is_empty() => {
                self.ps_error = None;
                netscan::start_port_scan(self.ps_target.trim().to_string(), ports, self.ps_timeout, self.ps_banners, self.portscan.clone(), self.ps_stop.clone(), ctx.clone());
            }
            Ok(_) => self.ps_error = Some(tr("Escribe una IP o un nombre de equipo").into()),
            Err(e) => self.ps_error = Some(e),
        }
    }

    fn start_capture(&mut self, ctx: &egui::Context) {
        if lock(&self.capture).running {
            return;
        }
        self.cap_selected = None;
        self.cap_msg = None;
        capture::start_live(self.cap_iface.clone(), self.capture.clone(), self.ids.clone(), &self.cap_ctl, ctx.clone());
    }

    fn start_audit(&mut self, targets: Vec<String>, ctx: &egui::Context) {
        let gw = lock(&self.info).gateway;
        security::start_audit(targets, gw, self.audit.clone(), self.audit_stop.clone(), ctx.clone());
    }

    fn add_watch(&mut self, host: String) {
        let host = host.trim().to_string();
        if host.is_empty() {
            return;
        }
        let mut m = lock(&self.monitor);
        if !m.watched.iter().any(|w| w.host == host) {
            m.watched.push(Watched::new(host));
        }
    }

    fn start_latency(&mut self, ctx: &egui::Context) {
        self.lat_stop.store(true, Ordering::Relaxed);
        self.lat_stop = Arc::new(AtomicBool::new(false));
        let m = if self.lat_tcp { Method::Tcp(self.lat_port) } else { Method::Icmp };
        ping::start_latency(self.latency.clone(), self.lat_stop.clone(), self.lat_target.trim().to_string(), m, self.lat_interval, ctx.clone());
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::hover());
            let p = ui.painter();
            p.circle_filled(r.center(), 16.0, ACCENT_BG());
            p.circle_stroke(r.center(), 16.0, Stroke::new(2.0_f32, ACCENT()));
            for (dx, dy) in [(-7.0, 5.0), (7.0, 5.0), (0.0, -7.0)] {
                p.line_segment([r.center(), r.center() + Vec2::new(dx, dy)], Stroke::new(1.5_f32, ACCENT()));
                p.circle_filled(r.center() + Vec2::new(dx, dy), 3.0, ACCENT());
            }
            ui.vertical(|ui| {
                ui.label(RichText::new("RedVisión").size(19.0).strong().color(TEXT()));
                ui.label(RichText::new(tr("Analizador de red")).size(11.5).color(MUTED()));
            });
        });
        ui.add_space(14.0);
        let alerts_hi = {
            let ids = lock(&self.ids);
            ids.count(Sev::Critical) + ids.count(Sev::High)
        };
        let cap_running = lock(&self.capture).running;
        for (tab, icon, label) in TABS {
            let sel = self.tab == *tab;
            let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::click());
            let p = ui.painter();
            if sel {
                p.rect_filled(rect, 8.0, SEL());
                p.rect_filled(egui::Rect::from_min_size(rect.min + Vec2::new(0.0, 7.0), Vec2::new(3.0, 20.0)), 2.0, ACCENT());
            } else if resp.hovered() {
                p.rect_filled(rect, 8.0, HOVER());
            }
            let col = if sel { TEXT() } else { SUBTLE() };
            p.text(rect.left_center() + Vec2::new(14.0, 0.0), Align2::LEFT_CENTER, *icon, FontId::proportional(15.0), if sel { ACCENT() } else { MUTED() });
            p.text(rect.left_center() + Vec2::new(40.0, 0.0), Align2::LEFT_CENTER, tr(label), FontId::proportional(14.0), col);
            if *tab == Tab::Ids && alerts_hi > 0 {
                let c = rect.right_center() - Vec2::new(18.0, 0.0);
                p.circle_filled(c, 10.0, RED());
                p.text(c, Align2::CENTER_CENTER, alerts_hi.min(99).to_string(), FontId::proportional(11.0), Color32::WHITE);
            }
            if *tab == Tab::Capture && cap_running {
                p.circle_filled(rect.right_center() - Vec2::new(18.0, 0.0), 5.0, RED());
            }
            if resp.clicked() {
                self.export_msg = None;
                self.tab = *tab;
            }
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(10.0);
            let info = lock(&self.info).clone();
            if info.admin {
                ui.label(RichText::new(tr("Permisos de administrador")).color(GREEN()).size(12.0));
            } else {
                ui.label(RichText::new(tr("Sin permisos de administrador")).color(AMBER()).size(12.0));
            }
            ui.label(RichText::new(format!("{} · {}", info.os, info.hostname)).color(MUTED()).size(12.0));
            ui.label(RichText::new(info.local_ip.map(|i| format!("IP {}", i)).unwrap_or(tr("Detectando red…").into())).color(MUTED()).size(12.0));
            ui.separator();
        });
    }
}

impl eframe::App for NetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_screenshot(ctx);
        self.settings.watched = lock(&self.monitor).watched.iter().map(|w| w.host.clone()).collect();
        if self.settings != self.saved && self.screenshot.is_none() {
            self.settings_msg = Some(match config::save(&self.settings) {
                Ok(()) => tf("Ajustes guardados en {}", &[&config::path().display()]),
                Err(e) => tf("No se pudo guardar: {}", &[&e]),
            });
            self.saved = self.settings.clone();
        }
        egui::SidePanel::left("nav")
            .exact_width(226.0)
            .resizable(false)
            .frame(egui::Frame::new().fill(BG()).inner_margin(egui::Margin::symmetric(10, 4)))
            .show(ctx, |ui| self.sidebar(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(PANEL()).inner_margin(egui::Margin::symmetric(22, 14)))
            .show(ctx, |ui| {
                if self.tab == Tab::Capture {
                    self.page_capture(ui, ctx);
                    return;
                }
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match self.tab {
                    Tab::Dashboard => self.page_dashboard(ui, ctx),
                    Tab::Network => self.page_network(ui, ctx),
                    Tab::Ports => self.page_ports(ui, ctx),
                    Tab::Dpi => self.page_dpi(ui, ctx),
                    Tab::Latency => self.page_latency(ui, ctx),
                    Tab::Qoe => self.page_qoe(ui, ctx),
                    Tab::Dns => self.page_dns(ui, ctx),
                    Tab::Security => self.page_security(ui, ctx),
                    Tab::Ids => self.page_ids(ui, ctx),
                    Tab::Monitor => self.page_monitor(ui),
                    Tab::Speed => self.page_speed(ui),
                    Tab::LanAudit => self.page_lanaudit(ui),
                    Tab::Tools => self.page_tools(ui),
                    Tab::Help => self.page_help(ui),
                    Tab::Settings => self.page_settings(ui, ctx),
                    Tab::Capture => {}
                });
            });
    }
}

fn default_save_path() -> String {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("captura-redvision.pcap").to_string_lossy().to_string()
}

fn kind_color(k: Kind) -> Color32 {
    match k {
        Kind::Router => ACCENT(),
        Kind::ThisPc => GREEN(),
        Kind::Computer => BLUE(),
        Kind::Phone => VIOLET(),
        Kind::Printer => AMBER(),
        Kind::Server => ORANGE(),
        Kind::Media => Color32::from_rgb(244, 114, 182),
        Kind::Iot => Color32::from_rgb(45, 212, 191),
        Kind::Unknown => MUTED(),
    }
}

fn ms(v: Option<f64>) -> String {
    v.map(|x| format!("{:.1} ms", x)).unwrap_or_else(|| "—".into())
}

fn ago(ts: f64) -> String {
    let d = (now_secs() - ts).max(0.0);
    if d < 60.0 {
        tf("hace {:.0} s", &[&(d)])
    } else if d < 3600.0 {
        tf("hace {:.0} min", &[&(d / 60.0)])
    } else {
        tf("hace {:.0} h", &[&(d / 3600.0)])
    }
}

fn progress(ui: &mut Ui, done: usize, total: usize, text: &str) {
    let f = if total > 0 { done as f32 / total as f32 } else { 0.0 };
    ui.add(egui::ProgressBar::new(f).text(format!("{} {}/{}", text, done, total)).fill(ACCENT_DIM()));
}

/// Dibuja el mapa de la red: Internet arriba, el router en el centro y los equipos alrededor.
fn draw_map(ui: &mut Ui, hosts: &[Host], gw: Option<Ipv4Addr>, local: Option<Ipv4Addr>, selected: Option<Ipv4Addr>, height: f32) -> Option<Ipv4Addr> {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::click());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 10.0, CHART_BG());
    let mut y = rect.top() + 20.0;
    while y < rect.bottom() {
        let mut x = rect.left() + 20.0;
        while x < rect.right() {
            p.circle_filled(Pos2::new(x, y), 0.8, GRID());
            x += 28.0;
        }
        y += 28.0;
    }
    let center = rect.center() + Vec2::new(0.0, 24.0);
    let inet = Pos2::new(center.x, rect.top() + 36.0);
    let mut nodes: Vec<(Ipv4Addr, Pos2, Kind, String)> = Vec::new();
    let router_ip = gw.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let router_label = hosts
        .iter()
        .find(|h| h.ip == router_ip)
        .map(|h| if h.name.is_empty() { h.ip.to_string() } else { h.name.clone() })
        .unwrap_or(router_ip.to_string());
    let mut others: Vec<&Host> = hosts.iter().filter(|h| h.ip != router_ip).collect();
    let fake_self;
    if others.is_empty() {
        if let Some(l) = local {
            fake_self = Host { ip: l, mac: String::new(), vendor: String::new(), name: tr("Este equipo").into(), rtt: None, ports: vec![], kind: Kind::ThisPc };
            others.push(&fake_self);
        }
    }
    let aspect = (rect.width() / rect.height()).clamp(1.0, 2.4);
    let max_r = rect.height() / 2.0 - 36.0;
    let mut idx = 0;
    let mut ring = 0;
    while idx < others.len() {
        let r = (95.0 + 70.0 * ring as f32).min(max_r);
        let cap = ((2.0 * std::f32::consts::PI * r * aspect.sqrt()) / 64.0).floor().max(6.0) as usize;
        let count = cap.min(others.len() - idx);
        for k in 0..count {
            let a = std::f32::consts::PI * 0.5 + 2.0 * std::f32::consts::PI * (k as f32 + 0.5 * (ring % 2) as f32) / count as f32;
            let pos = center + Vec2::new(r * aspect * a.cos(), r * a.sin());
            let h = others[idx + k];
            let label = if !h.name.is_empty() { h.name.split('.').next().unwrap_or("").to_string() } else { format!(".{}", h.ip.octets()[3]) };
            nodes.push((h.ip, pos, h.kind, label));
        }
        idx += count;
        ring += 1;
    }
    p.line_segment([inet, center], Stroke::new(2.5_f32, ACCENT().gamma_multiply(0.7)));
    for (_, pos, k, _) in &nodes {
        p.line_segment([center, *pos], Stroke::new(1.2_f32, kind_color(*k).gamma_multiply(0.35)));
    }
    for (dx, dy, r) in [(-14.0, 4.0, 13.0), (12.0, 4.0, 14.0), (0.0, -6.0, 16.0)] {
        p.circle_filled(inet + Vec2::new(dx, dy), r, HOVER());
    }
    p.text(inet + Vec2::new(0.0, 2.0), Align2::CENTER_CENTER, "Internet", FontId::proportional(11.5), TEXT());
    p.circle_filled(center, 24.0, ACCENT_BG());
    p.circle_stroke(center, 24.0, Stroke::new(2.5_f32, ACCENT()));
    p.text(center, Align2::CENTER_CENTER, "R", FontId::proportional(17.0), ACCENT());
    p.text(center + Vec2::new(0.0, 34.0), Align2::CENTER_CENTER, tf("Router {}", &[&(router_label)]), FontId::proportional(12.0), TEXT());
    let hover = resp.hover_pos();
    let mut hovered: Option<(Ipv4Addr, Pos2)> = None;
    for (ip, pos, k, label) in &nodes {
        let col = kind_color(*k);
        let is_sel = Some(*ip) == selected;
        let hov = hover.is_some_and(|h| h.distance(*pos) < 18.0);
        if hov {
            hovered = Some((*ip, *pos));
        }
        let r = if is_sel || hov { 17.0 } else { 15.0 };
        p.circle_filled(*pos, r, col.gamma_multiply(0.22));
        p.circle_stroke(*pos, r, Stroke::new(if is_sel { 3.0_f32 } else { 1.6 }, col));
        p.text(*pos, Align2::CENTER_CENTER, k.icon(), FontId::proportional(11.0), col);
        p.text(*pos + Vec2::new(0.0, 25.0), Align2::CENTER_CENTER, label, FontId::proportional(11.0), SUBTLE());
    }
    if let Some((ip, pos)) = hovered {
        if let Some(h) = hosts.iter().find(|h| h.ip == ip) {
            let txt = tf("{}  {}\n{}{}\nLatencia {}", &[&(h.ip), &(h.kind.label()), &(h.mac), &(if h.vendor.is_empty() { String::new() } else { format!(" · {}", h.vendor) }), &(ms(h.rtt))]);
            let gal = ui.painter().layout_no_wrap(txt, FontId::proportional(12.0), TEXT());
            let r = egui::Rect::from_min_size(pos + Vec2::new(20.0, -20.0), gal.size() + Vec2::splat(12.0));
            p.rect_filled(r, 6.0, CARD2());
            p.rect_stroke(r, 6.0, Stroke::new(1.0_f32, BORDER()), egui::StrokeKind::Inside);
            p.galley(r.min + Vec2::splat(6.0), gal, TEXT());
        }
    }
    let mut lx = rect.left() + 14.0;
    for k in [Kind::Router, Kind::ThisPc, Kind::Computer, Kind::Phone, Kind::Server, Kind::Printer, Kind::Media, Kind::Iot, Kind::Unknown] {
        let pos = Pos2::new(lx, rect.bottom() - 16.0);
        p.circle_filled(pos, 5.0, kind_color(k));
        let g = p.text(pos + Vec2::new(9.0, 0.0), Align2::LEFT_CENTER, k.label(), FontId::proportional(11.0), MUTED());
        lx = g.right() + 16.0;
    }
    if resp.clicked() {
        if let Some((ip, _)) = hovered {
            return Some(ip);
        }
    }
    None
}

impl NetApp {
    fn page_dashboard(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Panel de red"), tr("Resumen en tiempo real de tu red, su calidad y su seguridad"));
        let info = lock(&self.info).clone();
        let (gw_lat, rates, hist): (Vec<Option<f64>>, (f64, f64), Vec<(f64, f64)>) = {
            let m = lock(&self.monitor);
            (m.gw_latency.iter().cloned().collect(), m.total_rates(), m.total_hist())
        };
        let gw_stats = ping::stats(&gw_lat[gw_lat.len().saturating_sub(20)..]);
        let (n_hosts, scanned, scanning, scan_started) = {
            let s = lock(&self.subnet);
            (s.hosts.len(), s.scans > 0, s.running, s.started)
        };
        let (n_alerts, n_hi, recent): (usize, usize, Vec<crate::ids::Alert>) = {
            let i = lock(&self.ids);
            (i.alerts.len(), i.count(Sev::Critical) + i.count(Sev::High), i.alerts.iter().rev().take(6).cloned().collect())
        };
        ui.columns(4, |c| {
            stat(
                &mut c[0],
                tr("Este equipo"),
                &info.local_ip.map(|i| format!("{}/{}", i, info.prefix)).unwrap_or("…".into()),
                TEXT(),
                &format!("{} · {}", info.hostname, if info.iface.is_empty() { tr("interfaz") } else { &info.iface }),
            );
            stat(
                &mut c[1],
                tr("Puerta de enlace"),
                &info.gateway.map(|g| g.to_string()).unwrap_or("…".into()),
                ACCENT(),
                &if gw_stats.recv > 0 { tf("{:.1} ms · pérdida {:.0}%", &[&(gw_stats.avg), &(gw_stats.loss)]) } else { tr("midiendo latencia…").to_string() },
            );
            stat(
                &mut c[2],
                tr("Dispositivos en la red"),
                &if scanned || scanning { n_hosts.to_string() } else { "—".into() },
                GREEN(),
                &if scanning { tr("escaneando…").to_string() } else if scanned { tf("escaneado {}", &[&(ago(scan_started))]) } else { tr("pulsa «Escanear la red»").into() },
            );
            stat(
                &mut c[3],
                tr("Alertas de seguridad"),
                &n_alerts.to_string(),
                if n_hi > 0 { RED() } else { GREEN() },
                &if n_hi > 0 { tf("{} altas o críticas", &[&(n_hi)]) } else { tr("sin alertas graves").into() },
            );
        });
        ui.add_space(8.0);
        ui.columns(2, |c| {
            card(&mut c[0], tr("Tráfico de la red"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("⬇ {}", fmt_bps(rates.0))).color(ACCENT()).strong());
                    ui.label(RichText::new(format!("⬆ {}", fmt_bps(rates.1))).color(VIOLET()).strong());
                    muted(ui, tr("últimos 2 minutos"));
                });
                let rx: Vec<Option<f64>> = hist.iter().map(|v| Some(v.0 * 8.0)).collect();
                let tx: Vec<Option<f64>> = hist.iter().map(|v| Some(v.1 * 8.0)).collect();
                line_chart(ui, 170.0, &[Series { values: &rx, color: ACCENT(), fill: true }, Series { values: &tx, color: VIOLET(), fill: true }], &|v| fmt_bps(v / 8.0), 8000.0);
            });
            card(&mut c[1], tr("Latencia hasta el router"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tf("media {}", &[&(ms(if gw_stats.recv > 0 { Some(gw_stats.avg) } else { None }))])).color(GREEN()).strong());
                    ui.label(RichText::new(tf("jitter {:.1} ms", &[&(gw_stats.jitter)])).color(AMBER()));
                    ui.label(RichText::new(tf("pérdida {:.0}%", &[&(gw_stats.loss)])).color(if gw_stats.loss > 0.0 { RED() } else { MUTED() }));
                });
                line_chart(ui, 170.0, &[Series { values: &gw_lat, color: GREEN(), fill: true }], &|v| format!("{:.0} ms", v), 5.0);
            });
        });
        ui.add_space(8.0);
        let audit_score = lock(&self.audit).score;
        let qoe_score = lock(&self.qoe).result.as_ref().map(|r| r.overall);
        ui.columns(3, |c| {
            card(&mut c[0], tr("Seguridad"), |ui| {
                ui.horizontal(|ui| {
                    gauge(ui, audit_score.map(|s| s as f64), tr("puntuación"), 110.0);
                    ui.vertical(|ui| {
                        ui.add_space(14.0);
                        muted(ui, if audit_score.is_some() { tr("Resultado de la última auditoría.") } else { tr("Aún no has auditado tu red.") });
                        if primary(ui, tr("Auditar mi red")).clicked() {
                            self.tab = Tab::Security;
                        }
                    });
                });
            });
            card(&mut c[1], tr("Calidad de la conexión"), |ui| {
                ui.horizontal(|ui| {
                    gauge(ui, qoe_score, "QoE", 110.0);
                    ui.vertical(|ui| {
                        ui.add_space(14.0);
                        muted(ui, qoe_score.map(|s| tf("Experiencia {}", &[&(qoe::verdict(s).to_lowercase())])).unwrap_or(tr("Mide voz, vídeo, juegos y web.").into()));
                        if primary(ui, tr("Medir calidad")).clicked() {
                            self.tab = Tab::Qoe;
                        }
                    });
                });
            });
            card(&mut c[2], tr("Alertas recientes"), |ui| {
                if recent.is_empty() {
                    muted(ui, tr("Sin alertas. El vigilante revisa la tabla ARP, los equipos vigilados y el tráfico capturado."));
                }
                for a in &recent {
                    ui.horizontal(|ui| {
                        badge(ui, a.sev.label(), sev_color(a.sev));
                        ui.add(egui::Label::new(RichText::new(format!("{} · {}", a.cat, a.src)).size(12.5)).truncate());
                    });
                }
            });
        });
        ui.add_space(8.0);
        card(ui, tr("Acciones rápidas"), |ui| {
            ui.horizontal_wrapped(|ui| {
                if primary(ui, tr("🌐 Escanear la red")).clicked() {
                    self.start_subnet(ctx);
                    self.tab = Tab::Network;
                }
                if ui.button(tr("📦 Capturar paquetes")).clicked() {
                    self.tab = Tab::Capture;
                }
                if ui.button(tr("⏱ Probar latencia")).clicked() {
                    self.start_latency(ctx);
                    self.tab = Tab::Latency;
                }
                if ui.button(tr("🔎 Analizar DNS")).clicked() {
                    self.tab = Tab::Dns;
                }
                if ui.button(tr("🔌 Ver puertos abiertos")).clicked() {
                    self.tab = Tab::Ports;
                }
                if ui.button(tr("🔧 Herramientas")).clicked() {
                    self.tab = Tab::Tools;
                }
            });
        });
    }

    fn page_network(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Red y topología"), tr("Descubre los equipos activos de tu subred y cómo se conectan"));
        let info = lock(&self.info).clone();
        let (hosts, running, done, total, elapsed, scans) = {
            let s = lock(&self.subnet);
            (s.hosts.clone(), s.running, s.done, s.total, s.elapsed, s.scans)
        };
        ui.horizontal(|ui| {
            if running {
                if danger(ui, tr("Detener")).clicked() {
                    self.subnet_stop.store(true, Ordering::Relaxed);
                }
            } else if primary(ui, &tf("Escanear la red {}", &[&(info.network_label())])).clicked() {
                self.start_subnet(ctx);
            }
            ui.separator();
            ui.selectable_value(&mut self.map_view, true, tr("Mapa"));
            ui.selectable_value(&mut self.map_view, false, tr("Lista"));
            if !hosts.is_empty() && ui.button(format!("⬇ {}", tr("Exportar CSV"))).clicked() {
                let rows = hosts
                    .iter()
                    .map(|h| {
                        vec![
                            h.ip.to_string(),
                            h.name.clone(),
                            h.mac.clone(),
                            h.vendor.clone(),
                            h.kind.label().to_string(),
                            h.rtt.map(|r| format!("{:.1}", r)).unwrap_or_default(),
                            h.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" "),
                        ]
                    })
                    .collect();
                self.export("equipos", &["IP", "Nombre", "MAC", "Fabricante", "Tipo", "Latencia", "Puertos abiertos"], rows);
            }
            ui.separator();
            if running {
                progress(ui, done, total, tr("Comprobando direcciones"));
            } else if scans > 0 {
                muted(ui, tf("{} equipos encontrados en {:.0} s", &[&(hosts.len()), &(elapsed)]));
            } else {
                muted(ui, tr("Usa ping y conexiones TCP; no necesita permisos especiales."));
            }
        });
        self.export_notice(ui);
        ui.add_space(6.0);
        if self.map_view {
            if let Some(ip) = draw_map(ui, &hosts, info.gateway, info.local_ip, self.selected_host, 470.0) {
                self.selected_host = Some(ip);
            }
        } else {
            card(ui, "", |ui| {
                let cols = [(130.0, "IP"), (190.0, tr("Nombre")), (150.0, "MAC"), (170.0, tr("Fabricante")), (120.0, tr("Tipo")), (90.0, tr("Latencia")), (200.0, tr("Puertos abiertos"))];
                table_header(ui, &cols);
                for (i, h) in hosts.iter().enumerate() {
                    let ports = h.ports.iter().map(|p| format!("{} {}", p, service_name(*p))).collect::<Vec<_>>().join(", ");
                    let row = [
                        (130.0, h.ip.to_string(), TEXT()),
                        (190.0, h.name.clone(), TEXT()),
                        (150.0, h.mac.clone(), MUTED()),
                        (170.0, h.vendor.clone(), MUTED()),
                        (120.0, h.kind.label().to_string(), kind_color(h.kind)),
                        (90.0, ms(h.rtt), GREEN()),
                        (200.0, ports, MUTED()),
                    ];
                    if table_row(ui, &row, self.selected_host == Some(h.ip), i % 2 == 1).clicked() {
                        self.selected_host = Some(h.ip);
                    }
                }
                if hosts.is_empty() {
                    muted(ui, tr("Todavía no hay equipos. Pulsa «Escanear la red»."));
                }
            });
        }
        ui.add_space(8.0);
        if let Some(h) = self.selected_host.and_then(|ip| hosts.iter().find(|h| h.ip == ip).cloned()) {
            card(ui, &format!("{} — {}", h.ip, h.kind.label()), |ui| {
                egui::Grid::new("hostinfo").num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
                    for (k, v) in [
                        (tr("Nombre"), if h.name.is_empty() { tr("(sin nombre)").into() } else { h.name.clone() }),
                        ("MAC", if h.mac.is_empty() { tr("(desconocida)").into() } else { h.mac.clone() }),
                        (tr("Fabricante (estimado)"), if h.vendor.is_empty() { "—".into() } else { h.vendor.clone() }),
                        (tr("Latencia"), ms(h.rtt)),
                        (
                            tr("Puertos detectados"),
                            if h.ports.is_empty() { tr("ninguno de los comprobados").into() } else { h.ports.iter().map(|p| format!("{} ({})", p, service_name(*p))).collect::<Vec<_>>().join(", ") },
                        ),
                    ] {
                        ui.label(RichText::new(k).color(MUTED()));
                        ui.label(v);
                        ui.end_row();
                    }
                });
                ui.horizontal(|ui| {
                    if primary(ui, tr("Escanear todos sus puertos")).clicked() {
                        self.ps_target = h.ip.to_string();
                        self.ports_sub = 1;
                        self.start_portscan(ctx);
                        self.tab = Tab::Ports;
                    }
                    if ui.button(tr("Auditar seguridad")).clicked() {
                        self.audit_target = h.ip.to_string();
                        self.start_audit(vec![h.ip.to_string()], ctx);
                        self.tab = Tab::Security;
                    }
                    if ui.button(tr("Medir latencia")).clicked() {
                        self.lat_target = h.ip.to_string();
                        self.start_latency(ctx);
                        self.tab = Tab::Latency;
                    }
                    if ui.button(tr("Vigilar")).clicked() {
                        self.add_watch(h.ip.to_string());
                    }
                    if !h.mac.is_empty() && ui.button(tr("Despertar (Wake-on-LAN)")).clicked() {
                        self.wol_mac = h.mac.clone();
                        self.send_wol();
                    }
                });
            });
        } else if !hosts.is_empty() {
            muted(ui, tr("Pulsa un equipo del mapa para ver sus detalles."));
        }
    }

    fn page_ports(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Puertos"), tr("Qué escucha este equipo y qué servicios ofrecen otros"));
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.ports_sub, 0, tr("Este equipo"));
            ui.selectable_value(&mut self.ports_sub, 1, tr("Escáner de puertos"));
        });
        ui.add_space(6.0);
        if self.ports_sub == 0 {
            let (conns, t) = {
                let m = lock(&self.monitor);
                (m.conns.clone(), m.conns_time)
            };
            let listening = conns.iter().filter(|c| c.listening()).count();
            let established = conns.iter().filter(|c| c.state == "ESTABLECIDA").count();
            ui.columns(3, |c| {
                stat(&mut c[0], tr("Puertos a la escucha"), &listening.to_string(), ACCENT(), tr("servicios que aceptan conexiones"));
                stat(&mut c[1], tr("Conexiones establecidas"), &established.to_string(), GREEN(), tr("comunicaciones activas"));
                stat(&mut c[2], tr("Total de sockets"), &conns.len().to_string(), TEXT(), &if t > 0.0 { tf("actualizado {}", &[&(ago(t))]) } else { tr("leyendo…").into() });
            });
            ui.add_space(6.0);
            card(ui, "", |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr("Filtrar:"));
                    ui.add(egui::TextEdit::singleline(&mut self.conn_filter).hint_text("puerto, IP, programa…").desired_width(240.0));
                    ui.checkbox(&mut self.conn_all, tr("Mostrar también las conexiones (no solo los puertos a la escucha)"));
                    if ui.button(format!("⬇ {}", tr("Exportar CSV"))).clicked() {
                        let rows = conns
                            .iter()
                            .map(|c| vec![c.proto.clone(), c.local.clone(), c.lport.to_string(), c.remote.clone(), c.rport.to_string(), c.state.clone(), c.process.clone()])
                            .collect();
                        self.export("conexiones", &["Protocolo", "Dirección local", "Puerto", "Remoto", "Puerto", "Estado", "Programa"], rows);
                    }
                });
                self.export_notice(ui);
                ui.add_space(4.0);
                let f = self.conn_filter.to_lowercase();
                let mut rows: Vec<_> = conns
                    .iter()
                    .filter(|c| self.conn_all || c.listening())
                    .filter(|c| f.is_empty() || format!("{} {} {} {} {} {}", c.proto, c.local, c.lport, c.remote, c.rport, c.process).to_lowercase().contains(&f))
                    .collect();
                rows.sort_by_key(|c| (!c.listening(), c.lport));
                let cols = [(80.0, tr("Protocolo")), (230.0, tr("Dirección local")), (80.0, tr("Puerto")), (120.0, tr("Servicio")), (230.0, tr("Remoto")), (130.0, tr("Estado")), (200.0, tr("Programa"))];
                table_header(ui, &cols);
                for (i, c) in rows.iter().take(800).enumerate() {
                    let exposed = c.listening() && (c.local == "0.0.0.0" || c.local == "::" || c.local == "*");
                    let prog = match (&c.pid, c.process.is_empty()) {
                        (Some(p), false) => format!("{} ({})", c.process, p),
                        (Some(p), true) => tf("PID {}", &[&(p)]),
                        _ => "—".into(),
                    };
                    let row = [
                        (80.0, c.proto.clone(), MUTED()),
                        (230.0, c.local.clone(), if exposed { AMBER() } else { TEXT() }),
                        (80.0, c.lport.to_string(), TEXT()),
                        (120.0, service_name(c.lport).to_string(), ACCENT()),
                        (230.0, if c.listening() { "—".into() } else { format!("{}:{}", c.remote, c.rport) }, MUTED()),
                        (130.0, c.state.clone(), if c.listening() { GREEN() } else { TEXT() }),
                        (200.0, prog, MUTED()),
                    ];
                    table_row(ui, &row, false, i % 2 == 1);
                }
                ui.add_space(4.0);
                muted(ui, tr("En ámbar: puertos abiertos a toda la red (0.0.0.0). El nombre del programa solo aparece para procesos propios o con permisos de administrador."));
            });
            return;
        }
        let (ps_running, done, total, open, closed, filtered, err, elapsed, ip) = {
            let s = lock(&self.portscan);
            (s.running, s.done, s.total, s.open.clone(), s.closed, s.filtered, s.error.clone(), s.elapsed, s.ip)
        };
        card(ui, tr("Escáner de puertos TCP"), |ui| {
            ui.horizontal(|ui| {
                ui.label(tr("Equipo:"));
                ui.add(egui::TextEdit::singleline(&mut self.ps_target).hint_text("192.168.1.1 o nombre").desired_width(200.0));
                ui.label(tr("Puertos:"));
                ui.add(egui::TextEdit::singleline(&mut self.ps_spec).hint_text("comunes, 1-1024, 22,80,443, todos").desired_width(200.0));
                ui.label(tr("Espera (ms):"));
                ui.add(egui::DragValue::new(&mut self.ps_timeout).range(50..=5000));
                ui.checkbox(&mut self.ps_banners, tr("Leer banners"));
            });
            ui.horizontal(|ui| {
                if ps_running {
                    if danger(ui, tr("Detener")).clicked() {
                        self.ps_stop.store(true, Ordering::Relaxed);
                    }
                    progress(ui, done, total, tr("Puertos comprobados"));
                } else {
                    if primary(ui, tr("Escanear")).clicked() {
                        self.start_portscan(ctx);
                    }
                    for (label, v) in [(tr("Comunes"), "comunes"), ("1-1024", "1-1024"), (tr("Todos"), "todos")] {
                        if ui.small_button(label).clicked() {
                            self.ps_spec = v.into();
                        }
                    }
                    if total > 0 {
                        muted(ui, tf("{}: {} abiertos · {} cerrados · {} filtrados · {:.1} s", &[&(ip.map(|i| i.to_string()).unwrap_or_default()), &(open.len()), &(closed), &(filtered), &(elapsed)]));
                    }
                }
            });
            if let Some(e) = self.ps_error.clone().or(err) {
                notice(ui, &e, RED());
            }
        });
        ui.add_space(6.0);
        card(ui, tr("Puertos abiertos"), |ui| {
            let cols = [(80.0, tr("Puerto")), (130.0, tr("Servicio")), (90.0, tr("Respuesta")), (500.0, tr("Banner / versión"))];
            table_header(ui, &cols);
            for (i, o) in open.iter().enumerate() {
                let row = [
                    (80.0, o.port.to_string(), ACCENT()),
                    (130.0, if o.service.is_empty() { tr("desconocido").into() } else { o.service.clone() }, TEXT()),
                    (90.0, format!("{:.1} ms", o.rtt), GREEN()),
                    (500.0, o.banner.clone(), MUTED()),
                ];
                table_row(ui, &row, false, i % 2 == 1);
            }
            if open.is_empty() {
                muted(ui, if ps_running { tr("Buscando…") } else { tr("Sin resultados todavía.") });
            }
            ui.add_space(4.0);
            muted(ui, tr("Escanea solo equipos propios o con permiso de su dueño."));
        });
    }

    fn page_capture(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Captura de paquetes"), tr("Mira el tráfico paquete a paquete, guárdalo o abre capturas .pcap/.pcapng"));
        let info = lock(&self.info).clone();
        let (running, error, total, bytes, source) = {
            let s = lock(&self.capture);
            (s.running, s.error.clone(), s.total, s.bytes, s.source.clone())
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(tr("Interfaz:"));
            egui::ComboBox::from_id_salt("iface")
                .selected_text(if self.cap_iface.is_empty() { tr("predeterminada").to_string() } else { self.cap_iface.clone() })
                .width(190.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.cap_iface, String::new(), tr("predeterminada"));
                    for i in self.cap_ifaces.clone() {
                        ui.selectable_value(&mut self.cap_iface, i.clone(), i);
                    }
                });
            if ui.small_button("↻").on_hover_text("Volver a buscar interfaces").clicked() {
                self.cap_ifaces = capture::list_interfaces();
            }
            if running {
                if danger(ui, tr("Detener")).clicked() {
                    self.cap_ctl.stop();
                }
            } else if primary(ui, tr("Iniciar captura")).clicked() {
                self.start_capture(ctx);
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.cap_file).hint_text("ruta de un .pcap o .pcapng").desired_width(220.0));
            if ui.add_enabled(!running, egui::Button::new(tr("Abrir archivo"))).clicked() && !self.cap_file.trim().is_empty() {
                self.cap_selected = None;
                capture::open_file(self.cap_file.clone(), self.capture.clone(), self.ids.clone(), ctx.clone());
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.cap_save).desired_width(220.0));
            if ui.button(tr("Guardar .pcap")).clicked() {
                let r = capture::save_pcap(&self.cap_save, &lock(&self.capture).packets);
                self.cap_msg = Some(match r {
                    Ok(n) => tf("Guardados {} paquetes en {}", &[&(n), &(self.cap_save)]),
                    Err(e) => tf("No se pudo guardar: {}", &[&(e)]),
                });
            }
        });
        ui.horizontal(|ui| {
            ui.label(tr("Filtro:"));
            ui.add(egui::TextEdit::singleline(&mut self.cap_filter).hint_text("dns, tcp, 443, 192.168.1.10, google…").desired_width(300.0));
            ui.checkbox(&mut self.cap_autoscroll, tr("Seguir los últimos"));
            ui.separator();
            muted(ui, tf("{} · {} paquetes · {}", &[&(if source.is_empty() { tr("sin captura") } else { &source }), &(total), &(fmt_bytes(bytes as f64))]));
        });
        if !info.admin && !running && total == 0 {
            notice(
                ui,
                if cfg!(windows) {
                    tr("Para capturar en vivo hace falta Wireshark/Npcap instalado y abrir la app como administrador. Sin permisos puedes abrir archivos .pcap.")
                } else {
                    tr("Para capturar en vivo abre la app con sudo (o dale permiso una vez con setcap). Sin permisos puedes abrir archivos .pcap.")
                },
                AMBER(),
            );
        }
        if let Some(e) = error {
            notice(ui, &e, RED());
        }
        if let Some(m) = &self.cap_msg {
            notice(ui, m, GREEN());
        }
        ui.add_space(4.0);
        let st = lock(&self.capture);
        let first_no = st.packets.first().map(|p| p.no).unwrap_or(0);
        if self.cap_cache.0 != first_no || self.cap_cache.1 != st.packets.len() || self.cap_cache.2 != self.cap_filter {
            let toks: Vec<String> = self.cap_filter.to_lowercase().split_whitespace().map(String::from).collect();
            let idx: Vec<usize> = st
                .packets
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    toks.iter().all(|t| {
                        if let Ok(port) = t.parse::<u16>() {
                            p.s.sport == port || p.s.dport == port
                        } else {
                            p.s.proto.to_lowercase() == *t || format!("{} {} {} {}", p.s.proto, p.s.src, p.s.dst, p.s.info).to_lowercase().contains(t.as_str())
                        }
                    })
                })
                .map(|(i, _)| i)
                .collect();
            self.cap_cache = (first_no, st.packets.len(), self.cap_filter.clone(), idx);
        }
        let idx = &self.cap_cache.3;
        let list_h = (ui.available_height() * 0.52).max(160.0);
        let cols = [(70.0, "Nº"), (110.0, tr("Hora")), (250.0, tr("Origen")), (250.0, tr("Destino")), (85.0, tr("Protocolo")), (70.0, "Bytes"), (400.0, tr("Información"))];
        table_header(ui, &cols);
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("packets")
            .max_height(list_h)
            .auto_shrink([false, false])
            .stick_to_bottom(self.cap_autoscroll)
            .show_rows(ui, 22.0, idx.len(), |ui, range| {
                for r in range {
                    let p = &st.packets[idx[r]];
                    let row = [
                        (70.0, p.no.to_string(), MUTED()),
                        (110.0, fmt_clock_ms(p.ts), MUTED()),
                        (250.0, p.s.src.clone(), TEXT()),
                        (250.0, p.s.dst.clone(), TEXT()),
                        (85.0, p.s.proto.clone(), proto_color(&p.s.proto)),
                        (70.0, p.orig_len.to_string(), MUTED()),
                        (400.0, p.s.info.clone(), SUBTLE()),
                    ];
                    if table_row(ui, &row, self.cap_selected == Some(p.no), r % 2 == 1).clicked() {
                        clicked = Some(p.no);
                    }
                }
            });
        if idx.is_empty() {
            muted(ui, if total == 0 { tr("No hay paquetes. Inicia una captura o abre un archivo.") } else { tr("Ningún paquete coincide con el filtro.") });
        }
        let sel = self.cap_selected.and_then(|n| st.packets.iter().find(|p| p.no == n).cloned());
        drop(st);
        if let Some(c) = clicked {
            self.cap_selected = Some(c);
            self.cap_autoscroll = false;
        }
        ui.add_space(6.0);
        if let Some(p) = sel {
            let (_, layers) = packet::dissect(&p.data);
            ui.columns(2, |c| {
                egui::Frame::new().fill(CARD()).corner_radius(8.0).inner_margin(10.0).show(&mut c[0], |ui| {
                    ui.label(RichText::new(tf("Paquete {} · capas", &[&(p.no)])).strong());
                    egui::ScrollArea::vertical().id_salt("layers").auto_shrink([false, false]).show(ui, |ui| {
                        for (li, l) in layers.iter().enumerate() {
                            egui::CollapsingHeader::new(RichText::new(&l.name).color(ACCENT()).strong()).id_salt(("layer", li, p.no)).default_open(true).show(ui, |ui| {
                                egui::Grid::new(("lg", li, p.no)).num_columns(2).spacing([16.0, 2.0]).show(ui, |ui| {
                                    for (k, v) in &l.fields {
                                        ui.label(RichText::new(k).color(MUTED()).size(12.5));
                                        ui.label(RichText::new(v).size(12.5));
                                        ui.end_row();
                                    }
                                });
                            });
                        }
                    });
                });
                egui::Frame::new().fill(CARD()).corner_radius(8.0).inner_margin(10.0).show(&mut c[1], |ui| {
                    ui.label(RichText::new(tr("Bytes en hexadecimal")).strong());
                    egui::ScrollArea::vertical().id_salt("hex").auto_shrink([false, false]).show(ui, |ui| {
                        ui.label(RichText::new(packet::hexdump(&p.data, 4096)).monospace().size(12.0).color(SUBTLE()));
                    });
                });
            });
        } else if !idx.is_empty() {
            muted(ui, tr("Pulsa un paquete para ver sus capas y bytes."));
        }
    }

    fn page_dpi(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Análisis profundo de paquetes"), tr("Protocolos, quién habla con quién, sitios visitados y salud de TCP"));
        let st = lock(&self.capture);
        if st.total == 0 {
            drop(st);
            notice(ui, tr("Todavía no hay tráfico analizado. Inicia una captura (o abre un archivo .pcap) y vuelve aquí."), ACCENT());
            ui.add_space(6.0);
            if primary(ui, tr("Iniciar captura")).clicked() {
                self.start_capture(ctx);
                self.tab = Tab::Capture;
            }
            return;
        }
        let dur = (st.last - st.start).max(1.0);
        ui.columns(4, |c| {
            stat(&mut c[0], tr("Paquetes"), &st.total.to_string(), TEXT(), &tf("{:.0} por segundo", &[&(st.total as f64 / dur)]));
            stat(&mut c[1], tr("Datos"), &fmt_bytes(st.bytes as f64), ACCENT(), &tf("media {}", &[&(fmt_bps(st.bytes as f64 / dur))]));
            stat(&mut c[2], tr("Protocolos distintos"), &st.protos.len().to_string(), VIOLET(), tr("detectados por contenido y puerto"));
            stat(&mut c[3], tr("Conversaciones"), &st.convs.len().to_string(), GREEN(), &tf("{} equipos", &[&(st.talkers.len())]));
        });
        ui.add_space(8.0);
        let mut protos: Vec<_> = st.protos.iter().map(|(k, v)| (k.clone(), *v)).collect();
        protos.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        let per_sec: Vec<Option<f64>> = st.per_sec.iter().map(|x| Some(x.1 as f64 * 8.0)).collect();
        let total_bytes = st.bytes.max(1);
        ui.columns(2, |c| {
            card(&mut c[0], tr("Protocolos (por volumen)"), |ui| {
                for (name, (pk, by)) in protos.iter().take(12) {
                    bar(ui, name, &tf("{} · {} paq.", &[&(fmt_bytes(*by as f64)), &(pk)]), *by as f32 / total_bytes as f32, proto_color(name));
                }
            });
            card(&mut c[1], tr("Tráfico capturado por segundo"), |ui| {
                line_chart(ui, 210.0, &[Series { values: &per_sec, color: ACCENT(), fill: true }], &|v| fmt_bps(v / 8.0), 8000.0);
            });
        });
        ui.add_space(8.0);
        let mut talkers: Vec<_> = st.talkers.iter().map(|(k, v)| (k.clone(), *v)).collect();
        talkers.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)));
        let mut convs: Vec<_> = st.convs.iter().map(|(k, v)| (k.clone(), *v)).collect();
        convs.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        ui.columns(2, |c| {
            card(&mut c[0], tr("Equipos que más hablan"), |ui| {
                table_header(ui, &[(260.0, tr("Dirección")), (110.0, tr("Enviado")), (110.0, tr("Recibido"))]);
                for (i, (ip, (tx, rx))) in talkers.iter().take(12).enumerate() {
                    table_row(ui, &[(260.0, ip.clone(), TEXT()), (110.0, fmt_bytes(*tx as f64), VIOLET()), (110.0, fmt_bytes(*rx as f64), ACCENT())], false, i % 2 == 1);
                }
            });
            card(&mut c[1], tr("Conversaciones principales"), |ui| {
                table_header(ui, &[(190.0, tr("Equipo A")), (190.0, tr("Equipo B")), (70.0, "Proto"), (90.0, tr("Datos"))]);
                for (i, ((a, b, p), (_, by))) in convs.iter().take(12).enumerate() {
                    table_row(ui, &[(190.0, a.clone(), TEXT()), (190.0, b.clone(), TEXT()), (70.0, p.clone(), proto_color(p)), (90.0, fmt_bytes(*by as f64), MUTED())], false, i % 2 == 1);
                }
            });
        });
        ui.add_space(8.0);
        let mut dns_top: Vec<_> = st.dns.iter().map(|(k, v)| (k.clone(), *v)).collect();
        dns_top.sort_by(|a, b| b.1.cmp(&a.1));
        let mut sni: Vec<_> = st.sni.iter().map(|(k, v)| (k.clone(), *v)).collect();
        sni.sort_by(|a, b| b.1.cmp(&a.1));
        let (syn, synack, rst) = (st.syn, st.synack, st.rst);
        let http: Vec<_> = st.http.iter().rev().take(12).cloned().collect();
        let dhcp: Vec<_> = st.dhcp.iter().rev().take(8).cloned().collect();
        drop(st);
        ui.columns(2, |c| {
            card(&mut c[0], tr("Nombres consultados por DNS"), |ui| {
                if dns_top.is_empty() {
                    muted(ui, tr("Sin consultas DNS en la captura."));
                }
                for (n, k) in dns_top.iter().take(14) {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:>4}", k)).monospace().color(ACCENT()));
                        ui.add(egui::Label::new(n.as_str()).truncate());
                    });
                }
            });
            card(&mut c[1], tr("Sitios cifrados (TLS · nombre del servidor)"), |ui| {
                if sni.is_empty() {
                    muted(ui, tr("Sin conexiones TLS nuevas en la captura."));
                }
                for (n, k) in sni.iter().take(14) {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:>4}", k)).monospace().color(VIOLET()));
                        ui.add(egui::Label::new(n.as_str()).truncate());
                    });
                }
            });
        });
        ui.add_space(8.0);
        let ratio = if syn > 0 { synack as f64 / syn as f64 } else { 1.0 };
        ui.columns(2, |c| {
            card(&mut c[0], tr("Salud de las conexiones TCP"), |ui| {
                egui::Grid::new("tcph").num_columns(2).show(ui, |ui| {
                    ui.label(tr("Intentos de conexión (SYN)"));
                    ui.label(syn.to_string());
                    ui.end_row();
                    ui.label(tr("Aceptadas (SYN-ACK)"));
                    ui.label(synack.to_string());
                    ui.end_row();
                    ui.label(tr("Reinicios (RST)"));
                    ui.label(rst.to_string());
                    ui.end_row();
                });
                if syn > 20 && ratio < 0.5 {
                    notice(ui, tr("Muchas conexiones sin respuesta: puede haber un escaneo, un cortafuegos bloqueando o un servicio caído."), AMBER());
                } else {
                    muted(ui, tr("Las conexiones se establecen con normalidad."));
                }
            });
            card(&mut c[1], tr("Peticiones web sin cifrar (HTTP) y DHCP"), |ui| {
                if http.is_empty() && dhcp.is_empty() {
                    muted(ui, tr("Nada que mostrar."));
                }
                for (t, src, h) in &http {
                    ui.add(egui::Label::new(RichText::new(format!("{} {} → {}", fmt_clock(*t), src, h)).size(12.5)).truncate());
                }
                for (t, d) in &dhcp {
                    ui.add(egui::Label::new(RichText::new(format!("{} {}", fmt_clock(*t), d)).size(12.5).color(ORANGE())).truncate());
                }
            });
        });
    }

    fn page_latency(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Latencia y pérdida de paquetes"), tr("Mide el retardo, la variación (jitter) y los paquetes perdidos, y sigue la ruta"));
        let (running, samples, err, ip) = {
            let s = lock(&self.latency);
            (s.running, s.samples.clone(), s.error.clone(), s.ip)
        };
        let gw = lock(&self.info).gateway;
        card(ui, "", |ui| {
            ui.horizontal(|ui| {
                ui.label(tr("Destino:"));
                ui.add(egui::TextEdit::singleline(&mut self.lat_target).desired_width(200.0));
                ui.radio_value(&mut self.lat_tcp, false, tr("Ping (ICMP)"));
                ui.radio_value(&mut self.lat_tcp, true, tr("Conexión TCP al puerto"));
                if self.lat_tcp {
                    ui.add(egui::DragValue::new(&mut self.lat_port).range(1..=65535));
                }
                ui.label(tr("Cada"));
                ui.add(egui::DragValue::new(&mut self.lat_interval).range(200..=10000).suffix(" ms"));
                if running {
                    if danger(ui, tr("Detener")).clicked() {
                        self.lat_stop.store(true, Ordering::Relaxed);
                    }
                } else if primary(ui, tr("Iniciar")).clicked() {
                    self.start_latency(ctx);
                }
            });
            ui.horizontal(|ui| {
                muted(ui, tr("Rápidos:"));
                let quick = [
                    (tr("Router").to_string(), gw.map(|g| g.to_string()).unwrap_or_default()),
                    ("Cloudflare".into(), "1.1.1.1".into()),
                    ("Google".into(), "8.8.8.8".into()),
                ];
                for (l, t) in quick {
                    if !t.is_empty() && ui.small_button(l).clicked() {
                        self.lat_target = t;
                        self.start_latency(ctx);
                    }
                }
                if let Some(ip) = ip {
                    muted(ui, tf("· midiendo {}", &[&(ip)]));
                }
            });
            if let Some(e) = err {
                notice(ui, &e, RED());
            }
        });
        let vals: Vec<Option<f64>> = samples.iter().map(|s| s.1).collect();
        let st = ping::stats(&vals);
        let (_, mosv) = ping::mos(st.avg, st.jitter, st.loss);
        ui.add_space(6.0);
        ui.columns(6, |c| {
            stat(&mut c[0], tr("Enviados / recibidos"), &format!("{} / {}", st.sent, st.recv), TEXT(), "");
            stat(&mut c[1], tr("Pérdida"), &format!("{:.1} %", st.loss), if st.loss > 2.0 { RED() } else if st.loss > 0.0 { AMBER() } else { GREEN() }, "");
            stat(&mut c[2], tr("Latencia media"), &ms(if st.recv > 0 { Some(st.avg) } else { None }), ACCENT(), &tf("mín {:.1} · máx {:.1}", &[&(st.min), &(st.max)]));
            stat(&mut c[3], "Jitter", &format!("{:.1} ms", st.jitter), if st.jitter > 30.0 { RED() } else { VIOLET() }, &tf("desv. {:.1} ms", &[&(st.stddev)]));
            stat(&mut c[4], tr("Percentil 95"), &format!("{:.1} ms", st.p95), TEXT(), "");
            stat(&mut c[5], tr("MOS (voz)"), &if st.recv > 0 { format!("{:.2}", mosv) } else { "—".into() }, score_color((mosv - 1.0) / 3.5 * 100.0), tr("de 1 a 4.5"));
        });
        ui.add_space(6.0);
        let gw_stats = {
            let m = lock(&self.monitor);
            let v: Vec<Option<f64>> = m.gw_latency.iter().cloned().collect();
            ping::stats(&v)
        };
        card(ui, tr("Latencia en el tiempo (marcas rojas = paquetes perdidos)"), |ui| {
            let last: Vec<Option<f64>> = vals[vals.len().saturating_sub(300)..].to_vec();
            line_chart(ui, 220.0, &[Series { values: &last, color: ACCENT(), fill: true }], &|v| format!("{:.0} ms", v), 5.0);
            if st.sent >= 10 {
                let mut d = Vec::new();
                if st.loss > 2.0 {
                    d.push(tf("Hay pérdida de paquetes ({:.1} %): revisa el Wi-Fi, el cable o la saturación de la línea.", &[&(st.loss)]));
                }
                if st.jitter > 30.0 {
                    d.push(tr("El jitter es alto: las llamadas y videollamadas pueden cortarse.").to_string());
                }
                if st.avg > 100.0 {
                    d.push(tr("La latencia es alta para juegos y llamadas.").to_string());
                }
                if gw_stats.recv > 3 && st.recv > 0 && gw_stats.avg > st.avg * 0.6 && st.avg > 30.0 {
                    d.push(tr("Gran parte del retardo está ya en tu red local (router o Wi-Fi).").to_string());
                }
                if d.is_empty() {
                    notice(ui, tr("Conexión estable: sin pérdidas ni retardos relevantes."), GREEN());
                } else {
                    notice(ui, &d.join("  "), AMBER());
                }
            }
        });
        ui.add_space(6.0);
        let (t_running, hops, raw, terr) = {
            let t = lock(&self.trace);
            (t.running, t.hops.clone(), t.raw.clone(), t.error.clone())
        };
        card(ui, tr("Ruta hasta el destino (traceroute)"), |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.trace_target).desired_width(200.0));
                if ui.add_enabled(!t_running, egui::Button::new(if t_running { tr("Trazando…") } else { tr("Trazar ruta") })).clicked() {
                    ping::start_trace(self.trace.clone(), self.trace_target.trim().to_string(), ctx.clone());
                }
                if t_running {
                    ui.spinner();
                }
            });
            if let Some(e) = terr {
                notice(ui, &e, AMBER());
            }
            let maxr = hops.iter().filter_map(|h| h.rtt).fold(1.0, f64::max);
            for h in &hops {
                let (a, b) = match (h.ip, h.rtt) {
                    (Some(ip), Some(r)) => (ip.to_string(), format!("{:.1} ms", r)),
                    (Some(ip), None) => (ip.to_string(), "—".into()),
                    (None, _) => (tr("* (sin respuesta)").into(), "—".into()),
                };
                bar(ui, &format!("{:>2}. {}", h.n, a), &b, (h.rtt.unwrap_or(0.0) / maxr) as f32, if h.rtt.is_some() { ACCENT() } else { MUTED() });
            }
            if !raw.is_empty() {
                egui::CollapsingHeader::new(tr("Salida completa")).show(ui, |ui| {
                    ui.label(RichText::new(raw.join("\n")).monospace().size(12.0));
                });
            }
        });
    }

    fn page_qoe(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Calidad de experiencia (QoE)"), tr("Cómo se sentirá tu conexión en llamadas, vídeo, juegos y navegación"));
        let (running, step, prog, live, result) = {
            let s = lock(&self.qoe);
            (s.running, s.step.clone(), s.progress, s.live_down, s.result.clone())
        };
        card(ui, "", |ui| {
            ui.horizontal(|ui| {
                if ui.add_enabled(!running, egui::Button::new(RichText::new(tr("Medir calidad ahora")).strong().color(ON_ACCENT())).fill(ACCENT())).clicked() {
                    let info = lock(&self.info).clone();
                    qoe::start_qoe(self.qoe.clone(), info.gateway, info.dns.first().copied(), self.qoe_url.clone(), ctx.clone());
                }
                ui.label(tr("Archivo de prueba de velocidad:"));
                ui.add(egui::TextEdit::singleline(&mut self.qoe_url).desired_width(330.0));
            });
            if running {
                ui.add(egui::ProgressBar::new(prog).text(step.clone()).fill(ACCENT_DIM()));
                if let Some(d) = live {
                    muted(ui, tf("Descarga en curso: {}", &[&(fmt_bps(d))]));
                }
            } else {
                muted(ui, tr("Tarda unos 20 segundos: mide el router, Internet (1.1.1.1), el DNS, el tiempo de conexión y la velocidad de descarga."));
            }
        });
        ui.add_space(6.0);
        let Some(r) = result else { return };
        ui.columns(2, |c| {
            card(&mut c[0], tr("Nota global"), |ui| {
                ui.horizontal(|ui| {
                    gauge(ui, Some(r.overall), tr("de 100"), 150.0);
                    ui.vertical(|ui| {
                        ui.add_space(20.0);
                        ui.label(RichText::new(qoe::verdict(r.overall)).size(26.0).strong().color(score_color(r.overall)));
                        muted(ui, tf("MOS de voz {:.2} · factor R {:.0}", &[&(r.mos), &(r.r)]));
                        if let Some(e) = &r.down_err {
                            muted(ui, tf("Velocidad no medida: {}", &[&(e)]));
                        }
                    });
                });
            });
            card(&mut c[1], tr("Por tipo de uso"), |ui| {
                for s in &r.scores {
                    bar(ui, s.name, &format!("{:.0} · {}", s.score, qoe::verdict(s.score)), (s.score / 100.0) as f32, score_color(s.score));
                    ui.label(RichText::new(format!("      {}", s.detail)).color(MUTED()).size(12.0));
                }
            });
        });
        ui.add_space(6.0);
        ui.columns(6, |c| {
            stat(&mut c[0], tr("Router"), &ms(if r.gw.recv > 0 { Some(r.gw.avg) } else { None }), GREEN(), &tf("pérdida {:.0}%", &[&(r.gw.loss)]));
            stat(&mut c[1], "Internet", &ms(if r.inet.recv > 0 { Some(r.inet.avg) } else { None }), ACCENT(), &tf("pérdida {:.0}%", &[&(r.inet.loss)]));
            stat(&mut c[2], "Jitter", &format!("{:.1} ms", r.inet.jitter), VIOLET(), "");
            stat(&mut c[3], "DNS", &ms(r.dns_ms), TEXT(), tr("resolución de nombres"));
            stat(&mut c[4], tr("Conexión web"), &ms(r.tcp_ms), TEXT(), tr("tiempo de conexión TCP"));
            stat(&mut c[5], tr("Descarga"), &r.down_bps.map(fmt_bps).unwrap_or("—".into()), ACCENT(), "");
        });
    }

    fn page_dns(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Análisis DNS"), tr("Consulta registros, compara servidores y revisa la seguridad del dominio"));
        let info = lock(&self.info).clone();
        let servers = dns::public_resolvers(&info.dns);
        let (running, step, last, resolvers, records, findings) = {
            let s = lock(&self.dns);
            (s.running, s.step.clone(), s.last.clone(), s.resolvers.clone(), s.records.clone(), s.findings.clone())
        };
        card(ui, tr("Consulta"), |ui| {
            ui.horizontal(|ui| {
                ui.label(tr("Dominio:"));
                ui.add(egui::TextEdit::singleline(&mut self.dns_name).desired_width(220.0));
                egui::ComboBox::from_id_salt("dnstype").selected_text(dns::type_name(self.dns_type)).show_ui(ui, |ui| {
                    for (n, t) in dns::TYPES {
                        ui.selectable_value(&mut self.dns_type, *t, *n);
                    }
                });
                ui.label(tr("Servidor:"));
                let label = if self.dns_server < servers.len() { format!("{} ({})", servers[self.dns_server].0, servers[self.dns_server].1) } else { tr("Otro…").into() };
                egui::ComboBox::from_id_salt("dnsserver").selected_text(label).width(220.0).show_ui(ui, |ui| {
                    for (i, (n, ip)) in servers.iter().enumerate() {
                        ui.selectable_value(&mut self.dns_server, i, format!("{} ({})", n, ip));
                    }
                    ui.selectable_value(&mut self.dns_server, servers.len(), tr("Otro…"));
                });
                if self.dns_server >= servers.len() {
                    ui.add(egui::TextEdit::singleline(&mut self.dns_custom).hint_text("IP del servidor").desired_width(120.0));
                }
                let server: Option<IpAddr> = if self.dns_server < servers.len() { Some(servers[self.dns_server].1) } else { self.dns_custom.trim().parse().ok() };
                let name = self.dns_name.trim().to_string();
                if ui.add_enabled(!running && server.is_some() && !name.is_empty(), egui::Button::new(tr("Consultar"))).clicked() {
                    let qname = if self.dns_type == 12 { name.parse::<Ipv4Addr>().map(dns::ptr_name).unwrap_or(name.clone()) } else { name.clone() };
                    if let Some(s) = server {
                        dns::start_query(self.dns.clone(), s, qname, self.dns_type, ctx.clone());
                    }
                }
                if ui
                    .add_enabled(!running && !name.is_empty(), egui::Button::new(RichText::new(tr("Análisis completo")).strong().color(ON_ACCENT())).fill(ACCENT()))
                    .clicked()
                {
                    dns::start_analysis(self.dns.clone(), info.dns.clone(), name, ctx.clone());
                }
                if running {
                    ui.spinner();
                    muted(ui, step.clone());
                }
            });
            if let Some((name, server, res)) = last {
                ui.add_space(4.0);
                match res {
                    Err(e) => notice(ui, &format!("{} en {}: {}", name, server, e), RED()),
                    Ok((m, t)) => {
                        ui.horizontal(|ui| {
                            badge(ui, dns::rcode_name(m.rcode), if m.rcode == 0 { GREEN() } else { AMBER() });
                            muted(ui, tf("{} · {:.1} ms · indicadores: {}", &[&(server), &(t), &(m.flag_text())]));
                            if m.flags & 0x0020 != 0 {
                                badge(ui, tr("DNSSEC verificado"), GREEN());
                            }
                        });
                        let cols = [(260.0, tr("Nombre")), (70.0, tr("Tipo")), (80.0, "TTL"), (500.0, tr("Valor"))];
                        table_header(ui, &cols);
                        let mut i = 0;
                        for (sec, list) in [("", &m.answers), (tr("autoridad · "), &m.authority)] {
                            for a in list.iter() {
                                if a.rtype == 41 {
                                    continue;
                                }
                                table_row(
                                    ui,
                                    &[(260.0, format!("{}{}", sec, a.name), TEXT()), (70.0, dns::type_name(a.rtype), ACCENT()), (80.0, format!("{} s", a.ttl), MUTED()), (500.0, a.data.clone(), TEXT())],
                                    false,
                                    i % 2 == 1,
                                );
                                i += 1;
                            }
                        }
                        if i == 0 {
                            muted(ui, tr("La respuesta no trae registros."));
                        }
                    }
                }
            }
        });
        ui.add_space(6.0);
        if resolvers.is_empty() && findings.is_empty() {
            return;
        }
        ui.columns(2, |c| {
            card(&mut c[0], tr("Velocidad de los servidores DNS"), |ui| {
                let maxv = resolvers.iter().filter_map(|r| r.ms).fold(1.0, f64::max);
                for r in &resolvers {
                    let (txt, f, col) = match r.ms {
                        Some(m) => (
                            format!("{:.1} ms · {}", m, r.answers.first().cloned().unwrap_or_else(|| r.error.clone().unwrap_or_default())),
                            (m / maxv) as f32,
                            if m < 40.0 { GREEN() } else if m < 120.0 { AMBER() } else { RED() },
                        ),
                        None => (r.error.clone().unwrap_or(tr("sin respuesta").into()), 0.0, RED()),
                    };
                    bar(ui, &format!("{} {}", tr(&r.name), r.server), &txt, f, col);
                }
            });
            card(&mut c[1], tr("Registros del dominio"), |ui| {
                egui::Grid::new("records").num_columns(2).spacing([14.0, 3.0]).show(ui, |ui| {
                    for (t, v) in &records {
                        ui.label(RichText::new(t).color(ACCENT()).strong());
                        ui.add(egui::Label::new(if v.is_empty() { "—".to_string() } else { v.join("\n") }).wrap());
                        ui.end_row();
                    }
                });
            });
        });
        ui.add_space(6.0);
        card(ui, tr("Diagnóstico y seguridad del DNS"), |ui| {
            for f in &findings {
                ui.horizontal(|ui| {
                    badge(ui, f.sev.label(), sev_color(f.sev));
                    ui.label(RichText::new(&f.title).strong());
                });
                ui.label(RichText::new(&f.detail).color(MUTED()).size(12.5));
                ui.add_space(3.0);
            }
            if findings.is_empty() {
                muted(ui, tr("Analizando…"));
            }
        });
    }

    fn page_security(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Seguridad y vulnerabilidades"), tr("Busca servicios expuestos, contraseñas por defecto y software antiguo"));
        let hosts: Vec<String> = lock(&self.subnet).hosts.iter().map(|h| h.ip.to_string()).collect();
        let (running, step, done, total, findings, open, score) = {
            let a = lock(&self.audit);
            (a.running, a.step.clone(), a.hosts_done, a.hosts_total, a.findings.clone(), a.open_ports.clone(), a.score)
        };
        let gw = lock(&self.info).gateway;
        card(ui, "", |ui| {
            ui.horizontal(|ui| {
                ui.label(tr("Equipo:"));
                ui.add(egui::TextEdit::singleline(&mut self.audit_target).hint_text("IP o nombre").desired_width(200.0));
                if running {
                    if danger(ui, tr("Detener")).clicked() {
                        self.audit_stop.store(true, Ordering::Relaxed);
                    }
                } else {
                    if primary(ui, tr("Auditar este equipo")).clicked() && !self.audit_target.trim().is_empty() {
                        let t = self.audit_target.trim().to_string();
                        self.start_audit(vec![t], ctx);
                    }
                    if let Some(g) = gw {
                        if ui.button(tr("Auditar el router")).clicked() {
                            self.audit_target = g.to_string();
                            self.start_audit(vec![g.to_string()], ctx);
                        }
                    }
                    if ui
                        .add_enabled(!hosts.is_empty(), egui::Button::new(tf("Auditar toda la red ({} equipos)", &[&(hosts.len())])))
                        .on_disabled_hover_text("Primero escanea la red")
                        .clicked()
                    {
                        self.start_audit(hosts.clone(), ctx);
                    }
                }
            });
            if running {
                progress(ui, done, total, &step);
            }
            muted(ui, tr("Audita solo equipos propios o con permiso. Se comprueban unos 60 puertos habituales, banners, accesos anónimos (FTP, Redis, Memcached, Docker, Elasticsearch), SNMP «public», UPnP y DNS abiertos."));
        });
        ui.add_space(6.0);
        if score.is_none() && !running {
            return;
        }
        ui.columns(2, |c| {
            card(&mut c[0], tr("Puntuación de seguridad"), |ui| {
                ui.horizontal(|ui| {
                    gauge(ui, score.map(|s| s as f64), tr("de 100"), 130.0);
                    ui.vertical(|ui| {
                        ui.add_space(10.0);
                        for s in Sev::all() {
                            let n = findings.iter().filter(|f| f.sev == s).count();
                            ui.horizontal(|ui| {
                                badge(ui, s.label(), sev_color(s));
                                ui.label(tf("{} hallazgos", &[&(n)]));
                            });
                        }
                    });
                });
            });
            card(&mut c[1], tr("Servicios abiertos encontrados"), |ui| {
                if open.is_empty() {
                    muted(ui, tr("Ninguno todavía."));
                }
                for (h, p, b) in open.iter().take(14) {
                    ui.add(egui::Label::new(RichText::new(format!("{}:{} {}  {}", h, p, service_name(*p), b)).size(12.5)).truncate());
                }
            });
        });
        ui.add_space(6.0);
        card(ui, tr("Hallazgos"), |ui| {
            if !findings.is_empty() && ui.button(format!("⬇ {}", tr("Exportar CSV"))).clicked() {
                let rows = findings
                    .iter()
                    .map(|f| vec![f.sev.label().to_string(), f.host.clone(), f.port.map(|p| p.to_string()).unwrap_or_default(), f.title.clone(), f.detail.clone(), f.fix.clone()])
                    .collect();
                self.export("hallazgos", &["Nivel", "Equipo", "Puerto", "Hallazgos", "Descripción", "Cómo arreglarlo"], rows);
            }
            self.export_notice(ui);
            for f in &findings {
                egui::Frame::new().fill(CARD2()).corner_radius(8.0).inner_margin(10.0).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        badge(ui, f.sev.label(), sev_color(f.sev));
                        ui.label(RichText::new(&f.title).strong());
                        muted(ui, format!("{}{}", f.host, f.port.map(|p| format!(":{}", p)).unwrap_or_default()));
                    });
                    ui.label(RichText::new(&f.detail).size(12.5));
                    if !f.fix.is_empty() {
                        ui.label(RichText::new(tf("Cómo arreglarlo: {}", &[&(f.fix)])).color(GREEN()).size(12.5));
                    }
                });
                ui.add_space(4.0);
            }
        });
    }

    fn page_ids(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Detección de intrusos y anomalías"), tr("Vigila escaneos, suplantaciones, inundaciones, túneles DNS y contraseñas en claro"));
        let (alerts, enabled, seen) = {
            let i = lock(&self.ids);
            (i.alerts.clone(), i.enabled, i.packets_seen)
        };
        let cap_running = lock(&self.capture).running;
        let watched = lock(&self.monitor).watched.len();
        ui.columns(5, |c| {
            for (i, s) in Sev::all().iter().enumerate() {
                let n = alerts.iter().filter(|a| a.sev == *s).count();
                stat(&mut c[i], &tf("Alertas {}", &[&(s.label().to_lowercase())]), &n.to_string(), if n > 0 { sev_color(*s) } else { MUTED() }, "");
            }
        });
        ui.add_space(6.0);
        card(ui, tr("Fuentes vigiladas"), |ui| {
            ui.horizontal_wrapped(|ui| {
                let mut en = enabled;
                if ui.checkbox(&mut en, tr("Detector activo")).changed() {
                    lock(&self.ids).enabled = en;
                }
                ui.separator();
                badge(ui, if cap_running { tr("Captura en vivo: activa") } else { tr("Captura en vivo: parada") }, if cap_running { GREEN() } else { AMBER() });
                muted(ui, tf("{} paquetes analizados", &[&(seen)]));
                if !cap_running && primary(ui, tr("Iniciar captura para el detector")).clicked() {
                    self.start_capture(ctx);
                }
                ui.separator();
                badge(ui, tr("Tabla ARP: cada 10 s"), GREEN());
                badge(ui, &tf("Equipos vigilados: {}", &[&(watched)]), if watched > 0 { GREEN() } else { MUTED() });
                badge(ui, tr("Tráfico por interfaz: cada 1 s"), GREEN());
            });
            if !cap_running {
                muted(ui, tr("Sin captura solo se detectan suplantaciones ARP, equipos nuevos o caídos y picos de tráfico. Con captura se analizan todos los paquetes."));
            }
        });
        ui.add_space(6.0);
        card(ui, tr("Alertas"), |ui| {
            ui.horizontal(|ui| {
                ui.label(tr("Mostrar desde:"));
                egui::ComboBox::from_id_salt("sevmin").selected_text(self.ids_min.label()).show_ui(ui, |ui| {
                    for s in Sev::all().iter().rev() {
                        ui.selectable_value(&mut self.ids_min, *s, s.label());
                    }
                });
                if !alerts.is_empty() && ui.button(format!("⬇ {}", tr("Exportar CSV"))).clicked() {
                    let rows = alerts.iter().map(|a| vec![fmt_clock(a.ts), a.sev.label().to_string(), a.cat.clone(), a.src.clone(), a.msg.clone()]).collect();
                    self.export("alertas", &["Hora", "Nivel", "Tipo", "Origen", "Descripción"], rows);
                }
                if ui.button(tr("Borrar alertas")).clicked() {
                    lock(&self.ids).alerts.clear();
                }
            });
            self.export_notice(ui);
            let cols = [(90.0, tr("Hora")), (80.0, tr("Nivel")), (170.0, tr("Tipo")), (160.0, tr("Origen")), (600.0, tr("Descripción"))];
            table_header(ui, &cols);
            let mut n = 0;
            for a in alerts.iter().rev().filter(|a| a.sev >= self.ids_min).take(500) {
                table_row(
                    ui,
                    &[(90.0, fmt_clock(a.ts), MUTED()), (80.0, a.sev.label().to_string(), sev_color(a.sev)), (170.0, a.cat.clone(), TEXT()), (160.0, a.src.clone(), ACCENT()), (600.0, a.msg.clone(), SUBTLE())],
                    false,
                    n % 2 == 1,
                );
                n += 1;
            }
            if n == 0 {
                muted(ui, tr("Sin alertas por ahora."));
            }
        });
        ui.add_space(6.0);
        card(ui, tr("Reglas de detección"), |ui| {
            egui::Grid::new("rules").num_columns(2).spacing([18.0, 3.0]).striped(true).show(ui, |ui| {
                for (n, d) in RULES.iter().map(|(n, d)| (tr(n), tr(d))) {
                    ui.label(RichText::new(n).strong().color(ACCENT()));
                    ui.label(RichText::new(d).color(MUTED()));
                    ui.end_row();
                }
            });
        });
    }

    fn page_monitor(&mut self, ui: &mut Ui) {
        page_title(ui, tr("Monitorización"), tr("Tráfico de cada interfaz y disponibilidad de los equipos que te importan"));
        let (ifaces, watched, gw_lat, total_hist) = {
            let m = lock(&self.monitor);
            (m.ifaces.clone(), m.watched.clone(), m.gw_latency.iter().cloned().collect::<Vec<_>>(), m.total_hist())
        };
        let gw = lock(&self.info).gateway;
        card(ui, tr("Tráfico"), |ui| {
            ui.horizontal(|ui| {
                ui.label(tr("Interfaz:"));
                egui::ComboBox::from_id_salt("moniface").selected_text(if self.mon_iface.is_empty() { tr("Todas").to_string() } else { self.mon_iface.clone() }).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.mon_iface, String::new(), tr("Todas"));
                    for n in ifaces.keys() {
                        ui.selectable_value(&mut self.mon_iface, n.clone(), n);
                    }
                });
                ui.label(RichText::new(tr("Descarga")).color(ACCENT()));
                ui.label(RichText::new(tr("Subida")).color(VIOLET()));
            });
            let hist: Vec<(f64, f64)> = if self.mon_iface.is_empty() { total_hist.clone() } else { ifaces.get(&self.mon_iface).map(|s| s.hist.iter().cloned().collect()).unwrap_or_default() };
            let rx: Vec<Option<f64>> = hist.iter().map(|v| Some(v.0 * 8.0)).collect();
            let tx: Vec<Option<f64>> = hist.iter().map(|v| Some(v.1 * 8.0)).collect();
            line_chart(ui, 200.0, &[Series { values: &rx, color: ACCENT(), fill: true }, Series { values: &tx, color: VIOLET(), fill: true }], &|v| fmt_bps(v / 8.0), 8000.0);
            ui.add_space(4.0);
            let cols = [(180.0, tr("Interfaz")), (130.0, tr("Descarga")), (130.0, tr("Subida")), (140.0, tr("Total recibido")), (140.0, tr("Total enviado"))];
            table_header(ui, &cols);
            for (i, (n, s)) in ifaces.iter().enumerate() {
                table_row(
                    ui,
                    &[(180.0, n.clone(), TEXT()), (130.0, fmt_bps(s.rx_rate), ACCENT()), (130.0, fmt_bps(s.tx_rate), VIOLET()), (140.0, fmt_bytes(s.rx as f64), MUTED()), (140.0, fmt_bytes(s.tx as f64), MUTED())],
                    self.mon_iface == *n,
                    i % 2 == 1,
                );
            }
        });
        ui.add_space(6.0);
        card(ui, tr("Equipos vigilados (ping cada 5 s)"), |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.watch_input).hint_text("IP o nombre, p. ej. 192.168.1.20 o google.com").desired_width(300.0));
                if primary(ui, tr("Añadir")).clicked() {
                    let h = std::mem::take(&mut self.watch_input);
                    self.add_watch(h);
                }
                if let Some(g) = gw {
                    if ui.button(tr("Vigilar el router")).clicked() {
                        self.add_watch(g.to_string());
                    }
                }
            });
            let mut remove = None;
            for w in &watched {
                ui.horizontal(|ui| {
                    let (col, st) = match w.up {
                        Some(true) => (GREEN(), tr("Activo")),
                        Some(false) => (RED(), tr("Caído")),
                        None => (MUTED(), tr("Comprobando")),
                    };
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 6.0, col);
                    ui.add_sized([220.0, 18.0], egui::Label::new(RichText::new(&w.host).strong()).truncate());
                    ui.add_sized([90.0, 18.0], egui::Label::new(RichText::new(st).color(col)));
                    ui.add_sized([80.0, 18.0], egui::Label::new(ms(w.last_rtt)));
                    let avail = if w.checks > 0 { 100.0 * w.ok as f64 / w.checks as f64 } else { 0.0 };
                    ui.add_sized([150.0, 18.0], egui::Label::new(RichText::new(tf("disponible {:.1}%", &[&(avail)])).color(MUTED())));
                    let h: Vec<Option<f64>> = w.hist.iter().cloned().collect();
                    sparkline(ui, &h, ACCENT(), 220.0, 22.0);
                    if ui.small_button(tr("Quitar")).clicked() {
                        remove = Some(w.host.clone());
                    }
                });
            }
            if watched.is_empty() {
                muted(ui, tr("Añade servidores, cámaras o el router: si dejan de responder aparecerá una alerta."));
            }
            if let Some(h) = remove {
                lock(&self.monitor).watched.retain(|w| w.host != h);
            }
        });
        ui.add_space(6.0);
        card(ui, tr("Latencia al router (cada 2 s)"), |ui| {
            line_chart(ui, 160.0, &[Series { values: &gw_lat, color: GREEN(), fill: true }], &|v| format!("{:.0} ms", v), 5.0);
        });
    }
}
