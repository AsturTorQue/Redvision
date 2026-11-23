//! Páginas de Herramientas y Ajustes, y exportación a CSV.
use crate::app::NetApp;
use crate::i18n::{tf, tr};
use crate::tools;
use crate::util::*;
use crate::widgets::*;
use eframe::egui::{self, Align2, FontId, RichText, Sense, Stroke, Ui, Vec2};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

#[derive(Default)]
pub struct MtuState {
    pub running: bool,
    pub step: Option<u32>,
    pub result: Option<Result<u32, String>>,
}

type Found<T> = Shared<(bool, Option<Result<Vec<T>, String>>)>;

/// Estado de las herramientas de descubrimiento.
#[derive(Default)]
pub struct ToolsState {
    pub mtu_target: String,
    pub mtu: Shared<MtuState>,
    pub upnp: Found<crate::netdiscover::UpnpDevice>,
    pub mdns: Found<crate::netdiscover::MdnsService>,
    pub arp: Vec<(Ipv4Addr, String)>,
    pub arp_loaded: bool,
    pub sys_text: Option<String>,
}

impl NetApp {
    pub(crate) fn send_wol(&mut self) {
        let info = lock(&self.info).clone();
        let bcast = info.local_ip.map(|ip| Ipv4Addr::from(u32::from(ip) | !mask(effective_prefix(info.prefix))));
        self.wol_msg = Some(match tools::wake_on_lan(&self.wol_mac, bcast) {
            Ok(m) => (true, tf("Paquete mágico enviado a {}", &[&m])),
            Err(e) => (false, e),
        });
    }

    pub(crate) fn export(&mut self, name: &str, header: &[&str], rows: Vec<Vec<String>>) {
        let header: Vec<&str> = header.iter().map(|h| tr(h)).collect();
        self.export_msg = Some(match tools::export_csv(name, &header, &rows) {
            Ok(p) => tf("Guardado en {}", &[&p.display()]),
            Err(e) => tf("No se pudo guardar: {}", &[&e]),
        });
    }

    pub(crate) fn export_notice(&self, ui: &mut Ui) {
        if let Some(m) = &self.export_msg {
            notice(ui, m, GREEN());
        }
    }

    pub(crate) fn page_tools(&mut self, ui: &mut Ui) {
        page_title(ui, tr("Herramientas"), tr("Utilidades rápidas para la red"));
        let pub_running = self.pubip_running.load(Ordering::Relaxed);
        let pub_result = lock(&self.pubip).clone();
        ui.columns(2, |c| {
            card(&mut c[0], tr("Mi IP pública"), |ui| {
                ui.horizontal(|ui| {
                    let btn = egui::Button::new(RichText::new(tr("Consultar IP pública")).strong().color(ON_ACCENT())).fill(ACCENT());
                    if ui.add_enabled(!pub_running, btn).clicked() {
                        let (slot, flag, ctx) = (self.pubip.clone(), self.pubip_running.clone(), ui.ctx().clone());
                        flag.store(true, Ordering::Relaxed);
                        std::thread::spawn(move || {
                            let r = tools::public_ip();
                            *lock(&slot) = Some(r);
                            flag.store(false, Ordering::Relaxed);
                            ctx.request_repaint();
                        });
                    }
                    if pub_running {
                        ui.spinner();
                    }
                });
                match &pub_result {
                    Some(Ok(rows)) => {
                        egui::Grid::new("pubip").num_columns(2).spacing([18.0, 4.0]).show(ui, |ui| {
                            for (k, v) in rows {
                                ui.label(RichText::new(tr(k)).color(MUTED()));
                                ui.label(RichText::new(v).strong());
                                ui.end_row();
                            }
                        });
                    }
                    Some(Err(e)) => notice(ui, e, RED()),
                    None => {}
                }
                muted(ui, tr("Usa el servicio público ip-api.com."));
            });
            card(&mut c[1], tr("Calculadora de subredes"), |ui| {
                if self.subnet_input.is_empty() {
                    let info = lock(&self.info).clone();
                    if let Some(ip) = info.local_ip {
                        self.subnet_input = format!("{}/{}", ip, info.prefix);
                    }
                }
                ui.horizontal(|ui| {
                    ui.label(tr("Dirección/prefijo:"));
                    ui.add(egui::TextEdit::singleline(&mut self.subnet_input).hint_text("192.168.1.10/24").desired_width(220.0));
                });
                match tools::subnet(&self.subnet_input) {
                    Some(rows) => {
                        egui::Grid::new("subnetcalc").num_columns(2).spacing([18.0, 4.0]).striped(true).show(ui, |ui| {
                            for (k, v) in rows {
                                ui.label(RichText::new(tr(k)).color(MUTED()));
                                ui.label(RichText::new(v).monospace());
                                ui.end_row();
                            }
                        });
                    }
                    None => muted(ui, tr("Formato no válido. Ejemplo: 192.168.1.10/24")),
                }
            });
        });
        ui.add_space(8.0);
        let hosts_with_mac: Vec<(String, String)> =
            lock(&self.subnet).hosts.iter().filter(|h| !h.mac.is_empty()).map(|h| (h.ip.to_string(), h.mac.clone())).collect();
        ui.columns(2, |c| {
            card(&mut c[0], tr("Encender equipos a distancia (Wake-on-LAN)"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr("MAC del equipo:"));
                    ui.add(egui::TextEdit::singleline(&mut self.wol_mac).hint_text("AA:BB:CC:DD:EE:FF").desired_width(170.0));
                    if !hosts_with_mac.is_empty() {
                        egui::ComboBox::from_id_salt("wolhosts").selected_text("…").show_ui(ui, |ui| {
                            for (ip, mac) in &hosts_with_mac {
                                if ui.selectable_label(false, format!("{} · {}", ip, mac)).clicked() {
                                    self.wol_mac = mac.clone();
                                }
                            }
                        });
                    }
                });
                if primary(ui, tr("Enviar paquete mágico")).clicked() {
                    self.send_wol();
                }
                if let Some((ok, m)) = &self.wol_msg {
                    notice(ui, m, if *ok { GREEN() } else { RED() });
                }
                muted(ui, tr("El equipo debe tener Wake-on-LAN activado en la BIOS y en la tarjeta de red."));
            });
            card(&mut c[1], tr("Buscar fabricante por MAC"), |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.mac_lookup).hint_text("AA:BB:CC:DD:EE:FF").desired_width(220.0));
                if let Some(m) = normalize_mac(self.mac_lookup.trim()) {
                    let v = vendor(&m);
                    if v.is_empty() {
                        muted(ui, tr("No está en la lista interna de fabricantes."));
                    } else {
                        ui.label(RichText::new(tf("Fabricante: {}", &[&v])).strong().color(ACCENT()));
                    }
                }
            });
        });
        ui.add_space(8.0);
        self.tools_more(ui);
    }

    fn tools_more(&mut self, ui: &mut Ui) {
        let (mtu_running, mtu_step, mtu_result) = {
            let m = lock(&self.tx.mtu);
            (m.running, m.step, m.result.clone())
        };
        if self.tx.mtu_target.is_empty() {
            self.tx.mtu_target = "1.1.1.1".into();
        }
        if !self.tx.arp_loaded {
            self.tx.arp = arp_table();
            self.tx.arp_loaded = true;
        }
        ui.columns(2, |c| {
            card(&mut c[0], tr("Tamaño máximo de paquete (MTU de la ruta)"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr("Destino:"));
                    ui.add(egui::TextEdit::singleline(&mut self.tx.mtu_target).desired_width(180.0));
                    if ui.add_enabled(!mtu_running, egui::Button::new(tr("Medir MTU"))).clicked() {
                        let (st, host, ctx) = (self.tx.mtu.clone(), self.tx.mtu_target.trim().to_string(), ui.ctx().clone());
                        {
                            let mut m = lock(&st);
                            m.running = true;
                            m.result = None;
                        }
                        std::thread::spawn(move || {
                            let st2 = st.clone();
                            let c2 = ctx.clone();
                            let r = crate::netdiscover::path_mtu(&host, &move |n| {
                                lock(&st2).step = Some(n);
                                c2.request_repaint();
                            });
                            let mut m = lock(&st);
                            m.running = false;
                            m.step = None;
                            m.result = Some(r);
                            ctx.request_repaint();
                        });
                    }
                    if mtu_running {
                        ui.spinner();
                    }
                });
                if let Some(n) = mtu_step {
                    muted(ui, tf("Probando con {} bytes…", &[&n]));
                }
                match mtu_result {
                    Some(Ok(m)) => {
                        ui.label(RichText::new(tf("MTU de la ruta: {} bytes", &[&m])).size(18.0).strong().color(if m >= 1500 { GREEN() } else { AMBER() }));
                        if m < 1500 {
                            muted(ui, tr("Menor de 1500: hay un túnel, VPN o PPPoE en el camino. Si algunas webs no cargan, baja la MTU del equipo a este valor."));
                        }
                    }
                    Some(Err(e)) => notice(ui, &e, RED()),
                    None => muted(ui, tr("Encuentra el paquete más grande que llega sin partirse; útil para problemas con VPN o webs que no cargan.")),
                }
            });
            card(&mut c[1], tr("Tabla ARP del sistema"), |ui| {
                if ui.button(tr("Actualizar")).clicked() {
                    self.tx.arp = arp_table();
                }
                table_header(ui, &[(140.0, "IP"), (160.0, "MAC"), (200.0, tr("Fabricante"))]);
                egui::ScrollArea::vertical().id_salt("arptable").max_height(200.0).show(ui, |ui| {
                    for (i, (ip, mac)) in self.tx.arp.iter().enumerate() {
                        table_row(ui, &[(140.0, ip.to_string(), TEXT()), (160.0, mac.clone(), MUTED()), (200.0, vendor(mac), SUBTLE())], false, i % 2 == 1);
                    }
                });
            });
        });
        ui.add_space(8.0);
        let (up_running, up_result) = {
            let u = lock(&self.tx.upnp);
            (u.0, u.1.clone())
        };
        card(ui, tr("Dispositivos UPnP (televisores, routers, NAS…)"), |ui| {
            ui.horizontal(|ui| {
                if ui.add_enabled(!up_running, egui::Button::new(tr("Buscar dispositivos UPnP"))).clicked() {
                    let (st, ctx) = (self.tx.upnp.clone(), ui.ctx().clone());
                    lock(&st).0 = true;
                    std::thread::spawn(move || {
                        let r = crate::netdiscover::upnp_discover(3000);
                        *lock(&st) = (false, Some(r));
                        ctx.request_repaint();
                    });
                }
                if up_running {
                    ui.spinner();
                    muted(ui, tr("Buscando…"));
                }
            });
            match up_result {
                Some(Ok(devs)) if !devs.is_empty() => {
                    table_header(ui, &[(130.0, "IP"), (220.0, tr("Nombre")), (160.0, tr("Fabricante")), (180.0, tr("Modelo")), (300.0, tr("Servidor"))]);
                    for (i, d) in devs.iter().enumerate() {
                        let row = [
                            (130.0, d.ip.clone(), ACCENT()),
                            (220.0, d.name.clone(), TEXT()),
                            (160.0, d.maker.clone(), SUBTLE()),
                            (180.0, d.model.clone(), SUBTLE()),
                            (300.0, d.server.clone(), MUTED()),
                        ];
                        table_row(ui, &row, false, i % 2 == 1).on_hover_text(d.types.join("\n"));
                    }
                }
                Some(Ok(_)) => muted(ui, tr("Sin respuestas UPnP.")),
                Some(Err(e)) => notice(ui, &e, RED()),
                None => {}
            }
        });
        ui.add_space(8.0);
        let (md_running, md_result) = {
            let u = lock(&self.tx.mdns);
            (u.0, u.1.clone())
        };
        card(ui, tr("Servicios Bonjour / mDNS (impresoras, Chromecast, AirPlay…)"), |ui| {
            ui.horizontal(|ui| {
                if ui.add_enabled(!md_running, egui::Button::new(tr("Buscar servicios mDNS"))).clicked() {
                    let (st, ctx) = (self.tx.mdns.clone(), ui.ctx().clone());
                    lock(&st).0 = true;
                    std::thread::spawn(move || {
                        let r = crate::netdiscover::mdns_discover();
                        *lock(&st) = (false, Some(r));
                        ctx.request_repaint();
                    });
                }
                if md_running {
                    ui.spinner();
                    muted(ui, tr("Buscando…"));
                }
            });
            match md_result {
                Some(Ok(list)) if !list.is_empty() => {
                    table_header(ui, &[(160.0, tr("Tipo")), (300.0, tr("Nombre")), (240.0, tr("Servicio")), (140.0, "IP")]);
                    for (i, s) in list.iter().enumerate() {
                        let label = crate::netdiscover::service_label(&s.kind);
                        let row = [
                            (160.0, tr(label).to_string(), ACCENT()),
                            (300.0, s.instance.clone(), TEXT()),
                            (240.0, s.kind.clone(), MUTED()),
                            (140.0, s.ip.clone(), SUBTLE()),
                        ];
                        table_row(ui, &row, false, i % 2 == 1);
                    }
                }
                Some(Ok(_)) => muted(ui, tr("Sin respuestas mDNS.")),
                Some(Err(e)) => notice(ui, &e, RED()),
                None => {}
            }
        });
        ui.add_space(8.0);
        card(ui, tr("Interfaces y rutas del sistema"), |ui| {
            ui.horizontal(|ui| {
                if ui.button(tr("Ver interfaces")).clicked() {
                    self.tx.sys_text = Some(crate::netdiscover::system_interfaces());
                }
                if ui.button(tr("Ver rutas")).clicked() {
                    self.tx.sys_text = Some(crate::netdiscover::system_routes());
                }
            });
            if let Some(t) = &self.tx.sys_text {
                egui::ScrollArea::both().id_salt("systext").max_height(260.0).show(ui, |ui| {
                    ui.label(RichText::new(t).monospace().size(12.0).color(SUBTLE()));
                });
            }
        });
    }

    pub(crate) fn page_settings(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_title(ui, tr("Ajustes"), tr("Idioma, aspecto y preferencias (se guardan solas)"));
        ui.columns(2, |c| {
            card(&mut c[0], tr("Idioma"), |ui| {
                for (i, (_, name)) in crate::i18n::LANGS.iter().enumerate() {
                    if ui.radio_value(&mut self.settings.lang, i, *name).changed() {
                        crate::i18n::set_lang(i);
                    }
                }
            });
            card(&mut c[1], tr("Tema"), |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (i, th) in THEMES.iter().enumerate() {
                        let sel = self.settings.theme == i;
                        let (rect, resp) = ui.allocate_exact_size(Vec2::new(120.0, 74.0), Sense::click());
                        let p = ui.painter();
                        p.rect_filled(rect, 8.0, th.preview_bg());
                        p.rect_filled(egui::Rect::from_min_size(rect.min + Vec2::new(8.0, 8.0), Vec2::new(28.0, 58.0)), 4.0, th.preview_card());
                        p.rect_filled(egui::Rect::from_min_size(rect.min + Vec2::new(44.0, 12.0), Vec2::new(66.0, 8.0)), 3.0, th.preview_accent());
                        p.rect_filled(egui::Rect::from_min_size(rect.min + Vec2::new(44.0, 26.0), Vec2::new(50.0, 6.0)), 3.0, th.preview_text());
                        p.text(rect.center_bottom() - Vec2::new(0.0, 12.0), Align2::CENTER_CENTER, tr(th.name), FontId::proportional(12.5), th.preview_text());
                        let stroke = Stroke::new(if sel { 3.0_f32 } else { 1.0 }, if sel { ACCENT() } else { BORDER() });
                        p.rect_stroke(rect, 8.0, stroke, egui::StrokeKind::Inside);
                        if resp.clicked() {
                            self.settings.theme = i;
                            set_theme(i);
                            apply_style(ctx);
                        }
                    }
                });
            });
        });
        ui.add_space(8.0);
        ui.columns(2, |c| {
            card(&mut c[0], tr("Tamaño de la interfaz"), |ui| {
                let mut pct = (self.settings.zoom * 100.0).round();
                if ui.add(egui::Slider::new(&mut pct, 70.0..=160.0).step_by(10.0).suffix(" %")).changed() {
                    self.settings.zoom = pct / 100.0;
                    ctx.set_zoom_factor(self.settings.zoom);
                }
                ui.add_space(6.0);
                ui.checkbox(&mut self.settings.scan_on_start, tr("Escanear la red al abrir la app"));
            });
            card(&mut c[1], tr("Acerca de"), |ui| {
                ui.label(RichText::new("RedVisión").size(18.0).strong().color(ACCENT()));
                muted(ui, tf("Versión {}", &[&env!("CARGO_PKG_VERSION")]));
                ui.label(tr("Analizador de red ligero y multiplataforma (Linux, Windows y macOS)."));
                ui.hyperlink("https://github.com/AsturTorQue/Redvision");
            });
        });
        if let Some(m) = &self.settings_msg {
            ui.add_space(6.0);
            muted(ui, m.clone());
        }
    }
}

impl Palette {
    pub fn preview_bg(&self) -> egui::Color32 {
        self.bg
    }
    pub fn preview_card(&self) -> egui::Color32 {
        self.card2
    }
    pub fn preview_accent(&self) -> egui::Color32 {
        self.accent
    }
    pub fn preview_text(&self) -> egui::Color32 {
        self.text
    }
}
