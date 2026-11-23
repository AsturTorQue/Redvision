//! Páginas «Velocidad entre equipos» y «Diagnóstico de la LAN».
use crate::app::NetApp;
use crate::i18n::{tf, tr};
use crate::lanaudit::{self, LanAudit};
use crate::speedtest::{self, SpeedServer, SpeedTest};
use crate::util::*;
use crate::widgets::*;
use eframe::egui::{self, RichText, Ui};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct LanState {
    pub server: Shared<SpeedServer>,
    pub server_stop: Arc<AtomicBool>,
    pub test: Shared<SpeedTest>,
    pub target: String,
    pub port: u16,
    pub secs: u64,
    pub streams: usize,
    pub audit: Shared<LanAudit>,
    pub audit_load: bool,
}

impl Default for LanState {
    fn default() -> Self {
        LanState {
            server: shared(SpeedServer::default()),
            server_stop: Arc::new(AtomicBool::new(false)),
            test: shared(SpeedTest::default()),
            target: String::new(),
            port: speedtest::DEFAULT_PORT,
            secs: 8,
            streams: 4,
            audit: shared(LanAudit::default()),
            audit_load: false,
        }
    }
}

fn mbps(v: Option<f64>) -> String {
    v.map(|x| if x >= 1000.0 { format!("{:.2} Gbps", x / 1000.0) } else { format!("{:.1} Mbps", x) }).unwrap_or_else(|| "—".into())
}

/// Qué significa la velocidad medida en la LAN.
fn speed_hint(v: f64) -> &'static str {
    if v >= 850.0 {
        "Enlace gigabit funcionando a pleno rendimiento."
    } else if v >= 300.0 {
        "Buena velocidad (gigabit con algo de pérdida o Wi-Fi rápido)."
    } else if v >= 80.0 {
        "Velocidad propia de un enlace de 100 Mb/s o de un Wi-Fi medio."
    } else {
        "Velocidad baja: revisa cables, switch o la señal Wi-Fi entre ambos equipos."
    }
}

impl NetApp {
    pub(crate) fn page_speed(&mut self, ui: &mut Ui) {
        page_title(ui, tr("Velocidad entre equipos"), tr("Mide la velocidad real de tu red local entre dos equipos que tengan RedVisión"));
        let local = lock(&self.info).local_ip;
        let (srv_running, srv_port, srv_err, srv_log) = {
            let s = lock(&self.lan.server);
            (s.running, s.port, s.error.clone(), s.log.clone())
        };
        let hosts: Vec<String> = lock(&self.subnet).hosts.iter().filter(|h| Some(h.ip) != local).map(|h| h.ip.to_string()).collect();
        ui.columns(2, |c| {
            card(&mut c[0], tr("1. En el otro equipo: modo servidor"), |ui| {
                muted(ui, tr("Abre RedVisión en el otro equipo y activa aquí el servidor. Ese equipo esperará las pruebas."));
                ui.horizontal(|ui| {
                    ui.label(tr("Puerto:"));
                    ui.add_enabled(!srv_running, egui::DragValue::new(&mut self.lan.port).range(1024..=65535));
                    if srv_running {
                        if danger(ui, tr("Detener servidor")).clicked() {
                            self.lan.server_stop.store(true, Ordering::Relaxed);
                        }
                    } else if primary(ui, tr("Activar servidor")).clicked() {
                        self.lan.server_stop = Arc::new(AtomicBool::new(false));
                        speedtest::start_server(self.lan.server.clone(), self.lan.server_stop.clone(), self.lan.port, ui.ctx().clone());
                    }
                });
                if srv_running {
                    notice(ui, &tf("Servidor activo en {}:{}. Usa esta dirección en el otro equipo.", &[&local.map(|i| i.to_string()).unwrap_or_default(), &srv_port]), GREEN());
                }
                if let Some(e) = srv_err {
                    notice(ui, &e, RED());
                }
                muted(ui, tr("Si no conecta, permite este puerto TCP en el cortafuegos del servidor."));
                for l in srv_log.iter().rev().take(8) {
                    ui.label(RichText::new(l).monospace().size(12.0).color(SUBTLE()));
                }
            });
            card(&mut c[1], tr("2. En este equipo: medir"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr("Servidor:"));
                    ui.add(egui::TextEdit::singleline(&mut self.lan.target).hint_text("192.168.1.20").desired_width(160.0));
                    if !hosts.is_empty() {
                        egui::ComboBox::from_id_salt("speedhosts").selected_text("…").show_ui(ui, |ui| {
                            for h in &hosts {
                                if ui.selectable_label(false, h).clicked() {
                                    self.lan.target = h.clone();
                                }
                            }
                        });
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(tr("Duración:"));
                    ui.add(egui::DragValue::new(&mut self.lan.secs).range(3..=30).suffix(" s"));
                    ui.label(tr("Conexiones en paralelo:"));
                    ui.add(egui::DragValue::new(&mut self.lan.streams).range(1..=8));
                });
                let running = lock(&self.lan.test).running;
                let btn = egui::Button::new(RichText::new(tr("Medir velocidad")).strong().color(ON_ACCENT())).fill(ACCENT());
                if ui.add_enabled(!running && !self.lan.target.trim().is_empty(), btn).clicked() {
                    speedtest::start_client(self.lan.test.clone(), self.lan.target.trim().to_string(), self.lan.port, self.lan.secs, self.lan.streams, ui.ctx().clone());
                }
                muted(ui, tr("También puedes medir contra tu propio equipo (127.0.0.1) para comprobar que funciona."));
            });
        });
        ui.add_space(8.0);
        let (running, phase, lat, down, up, ld, lu, err) = {
            let t = lock(&self.lan.test);
            (t.running, t.phase.clone(), t.latency, t.down, t.up, t.live_down.clone(), t.live_up.clone(), t.error.clone())
        };
        if !running && down.is_none() && err.is_none() {
            return;
        }
        if let Some(e) = &err {
            notice(ui, e, RED());
        }
        if running {
            ui.horizontal(|ui| {
                ui.spinner();
                muted(ui, phase.clone());
            });
        }
        ui.columns(3, |c| {
            stat(&mut c[0], tr("Bajada"), &mbps(down), ACCENT(), tr("el servidor envía a este equipo"));
            stat(&mut c[1], tr("Subida"), &mbps(up), VIOLET(), tr("este equipo envía al servidor"));
            stat(&mut c[2], tr("Latencia"), &lat.map(|l| format!("{:.2} ms", l)).unwrap_or("—".into()), GREEN(), tr("tiempo de conexión TCP"));
        });
        ui.add_space(6.0);
        card(ui, tr("Velocidad durante la prueba"), |ui| {
            ui.columns(2, |c| {
                c[0].label(RichText::new(tr("Bajada")).color(ACCENT()).strong());
                line_chart(&mut c[0], 200.0, &[Series { values: &ld, color: ACCENT(), fill: true }], &|v| format!("{:.0} Mbps", v), 10.0);
                c[1].label(RichText::new(tr("Subida")).color(VIOLET()).strong());
                line_chart(&mut c[1], 200.0, &[Series { values: &lu, color: VIOLET(), fill: true }], &|v| format!("{:.0} Mbps", v), 10.0);
            });
            if let Some(v) = down.or(up) {
                let best = down.unwrap_or(0.0).max(up.unwrap_or(0.0)).max(v);
                notice(ui, tr(speed_hint(best)), if best >= 300.0 { GREEN() } else if best >= 80.0 { AMBER() } else { RED() });
            }
        });
    }

    pub(crate) fn page_lanaudit(&mut self, ui: &mut Ui) {
        page_title(ui, tr("Diagnóstico de la LAN"), tr("Busca las causas habituales de una red local lenta o inestable"));
        let (running, step, prog, findings, facts, score) = {
            let a = lock(&self.lan.audit);
            (a.running, a.step.clone(), a.progress, a.findings.clone(), a.facts.clone(), a.score)
        };
        card(ui, "", |ui| {
            ui.horizontal(|ui| {
                let btn = egui::Button::new(RichText::new(tr("Diagnosticar la red")).strong().color(ON_ACCENT())).fill(ACCENT());
                if ui.add_enabled(!running, btn).clicked() {
                    let info = lock(&self.info).clone();
                    let url = if self.lan.audit_load { Some(self.qoe_url.clone()) } else { None };
                    lanaudit::start(self.lan.audit.clone(), info, url, ui.ctx().clone());
                }
                ui.checkbox(&mut self.lan.audit_load, tr("Incluir prueba de carga (bufferbloat, descarga unos 10 s)"));
            });
            if running {
                ui.add(egui::ProgressBar::new(prog).text(step.clone()).fill(ACCENT_DIM()));
            } else {
                muted(ui, tr("Revisa la dirección, el router, el cable o la señal Wi-Fi, los errores de la interfaz, las rutas, el DNS, la salida a Internet, portales cautivos, la MTU, IPv6 y conflictos ARP."));
            }
        });
        if score.is_none() && findings.is_empty() {
            return;
        }
        ui.add_space(6.0);
        ui.columns(2, |c| {
            card(&mut c[0], tr("Salud de la red local"), |ui| {
                ui.horizontal(|ui| {
                    gauge(ui, score.map(|s| s as f64), tr("de 100"), 130.0);
                    ui.vertical(|ui| {
                        ui.add_space(10.0);
                        for s in Sev::all() {
                            let n = findings.iter().filter(|f| f.sev == s).count();
                            if n > 0 {
                                ui.horizontal(|ui| {
                                    badge(ui, s.label(), sev_color(s));
                                    ui.label(tf("{} hallazgos", &[&n]));
                                });
                            }
                        }
                    });
                });
            });
            card(&mut c[1], tr("Datos de la red"), |ui| {
                egui::Grid::new("lanfacts").num_columns(2).spacing([18.0, 3.0]).striped(true).show(ui, |ui| {
                    for (k, v) in &facts {
                        ui.label(RichText::new(k).color(MUTED()));
                        ui.label(RichText::new(v).strong());
                        ui.end_row();
                    }
                });
            });
        });
        ui.add_space(6.0);
        card(ui, tr("Problemas encontrados"), |ui| {
            for f in &findings {
                egui::Frame::new().fill(CARD2()).corner_radius(8.0).inner_margin(10.0).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        badge(ui, f.sev.label(), sev_color(f.sev));
                        ui.label(RichText::new(&f.title).strong());
                    });
                    ui.label(RichText::new(&f.detail).size(12.5));
                    if !f.fix.is_empty() {
                        ui.label(RichText::new(tf("Cómo arreglarlo: {}", &[&f.fix])).color(GREEN()).size(12.5));
                    }
                });
                ui.add_space(4.0);
            }
        });
    }
}

use crate::ids::Sev;
