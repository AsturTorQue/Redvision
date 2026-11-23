//! Página «Analizador Wi-Fi».
use crate::app::NetApp;
use crate::i18n::{tf, tr};
use crate::util::*;
use crate::widgets::*;
use crate::wifi::{self, Ap, Band};
use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2};

const PALETTE: &[Color32] = &[
    Color32::from_rgb(96, 165, 250),
    Color32::from_rgb(52, 211, 153),
    Color32::from_rgb(251, 191, 36),
    Color32::from_rgb(244, 114, 182),
    Color32::from_rgb(167, 139, 250),
    Color32::from_rgb(251, 146, 60),
    Color32::from_rgb(45, 212, 191),
    Color32::from_rgb(248, 113, 113),
    Color32::from_rgb(163, 230, 53),
    Color32::from_rgb(129, 140, 248),
];

fn color_for(ssid: &str) -> Color32 {
    let h = ssid.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    PALETTE[h as usize % PALETTE.len()]
}

fn quality(dbm: i32) -> (&'static str, Color32) {
    if dbm >= -55 {
        ("Excelente", GREEN())
    } else if dbm >= -67 {
        ("Buena", Color32::from_rgb(163, 230, 53))
    } else if dbm >= -75 {
        ("Aceptable", AMBER())
    } else {
        ("Mala", RED())
    }
}

/// Espectro de canales: cada red es una «campana» centrada en su canal y tan alta como su señal.
fn spectrum(ui: &mut Ui, aps: &[&Ap], band: Band, current: Option<&str>) {
    let chans: &[u32] = if band == Band::G24 { wifi::CH24 } else { wifi::CH5 };
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 230.0), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 8.0, CHART_BG());
    let plot = Rect::from_min_max(rect.min + Vec2::new(52.0, 12.0), rect.max - Vec2::new(12.0, 26.0));
    // eje X: posición de cada canal
    let (lo, hi) = if band == Band::G24 { (-1.0f32, 15.0f32) } else { (-0.8f32, chans.len() as f32 - 0.2) };
    let x_of = |slot: f32| plot.left() + plot.width() * (slot - lo) / (hi - lo);
    let slot_of = |ch: u32| -> Option<f32> {
        if band == Band::G24 {
            Some(ch as f32)
        } else {
            chans.iter().position(|c| *c == ch).map(|i| i as f32)
        }
    };
    let y_of = |dbm: f32| plot.bottom() - plot.height() * ((dbm + 100.0) / 70.0).clamp(0.0, 1.0);
    for d in [-90, -80, -70, -60, -50, -40, -30] {
        let y = y_of(d as f32);
        p.line_segment([Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)], Stroke::new(1.0_f32, GRID()));
        p.text(Pos2::new(plot.left() - 6.0, y), Align2::RIGHT_CENTER, format!("{} dBm", d), FontId::proportional(10.0), MUTED());
    }
    let slot_w = plot.width() / (hi - lo);
    for (i, ch) in chans.iter().enumerate() {
        // Con poco espacio, un número sí y otro no
        if slot_w < 30.0 && i % 2 == 1 {
            continue;
        }
        if let Some(s) = slot_of(*ch) {
            p.text(Pos2::new(x_of(s), plot.bottom() + 12.0), Align2::CENTER_CENTER, ch.to_string(), FontId::proportional(10.5), MUTED());
        }
    }
    let mut labels_at: Vec<(u32, usize)> = Vec::new();
    let half = if band == Band::G24 { 2.0 } else { 0.45 };
    let mut shown = 0;
    for ap in aps.iter().filter(|a| a.band == band) {
        let Some(s) = slot_of(ap.channel) else { continue };
        let col = color_for(&ap.ssid);
        let top = y_of(ap.dbm as f32);
        let pts: Vec<Pos2> = (0..=24)
            .map(|i| {
                let t = -1.0 + i as f32 / 12.0;
                Pos2::new(x_of(s + t * half), plot.bottom() - (plot.bottom() - top) * (1.0 - t * t))
            })
            .collect();
        let mine = current.is_some_and(|c| c == ap.ssid) && ap.in_use;
        p.add(egui::Shape::convex_polygon(pts.clone(), col.gamma_multiply(if mine { 0.35 } else { 0.12 }), Stroke::NONE));
        p.line(pts, Stroke::new(if mine { 3.0_f32 } else { 1.5 }, col));
        let name = if ap.ssid.is_empty() { tr("(oculta)").to_string() } else { ap.ssid.chars().take(16).collect() };
        // Las redes del mismo canal apilan sus nombres para no taparse
        let k = match labels_at.iter_mut().find(|(c, _)| *c == ap.channel) {
            Some(e) => {
                e.1 += 1;
                e.1
            }
            None => {
                labels_at.push((ap.channel, 0));
                0
            }
        };
        let highest = aps.iter().filter(|a| a.band == band && a.channel == ap.channel).map(|a| a.dbm).max().unwrap_or(ap.dbm);
        let lx = x_of(s).max(plot.left() + 45.0);
        p.text(Pos2::new(lx, y_of(highest as f32) - 8.0 - 14.0 * k as f32), Align2::CENTER_BOTTOM, name, FontId::proportional(11.0), col);
        shown += 1;
    }
    if shown == 0 {
        p.text(plot.center(), Align2::CENTER_CENTER, tr("Ninguna red en esta banda"), FontId::proportional(13.0), MUTED());
    }
}

impl NetApp {
    pub(crate) fn page_wifi(&mut self, ui: &mut Ui) {
        page_title(ui, tr("Analizador Wi-Fi"), tr("Redes cercanas, tu conexión, canales libres y riesgos de seguridad"));
        let (running, last, history) = {
            let s = lock(&self.wifi);
            (s.running, s.last.clone(), s.history.iter().cloned().collect::<Vec<_>>())
        };
        // Primera búsqueda automática y actualización periódica
        let age = last.as_ref().map(|r| now_secs() - r.time).unwrap_or(f64::MAX);
        if !running && (last.is_none() || (self.wifi_auto && age > 10.0)) {
            wifi::start_scan(self.wifi.clone(), last.is_some(), ui.ctx().clone());
        }
        if self.wifi_auto {
            ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
        }
        card(ui, "", |ui| {
            ui.horizontal(|ui| {
                let btn = egui::Button::new(RichText::new(tr("Buscar redes Wi-Fi")).strong().color(ON_ACCENT())).fill(ACCENT());
                if ui.add_enabled(!running, btn).clicked() {
                    wifi::start_scan(self.wifi.clone(), true, ui.ctx().clone());
                }
                ui.checkbox(&mut self.wifi_auto, tr("Actualizar cada 10 s"));
                if running {
                    ui.spinner();
                    muted(ui, tr("Buscando…"));
                }
                if let Some(r) = &last {
                    muted(ui, tf("{} redes · fuente: {} · {}", &[&r.aps.len(), &r.source, &fmt_clock(r.time)]));
                }
            });
        });
        let Some(r) = last else { return };
        if let Some(e) = &r.error {
            ui.add_space(4.0);
            notice(ui, e, AMBER());
        }
        if r.ifaces.is_empty() && r.aps.is_empty() {
            ui.add_space(4.0);
            notice(ui, tr("Este equipo no tiene tarjeta Wi-Fi (o está desactivada). Con una tarjeta o un adaptador USB Wi-Fi verás aquí las redes cercanas."), BLUE());
            return;
        }
        ui.add_space(6.0);
        let cur_ssid = r.current.as_ref().map(|c| c.ssid.clone());
        ui.columns(2, |c| {
            card(&mut c[0], tr("Tu conexión Wi-Fi"), |ui| match &r.current {
                None => muted(ui, tr("No estás conectado a ninguna red Wi-Fi.")),
                Some(l) => {
                    egui::Grid::new("wifilink").num_columns(2).spacing([18.0, 4.0]).show(ui, |ui| {
                        let rows = [
                            (tr("Red (SSID)"), if l.ssid.is_empty() { tr("(oculta)").to_string() } else { l.ssid.clone() }),
                            ("BSSID", format!("{} {}", l.bssid, vendor(&l.bssid))),
                            (tr("Canal"), format!("{} · {}", l.channel, l.band.label())),
                            (tr("Velocidad del enlace"), if l.rate.is_empty() { "—".into() } else { l.rate.clone() }),
                            (tr("Interfaz"), l.iface.clone()),
                        ];
                        for (k, v) in rows {
                            ui.label(RichText::new(k).color(MUTED()));
                            ui.label(RichText::new(v).strong());
                            ui.end_row();
                        }
                        if let Some(d) = l.dbm {
                            let (q, col) = quality(d);
                            ui.label(RichText::new(tr("Señal Wi-Fi")).color(MUTED()));
                            ui.label(RichText::new(format!("{} dBm · {}", d, tr(q))).strong().color(col));
                            ui.end_row();
                        }
                    });
                    if history.iter().flatten().count() > 1 {
                        ui.add_space(4.0);
                        muted(ui, tr("Señal en el tiempo"));
                        let h: Vec<Option<f64>> = history.iter().map(|x| x.map(|v| v)).collect();
                        line_chart(ui, 110.0, &[Series { values: &h, color: ACCENT(), fill: true }], &|v| format!("{:.0} dBm", v - 100.0), 60.0);
                    }
                }
            });
            card(&mut c[1], tr("Canales recomendados"), |ui| {
                for band in [Band::G24, Band::G5] {
                    let n = r.aps.iter().filter(|a| a.band == band).count();
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(band.label()).strong().color(ACCENT()));
                        muted(ui, tf("{} redes", &[&n]));
                        if let Some(b) = wifi::best_channel(&r.aps, band) {
                            ui.label(RichText::new(tf("canal más libre: {}", &[&b])).strong().color(GREEN()));
                        }
                    });
                    let cong = wifi::congestion(&r.aps, band);
                    let maxv = cong.iter().map(|x| x.1).fold(1.0, f64::max);
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 46.0), Sense::hover());
                    let p = ui.painter_at(rect);
                    let w = rect.width() / cong.len() as f32;
                    for (i, (ch, v)) in cong.iter().enumerate() {
                        let x = rect.left() + w * i as f32;
                        let h = (rect.height() - 14.0) * (*v / maxv) as f32;
                        let col = if *v < 0.5 { GREEN() } else if *v < 1.5 { AMBER() } else { RED() };
                        p.rect_filled(Rect::from_min_max(Pos2::new(x + 1.0, rect.bottom() - 14.0 - h.max(2.0)), Pos2::new(x + w - 1.0, rect.bottom() - 14.0)), 2.0, col);
                        p.text(Pos2::new(x + w / 2.0, rect.bottom() - 6.0), Align2::CENTER_CENTER, ch.to_string(), FontId::proportional(9.5), MUTED());
                    }
                    ui.add_space(4.0);
                }
                muted(ui, tr("En 2.4 GHz usa solo los canales 1, 6 u 11: son los únicos que no se solapan."));
            });
        });
        ui.add_space(6.0);
        let aps: Vec<&Ap> = r.aps.iter().collect();
        ui.columns(2, |c| {
            card(&mut c[0], tr("Espectro 2.4 GHz"), |ui| spectrum(ui, &aps, Band::G24, cur_ssid.as_deref()));
            card(&mut c[1], tr("Espectro 5 GHz"), |ui| spectrum(ui, &aps, Band::G5, cur_ssid.as_deref()));
        });
        ui.add_space(6.0);
        let finds = wifi::findings(&r);
        if !finds.is_empty() {
            card(ui, tr("Seguridad y problemas de la Wi-Fi"), |ui| {
                for f in &finds {
                    ui.horizontal(|ui| {
                        badge(ui, f.sev.label(), sev_color(f.sev));
                        ui.label(RichText::new(&f.title).strong());
                    });
                    ui.label(RichText::new(&f.detail).size(12.5).color(SUBTLE()));
                    if !f.fix.is_empty() {
                        ui.label(RichText::new(tf("Cómo arreglarlo: {}", &[&f.fix])).color(GREEN()).size(12.5));
                    }
                    ui.add_space(3.0);
                }
            });
            ui.add_space(6.0);
        }
        card(ui, tr("Redes cercanas"), |ui| {
            if ui.button(format!("⬇ {}", tr("Exportar CSV"))).clicked() {
                let rows = r
                    .aps
                    .iter()
                    .map(|a| vec![a.ssid.clone(), a.bssid.clone(), vendor(&a.bssid), a.channel.to_string(), a.band.label().into(), a.dbm.to_string(), a.security.clone()])
                    .collect();
                self.export("wifi", &["Red (SSID)", "BSSID", "Fabricante", "Canal", "Banda", "dBm", "Seguridad"], rows);
            }
            self.export_notice(ui);
            table_header(ui, &[(220.0, tr("Red (SSID)")), (160.0, "BSSID"), (150.0, tr("Fabricante")), (70.0, tr("Canal")), (80.0, tr("Banda")), (170.0, tr("Señal")), (200.0, tr("Seguridad"))]);
            for (i, a) in r.aps.iter().enumerate() {
                let (q, col) = quality(a.dbm);
                let bars = format!("{}%", a.pct());
                let row = [
                    (220.0, if a.ssid.is_empty() { tr("(oculta)").to_string() } else { a.ssid.clone() }, if a.in_use { ACCENT() } else { TEXT() }),
                    (160.0, a.bssid.clone(), MUTED()),
                    (150.0, vendor(&a.bssid), SUBTLE()),
                    (70.0, a.channel.to_string(), TEXT()),
                    (80.0, a.band.label().to_string(), SUBTLE()),
                    (170.0, format!("{} {} dBm · {}", bars, a.dbm, tr(q)), col),
                    (200.0, if a.open() { tr("Abierta").to_string() } else { a.security.clone() }, if a.open() { RED() } else { SUBTLE() }),
                ];
                table_row(ui, &row, a.in_use, i % 2 == 1);
            }
        });
    }
}
