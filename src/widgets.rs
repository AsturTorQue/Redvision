//! Estilo visual y piezas de interfaz reutilizables: tarjetas, cifras, gráficas y filas de tabla.
use crate::ids::Sev;
use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Stroke, StrokeKind, Ui, Vec2};
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------- temas

pub struct Palette {
    pub name: &'static str,
    pub dark: bool,
    pub(crate) bg: Color32,
    pub(crate) panel: Color32,
    pub(crate) card: Color32,
    pub(crate) card2: Color32,
    pub(crate) border: Color32,
    pub(crate) text: Color32,
    pub(crate) muted: Color32,
    pub(crate) subtle: Color32,
    pub(crate) chart_bg: Color32,
    pub(crate) grid: Color32,
    pub(crate) sel: Color32,
    pub(crate) hover: Color32,
    pub(crate) stripe: Color32,
    pub(crate) accent: Color32,
    pub(crate) accent_bg: Color32,
    pub(crate) accent_dim: Color32,
    pub(crate) on_accent: Color32,
    pub(crate) green: Color32,
    pub(crate) amber: Color32,
    pub(crate) orange: Color32,
    pub(crate) red: Color32,
    pub(crate) violet: Color32,
    pub(crate) blue: Color32,
}

const fn c(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

pub const THEMES: &[Palette] = &[
    Palette {
        name: "Oscuro",
        dark: true,
        bg: c(11, 17, 26), panel: c(15, 23, 34), card: c(21, 31, 45), card2: c(27, 39, 56), border: c(38, 52, 72),
        text: c(226, 232, 240), muted: c(140, 155, 175), subtle: c(200, 210, 222), chart_bg: c(12, 19, 29), grid: c(30, 42, 58),
        sel: c(14, 61, 79), hover: c(30, 44, 62), stripe: c(18, 27, 39),
        accent: c(34, 211, 238), accent_bg: c(8, 51, 68), accent_dim: c(14, 116, 144), on_accent: c(8, 20, 28),
        green: c(52, 211, 153), amber: c(251, 191, 36), orange: c(251, 146, 60), red: c(248, 113, 113), violet: c(167, 139, 250), blue: c(96, 165, 250),
    },
    Palette {
        name: "Claro",
        dark: false,
        bg: c(236, 240, 245), panel: c(246, 248, 251), card: c(255, 255, 255), card2: c(236, 241, 247), border: c(210, 218, 228),
        text: c(22, 30, 42), muted: c(96, 110, 130), subtle: c(48, 60, 78), chart_bg: c(244, 247, 251), grid: c(222, 228, 236),
        sel: c(204, 238, 246), hover: c(228, 236, 245), stripe: c(247, 249, 252),
        accent: c(8, 145, 178), accent_bg: c(207, 242, 250), accent_dim: c(125, 211, 232), on_accent: c(255, 255, 255),
        green: c(5, 150, 105), amber: c(202, 138, 4), orange: c(234, 88, 12), red: c(220, 38, 38), violet: c(124, 58, 237), blue: c(37, 99, 235),
    },
    Palette {
        name: "Medianoche",
        dark: true,
        bg: c(13, 10, 28), panel: c(19, 15, 40), card: c(28, 22, 56), card2: c(37, 30, 72), border: c(56, 46, 98),
        text: c(232, 228, 248), muted: c(150, 140, 185), subtle: c(205, 198, 232), chart_bg: c(16, 12, 34), grid: c(40, 33, 72),
        sel: c(52, 36, 104), hover: c(40, 32, 80), stripe: c(24, 19, 48),
        accent: c(192, 132, 252), accent_bg: c(46, 24, 84), accent_dim: c(109, 64, 170), on_accent: c(20, 10, 36),
        green: c(74, 222, 128), amber: c(250, 204, 21), orange: c(251, 146, 60), red: c(251, 113, 133), violet: c(129, 140, 248), blue: c(96, 165, 250),
    },
    Palette {
        name: "Terminal",
        dark: true,
        bg: c(0, 0, 0), panel: c(5, 9, 5), card: c(10, 18, 10), card2: c(16, 28, 16), border: c(28, 60, 28),
        text: c(190, 255, 190), muted: c(90, 160, 90), subtle: c(150, 220, 150), chart_bg: c(3, 8, 3), grid: c(18, 40, 18),
        sel: c(18, 64, 18), hover: c(16, 40, 16), stripe: c(8, 14, 8),
        accent: c(57, 255, 20), accent_bg: c(12, 48, 8), accent_dim: c(30, 120, 20), on_accent: c(0, 0, 0),
        green: c(57, 255, 20), amber: c(255, 214, 10), orange: c(255, 160, 40), red: c(255, 80, 80), violet: c(160, 255, 200), blue: c(80, 220, 255),
    },
];

static THEME: AtomicUsize = AtomicUsize::new(0);

pub fn set_theme(i: usize) {
    THEME.store(i.min(THEMES.len() - 1), Ordering::Relaxed);
}
pub fn theme() -> usize {
    THEME.load(Ordering::Relaxed)
}
fn pal() -> &'static Palette {
    &THEMES[theme()]
}

macro_rules! colors {
    ($($f:ident => $n:ident),* $(,)?) => { $( #[allow(non_snake_case)] pub fn $n() -> Color32 { pal().$f } )* };
}
colors! {
    bg => BG, panel => PANEL, card => CARD, card2 => CARD2, border => BORDER, text => TEXT, muted => MUTED,
    subtle => SUBTLE, chart_bg => CHART_BG, grid => GRID, sel => SEL, hover => HOVER, stripe => STRIPE,
    accent => ACCENT, accent_bg => ACCENT_BG, accent_dim => ACCENT_DIM, on_accent => ON_ACCENT,
    green => GREEN, amber => AMBER, orange => ORANGE, red => RED, violet => VIOLET, blue => BLUE,
}

pub fn apply_style(ctx: &egui::Context) {
    let mut v = if pal().dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = PANEL();
    v.window_fill = CARD();
    v.extreme_bg_color = CHART_BG();
    v.faint_bg_color = STRIPE();
    v.override_text_color = Some(TEXT());
    v.selection.bg_fill = ACCENT_DIM();
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT());
    v.hyperlink_color = ACCENT();
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER());
    v.widgets.inactive.weak_bg_fill = CARD2();
    v.widgets.inactive.bg_fill = CARD2();
    v.widgets.hovered.weak_bg_fill = HOVER();
    v.widgets.active.weak_bg_fill = ACCENT_DIM();
    for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        w.corner_radius = 6.0.into();
    }
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(8.0, 7.0);
        s.spacing.button_padding = Vec2::new(10.0, 5.0);
        s.text_styles.insert(egui::TextStyle::Body, FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Button, FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Heading, FontId::proportional(22.0));
        s.text_styles.insert(egui::TextStyle::Monospace, FontId::monospace(12.5));
    });
}

pub fn sev_color(s: Sev) -> Color32 {
    match s {
        Sev::Critical => Color32::from_rgb(239, 68, 68),
        Sev::High => ORANGE(),
        Sev::Medium => AMBER(),
        Sev::Low => BLUE(),
        Sev::Info => MUTED(),
    }
}

pub fn score_color(v: f64) -> Color32 {
    if v >= 85.0 {
        GREEN()
    } else if v >= 70.0 {
        Color32::from_rgb(163, 230, 53)
    } else if v >= 50.0 {
        AMBER()
    } else {
        RED()
    }
}

pub fn proto_color(p: &str) -> Color32 {
    match p {
        "TCP" => BLUE(),
        "UDP" => VIOLET(),
        "DNS" | "mDNS" | "LLMNR" => Color32::from_rgb(45, 212, 191),
        "HTTP" => GREEN(),
        "TLS" | "HTTPS" | "QUIC" => Color32::from_rgb(129, 140, 248),
        "ARP" => AMBER(),
        "ICMP" | "ICMPv6" => Color32::from_rgb(244, 114, 182),
        "DHCP" => ORANGE(),
        "SSH" => Color32::from_rgb(190, 242, 100),
        _ => MUTED(),
    }
}

pub fn page_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.add_space(4.0);
    ui.label(RichText::new(title).size(24.0).strong().color(TEXT()));
    ui.label(RichText::new(subtitle).color(MUTED()));
    ui.add_space(8.0);
}

pub fn card<R>(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD())
        .stroke(Stroke::new(1.0_f32, BORDER()))
        .corner_radius(10.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if !title.is_empty() {
                ui.label(RichText::new(title).strong().size(15.5).color(TEXT()));
                ui.add_space(4.0);
            }
            add(ui)
        })
        .inner
}

/// Cifra grande con su etiqueta, para los paneles de resumen.
pub fn stat(ui: &mut Ui, label: &str, value: &str, color: Color32, sub: &str) {
    egui::Frame::new()
        .fill(CARD())
        .stroke(Stroke::new(1.0_f32, BORDER()))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(label).color(MUTED()).size(12.5));
            ui.label(RichText::new(value).color(color).size(24.0).strong());
            if !sub.is_empty() {
                ui.label(RichText::new(sub).color(MUTED()).size(12.0));
            }
        });
}

pub fn badge(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.6)))
        .corner_radius(9.0)
        .inner_margin(egui::Margin::symmetric(7, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).size(12.0).strong());
        });
}

pub fn primary(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).color(ON_ACCENT()).strong()).fill(ACCENT()))
}

pub fn danger(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE).strong()).fill(Color32::from_rgb(185, 28, 28)))
}

pub fn muted(ui: &mut Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).color(MUTED()));
}

pub fn notice(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.5)))
        .corner_radius(8.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(color));
        });
}

pub struct Series<'a> {
    pub values: &'a [Option<f64>],
    pub color: Color32,
    pub fill: bool,
}

/// Gráfica de líneas con rejilla. Los huecos (None) se marcan en rojo abajo (pérdidas).
pub fn line_chart(ui: &mut Ui, height: f32, series: &[Series], fmt: &dyn Fn(f64) -> String, min_max: f64) {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, height), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 8.0, CHART_BG());
    let plot = Rect::from_min_max(rect.min + Vec2::new(58.0, 10.0), rect.max - Vec2::new(10.0, 18.0));
    let n = series.iter().map(|s| s.values.len()).max().unwrap_or(0);
    let mut maxv = series.iter().flat_map(|s| s.values.iter().flatten()).cloned().fold(0.0, f64::max);
    maxv = (maxv * 1.15).max(min_max);
    for i in 0..=4 {
        let y = plot.bottom() - plot.height() * i as f32 / 4.0;
        p.line_segment([Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)], Stroke::new(1.0_f32, GRID()));
        p.text(Pos2::new(plot.left() - 6.0, y), Align2::RIGHT_CENTER, fmt(maxv * i as f64 / 4.0), FontId::proportional(10.5), MUTED());
    }
    if n < 2 {
        p.text(plot.center(), Align2::CENTER_CENTER, "Esperando datos…", FontId::proportional(13.0), MUTED());
        return;
    }
    let x_of = |i: usize| plot.left() + plot.width() * i as f32 / (n - 1) as f32;
    let y_of = |v: f64| plot.bottom() - plot.height() * (v / maxv) as f32;
    for s in series {
        let off = n - s.values.len();
        let mut seg: Vec<Pos2> = Vec::new();
        let flush = |seg: &mut Vec<Pos2>| {
            if seg.len() >= 2 {
                if s.fill {
                    for w in seg.windows(2) {
                        let poly = vec![w[0], w[1], Pos2::new(w[1].x, plot.bottom()), Pos2::new(w[0].x, plot.bottom())];
                        p.add(egui::Shape::convex_polygon(poly, s.color.gamma_multiply(0.12), Stroke::NONE));
                    }
                }
                p.line(seg.clone(), Stroke::new(1.8_f32, s.color));
            } else if seg.len() == 1 {
                p.circle_filled(seg[0], 2.0, s.color);
            }
            seg.clear();
        };
        for (i, v) in s.values.iter().enumerate() {
            match v {
                Some(v) => seg.push(Pos2::new(x_of(off + i), y_of(*v))),
                None => {
                    flush(&mut seg);
                    let x = x_of(off + i);
                    p.line_segment([Pos2::new(x, plot.bottom() - 6.0), Pos2::new(x, plot.bottom())], Stroke::new(2.0_f32, RED()));
                }
            }
        }
        flush(&mut seg);
    }
    if let Some(pos) = resp.hover_pos() {
        if plot.contains(pos) {
            let i = (((pos.x - plot.left()) / plot.width()) * (n - 1) as f32).round() as usize;
            p.line_segment([Pos2::new(x_of(i), plot.top()), Pos2::new(x_of(i), plot.bottom())], Stroke::new(1.0_f32, BORDER()));
            let mut txt = Vec::new();
            for s in series {
                let off = n - s.values.len();
                if i >= off {
                    txt.push(match s.values[i - off] {
                        Some(v) => fmt(v),
                        None => "perdido".into(),
                    });
                }
            }
            p.text(Pos2::new(x_of(i) + 6.0, plot.top() + 4.0), Align2::LEFT_TOP, txt.join(" / "), FontId::proportional(12.0), TEXT());
        }
    }
}

pub fn sparkline(ui: &mut Ui, values: &[Option<f64>], color: Color32, w: f32, h: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, h), Sense::hover());
    let p = ui.painter_at(rect);
    let maxv = values.iter().flatten().cloned().fold(0.0, f64::max).max(1e-9);
    let n = values.len();
    if n < 2 {
        return;
    }
    let pts: Vec<Pos2> = values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|v| Pos2::new(rect.left() + rect.width() * i as f32 / (n - 1) as f32, rect.bottom() - rect.height() * (v / maxv) as f32 * 0.9)))
        .collect();
    if pts.len() > 1 {
        p.line(pts, Stroke::new(1.5_f32, color));
    }
    for (i, v) in values.iter().enumerate() {
        if v.is_none() {
            let x = rect.left() + rect.width() * i as f32 / (n - 1) as f32;
            p.line_segment([Pos2::new(x, rect.bottom() - 4.0), Pos2::new(x, rect.bottom())], Stroke::new(1.5_f32, RED()));
        }
    }
}

/// Barra horizontal de proporción con etiqueta.
pub fn bar(ui: &mut Ui, label: &str, value_txt: &str, frac: f32, color: Color32) {
    ui.horizontal(|ui| {
        let lw = 150.0;
        ui.add_sized([lw, 18.0], egui::Label::new(RichText::new(label).color(TEXT())).truncate());
        let w = (ui.available_width() - 110.0).max(40.0);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 14.0), Sense::hover());
        ui.painter().rect_filled(rect, 4.0, GRID());
        let mut r = rect;
        r.set_width(rect.width() * frac.clamp(0.0, 1.0));
        ui.painter().rect_filled(r, 4.0, color);
        ui.label(RichText::new(value_txt).color(MUTED()).size(12.5));
    });
}

/// Indicador circular de puntuación 0-100.
pub fn gauge(ui: &mut Ui, value: Option<f64>, label: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter_at(rect);
    let c = rect.center();
    let r = size * 0.42;
    let start = std::f32::consts::PI * 0.75;
    let sweep = std::f32::consts::PI * 1.5;
    let arc = |frac: f32| -> Vec<Pos2> {
        (0..=48).map(|i| {
            let a = start + sweep * frac * i as f32 / 48.0;
            Pos2::new(c.x + r * a.cos(), c.y + r * a.sin())
        }).collect()
    };
    p.line(arc(1.0), Stroke::new(size * 0.08, GRID()));
    match value {
        Some(v) => {
            let col = score_color(v);
            p.line(arc((v / 100.0) as f32), Stroke::new(size * 0.08, col));
            p.text(c, Align2::CENTER_CENTER, format!("{:.0}", v), FontId::proportional(size * 0.26), col);
        }
        None => {
            p.text(c, Align2::CENTER_CENTER, "—", FontId::proportional(size * 0.26), MUTED());
        }
    }
    p.text(Pos2::new(c.x, rect.bottom() - size * 0.08), Align2::CENTER_CENTER, label, FontId::proportional(11.5), MUTED());
}

/// Fila de tabla dibujada a mano (rápida para miles de filas).
pub fn table_row(ui: &mut Ui, cols: &[(f32, String, Color32)], selected: bool, striped: bool) -> egui::Response {
    let h = 22.0;
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let p = ui.painter();
    if selected {
        p.rect_filled(rect, 3.0, SEL());
    } else if resp.hovered() {
        p.rect_filled(rect, 3.0, HOVER());
    } else if striped {
        p.rect_filled(rect, 0.0, STRIPE());
    }
    let mut x = rect.left() + 6.0;
    let n = cols.len();
    for (i, (cw, text, color)) in cols.iter().enumerate() {
        let width = if i + 1 == n { rect.right() - x } else { *cw };
        let cell = Rect::from_min_size(Pos2::new(x, rect.top()), Vec2::new(width - 6.0, h));
        ui.painter_at(cell).text(Pos2::new(x, rect.center().y), Align2::LEFT_CENTER, text, FontId::proportional(13.0), *color);
        x += width;
    }
    resp
}

pub fn table_header(ui: &mut Ui, cols: &[(f32, &str)]) {
    let h = 24.0;
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, h), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 4.0, CARD2());
    let mut x = rect.left() + 6.0;
    for (cw, t) in cols {
        p.text(Pos2::new(x, rect.center().y), Align2::LEFT_CENTER, *t, FontId::proportional(12.5), MUTED());
        x += cw;
    }
    let _ = StrokeKind::Inside;
}
