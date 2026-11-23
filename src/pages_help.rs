//! Página «Manual de uso»: muestra docs/MANUAL.*.md con índice, buscador y secciones plegables.
use crate::app::NetApp;
use crate::i18n::{lang, tf, tr};
use crate::widgets::*;
use eframe::egui::{self, text::LayoutJob, Color32, FontId, RichText, TextFormat, Ui};

const MANUAL_ES: &str = include_str!("../docs/MANUAL.es.md");
const MANUAL_EN: &str = include_str!("../docs/MANUAL.en.md");

struct Section<'a> {
    title: &'a str,
    body: Vec<&'a str>,
}

fn parse(md: &str) -> (&str, Vec<Section<'_>>) {
    let mut title = "";
    let mut out: Vec<Section> = Vec::new();
    for line in md.lines() {
        if let Some(t) = line.strip_prefix("# ") {
            title = t.trim();
        } else if let Some(t) = line.strip_prefix("## ") {
            out.push(Section { title: t.trim(), body: Vec::new() });
        } else if let Some(s) = out.last_mut() {
            s.body.push(line);
        }
    }
    (title, out)
}

/// Texto con **negrita** y `código` en línea.
fn inline(ui: &mut Ui, text: &str, size: f32, color: Color32) {
    let mut job = LayoutJob::default();
    job.wrap.max_width = ui.available_width();
    let (mut bold, mut code) = (false, false);
    let mut buf = String::new();
    let flush = |job: &mut LayoutJob, buf: &mut String, bold: bool, code: bool| {
        if buf.is_empty() {
            return;
        }
        let fmt = TextFormat {
            font_id: if code { FontId::monospace(size - 1.0) } else { FontId::proportional(size) },
            color: if code { ACCENT() } else if bold { TEXT() } else { color },
            background: if code { CARD2() } else { Color32::TRANSPARENT },
            ..Default::default()
        };
        job.append(buf, 0.0, fmt);
        buf.clear();
    };
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' && chars.peek() == Some(&'*') && !code {
            chars.next();
            flush(&mut job, &mut buf, bold, code);
            bold = !bold;
        } else if c == '`' {
            flush(&mut job, &mut buf, bold, code);
            code = !code;
        } else {
            buf.push(c);
        }
    }
    flush(&mut job, &mut buf, bold, code);
    ui.label(job);
}

fn render(ui: &mut Ui, body: &[&str]) {
    let mut para = String::new();
    let end_para = |ui: &mut Ui, para: &mut String| {
        if !para.trim().is_empty() {
            inline(ui, para.trim(), 14.5, SUBTLE());
            ui.add_space(4.0);
        }
        para.clear();
    };
    for line in body {
        let l = line.trim_end();
        if l.trim().is_empty() {
            end_para(ui, &mut para);
        } else if let Some(t) = l.strip_prefix("### ") {
            end_para(ui, &mut para);
            ui.add_space(6.0);
            ui.label(RichText::new(t).size(16.0).strong().color(ACCENT()));
        } else if let Some(t) = l.strip_prefix("> ") {
            end_para(ui, &mut para);
            egui::Frame::new().fill(AMBER().gamma_multiply(0.12)).corner_radius(6.0).inner_margin(8.0).show(ui, |ui| {
                ui.set_width(ui.available_width());
                inline(ui, t, 14.0, AMBER());
            });
            ui.add_space(4.0);
        } else if let Some(t) = l.trim_start().strip_prefix("- ") {
            end_para(ui, &mut para);
            ui.horizontal_top(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("•").color(ACCENT()));
                inline(ui, t, 14.5, SUBTLE());
            });
        } else if let Some((n, t)) = l.split_once(". ").filter(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) {
            end_para(ui, &mut para);
            ui.horizontal_top(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new(format!("{}.", n)).color(ACCENT()).strong());
                inline(ui, t, 14.5, SUBTLE());
            });
        } else {
            if !para.is_empty() {
                para.push(' ');
            }
            para.push_str(l.trim());
        }
    }
    end_para(ui, &mut para);
}

impl NetApp {
    pub(crate) fn page_help(&mut self, ui: &mut Ui) {
        let md = if lang() == 0 { MANUAL_ES } else { MANUAL_EN };
        let (title, sections) = parse(md);
        page_title(ui, tr("Manual de uso"), tr("Cómo usar cada parte de RedVisión, paso a paso"));
        if lang() >= 2 {
            notice(ui, tr("El manual completo está disponible en español e inglés; se muestra la versión en inglés."), BLUE());
            ui.add_space(4.0);
        }
        ui.horizontal(|ui| {
            ui.label(tr("Buscar en el manual:"));
            ui.add(egui::TextEdit::singleline(&mut self.help_search).hint_text("Wi-Fi, pcap, MTU…").desired_width(260.0));
            if !self.help_search.is_empty() && ui.small_button("✖").clicked() {
                self.help_search.clear();
            }
        });
        let q = self.help_search.trim().to_lowercase();
        let visible: Vec<usize> = sections
            .iter()
            .enumerate()
            .filter(|(_, s)| q.is_empty() || s.title.to_lowercase().contains(&q) || s.body.iter().any(|l| l.to_lowercase().contains(&q)))
            .map(|(i, _)| i)
            .collect();
        ui.add_space(4.0);
        card(ui, tr("Índice"), |ui| {
            ui.horizontal_wrapped(|ui| {
                for &i in &visible {
                    if ui.small_button(sections[i].title).clicked() {
                        self.help_jump = Some(i);
                    }
                }
            });
        });
        ui.add_space(6.0);
        if visible.is_empty() {
            muted(ui, tf("Sin resultados para «{}».", &[&self.help_search.trim()]));
            return;
        }
        ui.label(RichText::new(title).size(18.0).strong().color(TEXT()));
        ui.add_space(4.0);
        let jump = self.help_jump.take();
        for &i in &visible {
            let s = &sections[i];
            let open = if !q.is_empty() || jump == Some(i) { Some(true) } else { None };
            let resp = egui::CollapsingHeader::new(RichText::new(s.title).size(16.5).strong().color(TEXT()))
                .id_salt(("manual", lang(), i))
                .default_open(i == 0)
                .open(open)
                .show(ui, |ui| {
                    ui.set_max_width(980.0);
                    render(ui, &s.body);
                });
            if jump == Some(i) {
                resp.header_response.scroll_to_me(Some(egui::Align::TOP));
            }
        }
    }
}
