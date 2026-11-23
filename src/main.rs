#![cfg_attr(windows, windows_subsystem = "windows")]
//! RedVisión: analizador de red de escritorio para Linux, Windows y macOS.
use eframe::egui;

mod app;
mod capture;
mod dns;
mod ids;
mod monitor;
mod netscan;
mod packet;
mod ping;
mod ports;
mod qoe;
mod security;
mod util;
mod widgets;

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut screenshot = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--screenshot" && i + 1 < args.len() {
            screenshot = Some(std::path::PathBuf::from(&args[i + 1]));
            i += 1;
        }
        i += 1;
    }
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1400.0, 880.0])
        .with_min_inner_size([1000.0, 640.0])
        .with_title("RedVisión — Analizador de red");
    if let Ok(img) = image::load_from_memory(include_bytes!("../assets/icon.png")) {
        let img = img.to_rgba8();
        let (width, height) = img.dimensions();
        viewport = viewport.with_icon(egui::IconData { rgba: img.into_raw(), width, height });
    }
    if screenshot.is_some() {
        // Para las comprobaciones: abrir sin quitar el foco a la persona.
        viewport = viewport.with_active(false);
        #[cfg(windows)]
        {
            viewport = viewport.with_window_level(egui::WindowLevel::AlwaysOnBottom);
        }
    }
    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions { viewport, ..Default::default() };
    #[cfg(target_os = "macos")]
    if screenshot.is_some() {
        options.event_loop_builder = Some(Box::new(|b| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            b.with_activate_ignoring_other_apps(false);
        }));
    }
    eframe::run_native(
        "RedVisión",
        options,
        Box::new(move |cc| Ok(Box::new(app::NetApp::new(cc, screenshot)))),
    )
}
