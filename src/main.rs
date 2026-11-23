#![cfg_attr(windows, windows_subsystem = "windows")]
//! RedVisión: analizador de red de escritorio para Linux, Windows y macOS.
use eframe::egui;

mod app;
mod capture;
mod config;
mod desktop;
mod dns;
mod elevate;
mod history;
mod hostcheck;
mod i18n;
mod i18n_de;
mod i18n_fr;
mod ids;
mod lanaudit;
mod monitor;
mod netdiscover;
mod netscan;
mod packet;
mod pages_extra;
mod pages_help;
mod pages_lan;
mod pages_wifi;
mod ping;
mod ports;
mod pwned;
mod report;
mod qoe;
mod security;
mod speedtest;
mod tlscheck;
mod tools;
mod util;
mod widgets;
mod wifi;

/// Motor gráfico. En Windows hay dos: OpenGL (por defecto) y DirectX/WARP (por si no hay OpenGL,
/// como en muchas máquinas virtuales). En los demás sistemas solo se usa OpenGL.
#[derive(Clone, Copy, PartialEq)]
enum Gfx {
    Glow,
    Wgpu,
}

#[cfg(windows)]
fn renderer_file() -> std::path::PathBuf {
    config::dir().join("renderer")
}

fn log_error(msg: &str) {
    use std::io::Write;
    let _ = std::fs::create_dir_all(config::dir());
    let line = format!("[{}] {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(config::dir().join("error.log")) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// La app no tiene consola en Windows: si no puede arrancar, lo decimos en una ventana.
fn show_error(msg: &str) {
    eprintln!("{}", msg);
    #[cfg(windows)]
    {
        let text = format!("{}\n\nRegistro: {}", msg, config::dir().join("error.log").display()).replace('\'', "''");
        let _ = util::command("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('{}', 'RedVisión', 'OK', 'Error') | Out-Null", text),
            ])
            .status();
    }
}

fn run(screenshot: Option<std::path::PathBuf>, gfx: Gfx) -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1400.0, 880.0])
        .with_min_inner_size([1000.0, 640.0])
        .with_title("RedVisión — Analizador de red")
        .with_app_id(desktop::APP_ID);
    if screenshot.is_none() {
        desktop::register();
    }
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
    #[cfg(windows)]
    {
        options.renderer = if gfx == Gfx::Wgpu { eframe::Renderer::Wgpu } else { eframe::Renderer::Glow };
    }
    let _ = gfx;
    #[cfg(target_os = "macos")]
    if screenshot.is_some() {
        options.event_loop_builder = Some(Box::new(|b| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            b.with_activate_ignoring_other_apps(false);
        }));
    }
    eframe::run_native("RedVisión", options, Box::new(move |cc| Ok(Box::new(app::NetApp::new(cc, screenshot)))))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut screenshot = None;
    let mut forced = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--screenshot" if i + 1 < args.len() => {
                screenshot = Some(std::path::PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--renderer" if i + 1 < args.len() => {
                forced = Some(if args[i + 1] == "wgpu" || args[i + 1] == "directx" { Gfx::Wgpu } else { Gfx::Glow });
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    #[cfg(windows)]
    let remembered_wgpu = std::fs::read_to_string(renderer_file()).map(|t| t.trim() == "wgpu").unwrap_or(false);
    #[cfg(not(windows))]
    let remembered_wgpu = false;
    let gfx = forced.unwrap_or(if remembered_wgpu { Gfx::Wgpu } else { Gfx::Glow });
    std::panic::set_hook(Box::new(|info| {
        log_error(&format!("Error interno: {}", info));
    }));
    let Err(e) = run(screenshot, gfx) else { return };
    log_error(&format!("No se pudo abrir la ventana ({}): {}", if gfx == Gfx::Wgpu { "DirectX" } else { "OpenGL" }, e));
    // Windows sin OpenGL (máquina virtual, controlador antiguo…): reabrir con DirectX.
    #[cfg(windows)]
    if gfx == Gfx::Glow && forced.is_none() {
        if let Ok(exe) = std::env::current_exe() {
            let mut a = args.clone();
            a.push("--renderer".into());
            a.push("wgpu".into());
            if let Ok(st) = util::command(&exe.to_string_lossy()).args(&a).status() {
                if st.success() {
                    let _ = std::fs::create_dir_all(config::dir());
                    let _ = std::fs::write(renderer_file(), "wgpu");
                    return;
                }
            }
        }
    }
    show_error(&format!(
        "RedVisión no pudo abrir su ventana.\n\n{}\n\nSi usas una máquina virtual, activa la aceleración 3D en su configuración o instala los controladores de vídeo del sistema.",
        e
    ));
    std::process::exit(1);
}
