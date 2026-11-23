//! Volver a abrir la app con permisos de administrador (root) para capturar paquetes.
//! Linux: primero intenta dar a la app solo el permiso de captura (setcap con pkexec), que es
//! más seguro que ejecutarla entera como root; si no puede (AppImage), la abre como root.
//! Windows: «Ejecutar como administrador» (UAC). macOS: pide la contraseña con osascript.
use crate::util::*;
use std::path::PathBuf;
use std::process::Stdio;

#[derive(Clone, Default)]
pub struct ElevateState {
    pub running: bool,
    /// La nueva copia ya arrancó: hay que cerrar esta.
    pub close_now: bool,
    pub error: Option<String>,
}

/// En Linux, ¿tiene el proceso el permiso CAP_NET_RAW (captura) aunque no sea root?
pub fn has_capture_capability() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("CapEff:")).map(|l| l[7..].trim().to_string()))
        .and_then(|h| u64::from_str_radix(&h, 16).ok())
        .map(|caps| caps & (1 << 13) != 0)
        .unwrap_or(false)
}

fn exe() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE").map(PathBuf::from).or_else(|| std::env::current_exe().ok())
}

fn relaunch_plain(exe: &PathBuf) -> Result<(), String> {
    command(exe.to_str().unwrap_or_default())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn linux() -> Result<(), String> {
    let exe = exe().ok_or("exe")?;
    let path = exe.to_string_lossy().to_string();
    if std::env::var_os("APPIMAGE").is_none() {
        // 1. Dar solo el permiso de captura al programa y abrirlo de nuevo como usuario normal
        let st = command("pkexec")
            .args(["setcap", "cap_net_raw,cap_net_admin=eip", &path])
            .status()
            .map_err(|_| crate::i18n::tr("No se encontró «pkexec». Abre la app con sudo.").to_string())?;
        if st.success() {
            return relaunch_plain(&exe);
        }
        if st.code() == Some(126) {
            return Err(crate::i18n::tr("Se canceló la petición de contraseña.").into());
        }
    }
    // 2. Abrir la app entera como root conservando la sesión gráfica
    let mut args: Vec<String> = vec!["env".into()];
    for var in ["DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY", "LANG", "XDG_SESSION_TYPE"] {
        if let Ok(v) = std::env::var(var) {
            args.push(format!("{}={}", var, v));
        }
    }
    args.push(path);
    command("pkexec")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|_| crate::i18n::tr("No se encontró «pkexec». Abre la app con sudo.").to_string())
}

fn windows() -> Result<(), String> {
    let exe = exe().ok_or("exe")?;
    let p = exe.to_string_lossy().replace('\'', "''");
    let st = command("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &format!("Start-Process -FilePath '{}' -Verb RunAs", p)])
        .status()
        .map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err(crate::i18n::tr("Se canceló la petición de contraseña.").into())
    }
}

fn macos() -> Result<(), String> {
    let exe = exe().ok_or("exe")?;
    let p = exe.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"").replace('\'', "'\\''");
    let script = format!("do shell script \"'{}' > /dev/null 2>&1 &\" with administrator privileges", p);
    let st = command("osascript").args(["-e", &script]).status().map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err(crate::i18n::tr("Se canceló la petición de contraseña.").into())
    }
}

/// Pide la contraseña y abre una copia con permisos; si sale bien, esta copia debe cerrarse.
pub fn start(state: Shared<ElevateState>, ctx: egui::Context) {
    {
        let mut s = lock(&state);
        s.running = true;
        s.error = None;
    }
    std::thread::spawn(move || {
        let r = if cfg!(windows) {
            windows()
        } else if cfg!(target_os = "macos") {
            macos()
        } else {
            linux()
        };
        let mut s = lock(&state);
        s.running = false;
        match r {
            Ok(()) => s.close_now = true,
            Err(e) => s.error = Some(e),
        }
        ctx.request_repaint();
    });
}

use crate::egui;
