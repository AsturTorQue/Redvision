//! En Linux (sobre todo Wayland) el icono de la ventana lo pone el escritorio a partir de un
//! archivo .desktop cuyo nombre coincide con el app_id. Si la app no está instalada por un
//! paquete, se registra ella misma en ~/.local/share para el usuario actual.
pub const APP_ID: &str = "redvision";

#[cfg(target_os = "linux")]
pub fn register() {
    use std::path::PathBuf;
    if std::path::Path::new("/usr/share/applications/redvision.desktop").exists() && std::env::var_os("APPIMAGE").is_none() {
        return;
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    let Some(data) = data else { return };
    let exe = std::env::var_os("APPIMAGE").map(PathBuf::from).or_else(|| std::env::current_exe().ok());
    let Some(exe) = exe else { return };
    let icon_dir = data.join("icons/hicolor/512x512/apps");
    let png: &[u8] = include_bytes!("../assets/icon.png");
    // El nombre del icono cambia con su contenido: así el escritorio no sigue mostrando
    // el icono anterior que tenía guardado en caché.
    let hash = png.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3));
    let icon_name = format!("redvision-{:08x}", hash as u32);
    let icon = icon_dir.join(format!("{}.png", icon_name));
    if std::fs::read(&icon).map(|b| b != png).unwrap_or(true) {
        let _ = std::fs::create_dir_all(&icon_dir);
        let _ = std::fs::write(&icon, png);
        // Quitar iconos de versiones anteriores
        if let Ok(rd) = std::fs::read_dir(&icon_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if (n == "redvision.png" || n.starts_with("redvision-")) && n != format!("{}.png", icon_name) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        // Si el tema de iconos del usuario tiene caché, actualizarla
        let hicolor = data.join("icons/hicolor");
        if hicolor.join("icon-theme.cache").exists() {
            let _ = crate::util::command("gtk-update-icon-cache").args(["-f", "-t"]).arg(&hicolor).output();
        }
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=RedVisión\nGenericName=Network analyzer\nComment=Mapa de red, puertos, captura de paquetes, latencia, DNS y seguridad\nExec=\"{}\"\nIcon={}\nTerminal=false\nCategories=Network;Monitor;System;\nStartupWMClass={}\n",
        exe.display(),
        icon_name,
        APP_ID
    );
    let apps = data.join("applications");
    let file = apps.join("redvision.desktop");
    if std::fs::read_to_string(&file).map(|t| t != entry).unwrap_or(true) {
        let _ = std::fs::create_dir_all(&apps);
        let _ = std::fs::write(&file, entry);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn register() {}
