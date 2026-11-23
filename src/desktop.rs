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
    let icon = icon_dir.join("redvision.png");
    let png: &[u8] = include_bytes!("../assets/icon.png");
    if std::fs::read(&icon).map(|b| b != png).unwrap_or(true) {
        let _ = std::fs::create_dir_all(&icon_dir);
        let _ = std::fs::write(&icon, png);
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=RedVisión\nGenericName=Network analyzer\nComment=Mapa de red, puertos, captura de paquetes, latencia, DNS y seguridad\nExec=\"{}\"\nIcon=redvision\nTerminal=false\nCategories=Network;Monitor;System;\nStartupWMClass={}\n",
        exe.display(),
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
