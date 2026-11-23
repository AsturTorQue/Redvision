//! Preferencias guardadas entre sesiones (idioma, tema, tamaño, equipos vigilados).
use std::path::PathBuf;

#[derive(Clone, PartialEq)]
pub struct Settings {
    pub lang: usize,
    pub theme: usize,
    pub zoom: f32,
    pub scan_on_start: bool,
    pub watched: Vec<String>,
}

pub fn dir() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    if cfg!(windows) {
        std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(&home)).join("RedVision")
    } else if cfg!(target_os = "macos") {
        PathBuf::from(home).join("Library/Application Support/RedVision")
    } else {
        std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(home).join(".config")).join("redvision")
    }
}

pub fn path() -> PathBuf {
    dir().join("settings.conf")
}

pub fn load() -> Settings {
    let mut s = Settings { lang: crate::i18n::system_lang(), theme: 0, zoom: 1.0, scan_on_start: false, watched: Vec::new() };
    if let Ok(txt) = std::fs::read_to_string(path()) {
        for line in txt.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim();
            match k.trim() {
                "lang" => s.lang = crate::i18n::LANGS.iter().position(|(c, _)| *c == v).unwrap_or(s.lang),
                "theme" => s.theme = v.parse().unwrap_or(0),
                "zoom" => s.zoom = v.parse::<f32>().unwrap_or(1.0).clamp(0.7, 1.6),
                "scan_on_start" => s.scan_on_start = v == "true",
                "watched" => s.watched = v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
                _ => {}
            }
        }
    }
    // Para probar sin tocar las preferencias: REDVISION_LANG=en, REDVISION_THEME=1
    if let Ok(v) = std::env::var("REDVISION_LANG") {
        if let Some(i) = crate::i18n::LANGS.iter().position(|(c, _)| *c == v) {
            s.lang = i;
        }
    }
    if let Ok(v) = std::env::var("REDVISION_THEME") {
        s.theme = v.parse().unwrap_or(s.theme);
    }
    s
}

pub fn save(s: &Settings) -> Result<(), String> {
    std::fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let txt = format!(
        "# Preferencias de RedVisión\nlang={}\ntheme={}\nzoom={:.2}\nscan_on_start={}\nwatched={}\n",
        crate::i18n::LANGS[s.lang.min(crate::i18n::LANGS.len() - 1)].0,
        s.theme,
        s.zoom,
        s.scan_on_start,
        s.watched.join(",")
    );
    std::fs::write(path(), txt).map_err(|e| e.to_string())
}
