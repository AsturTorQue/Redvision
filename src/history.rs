//! Historial de alertas entre sesiones y avisos del sistema.
use crate::config;
use crate::ids::{Alert, Sev};
use crate::util::*;
use std::io::Write;
use std::path::PathBuf;

const KEEP_DAYS: f64 = 7.0;
const KEEP_MAX: usize = 1000;

fn path() -> PathBuf {
    config::dir().join("alerts.tsv")
}

fn num(s: Sev) -> u8 {
    match s {
        Sev::Info => 0,
        Sev::Low => 1,
        Sev::Medium => 2,
        Sev::High => 3,
        Sev::Critical => 4,
    }
}

fn from_num(n: u8) -> Sev {
    match n {
        0 => Sev::Info,
        1 => Sev::Low,
        2 => Sev::Medium,
        3 => Sev::High,
        _ => Sev::Critical,
    }
}

fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn line(a: &Alert) -> String {
    format!("{:.3}\t{}\t{}\t{}\t{}\n", a.ts, num(a.sev), clean(&a.cat), clean(&a.src), clean(&a.msg))
}

fn parse(l: &str) -> Option<Alert> {
    let mut f = l.splitn(5, '\t');
    Some(Alert {
        ts: f.next()?.parse().ok()?,
        sev: from_num(f.next()?.parse().ok()?),
        cat: f.next()?.to_string(),
        src: f.next()?.to_string(),
        msg: f.next()?.to_string(),
    })
}

/// Alertas de los últimos 7 días. Si el archivo ha crecido mucho, lo recorta.
pub fn load() -> Vec<Alert> {
    let Ok(txt) = std::fs::read_to_string(path()) else { return Vec::new() };
    let min = now_secs() - KEEP_DAYS * 86400.0;
    let mut v: Vec<Alert> = txt.lines().filter_map(parse).filter(|a| a.ts >= min).collect();
    if v.len() > KEEP_MAX {
        v.drain(..v.len() - KEEP_MAX);
    }
    if txt.lines().count() > KEEP_MAX * 2 {
        let _ = std::fs::write(path(), v.iter().map(line).collect::<String>());
    }
    v
}

pub fn append(alerts: &[Alert]) {
    if alerts.is_empty() {
        return;
    }
    let _ = std::fs::create_dir_all(config::dir());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path()) {
        let _ = f.write_all(alerts.iter().map(line).collect::<String>().as_bytes());
    }
}

pub fn clear() {
    let _ = std::fs::remove_file(path());
}

// ---------------------------------------------------------------- avisos del sistema

/// Muestra una notificación del sistema (sin ventana ni librerías extra).
pub fn notify(title: &str, body: &str) {
    let (title, body) = (title.to_string(), body.to_string());
    std::thread::spawn(move || {
        if cfg!(windows) {
            let q = |s: &str| s.replace('\'', "''");
            let script = format!(
                "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; \
                 $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; \
                 $n.Visible = $true; $n.ShowBalloonTip(8000, '{}', '{}', [System.Windows.Forms.ToolTipIcon]::Warning); \
                 Start-Sleep -Seconds 9; $n.Dispose()",
                q(&title),
                q(&body)
            );
            let _ = command("powershell").args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script]).status();
        } else if cfg!(target_os = "macos") {
            let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
            let script = format!("display notification \"{}\" with title \"{}\"", q(&body), q(&title));
            let _ = command("osascript").args(["-e", &script]).status();
        } else {
            let _ = command("notify-send").args(["--app-name=RedVisión", "--icon=dialog-warning", &title, &body]).status();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_roundtrip() {
        let a = Alert { ts: 1700000000.5, sev: Sev::High, cat: "Túnel\tDNS".into(), src: "1.2.3.4".into(), msg: "Una\nprueba".into() };
        let b = parse(line(&a).trim_end()).unwrap();
        assert_eq!((b.ts, b.sev, b.src.as_str()), (a.ts, Sev::High, "1.2.3.4"));
        assert_eq!(b.cat, "Túnel DNS");
        assert_eq!(b.msg, "Una prueba");
    }

    /// Notificación real: `cargo test -- --ignored --nocapture notify_here`
    #[test]
    #[ignore]
    fn notify_here() {
        notify("RedVisión", "Prueba de aviso");
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}
