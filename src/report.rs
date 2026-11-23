//! Informe completo en HTML (para guardar, imprimir como PDF o enviar a quien te ayude):
//! datos de la red, seguridad de este equipo, vulnerabilidades, diagnóstico de la LAN,
//! dispositivos y alertas recientes.
use crate::egui;
use crate::i18n::{tf, tr};
use crate::ids::{Alert, Sev};
use crate::lanaudit::LanFinding;
use crate::netscan::Host;
use crate::security::Finding;
use crate::util::*;
use std::path::PathBuf;

pub struct ReportData {
    pub info: NetInfo,
    pub hosts: Vec<Host>,
    pub host_facts: Vec<(String, String)>,
    pub host_findings: Vec<LanFinding>,
    pub host_score: Option<i32>,
    pub net_findings: Vec<Finding>,
    pub net_score: Option<i32>,
    pub lan_facts: Vec<(String, String)>,
    pub lan_findings: Vec<LanFinding>,
    pub lan_score: Option<i32>,
    pub alerts: Vec<Alert>,
}

#[derive(Default)]
pub struct ReportState {
    pub running: bool,
    pub result: Option<Result<PathBuf, String>>,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn sev_class(s: Sev) -> &'static str {
    match s {
        Sev::Critical => "crit",
        Sev::High => "high",
        Sev::Medium => "med",
        Sev::Low => "low",
        Sev::Info => "info",
    }
}

fn score_html(label: &str, score: Option<i32>) -> String {
    match score {
        Some(s) => {
            let c = if s >= 80 { "#16a34a" } else if s >= 50 { "#d97706" } else { "#dc2626" };
            format!("<div class=\"score\"><b style=\"color:{}\">{}</b><span>/100</span><div>{}</div></div>", c, s, esc(label))
        }
        None => format!("<div class=\"score\"><b style=\"color:#9ca3af\">—</b><div>{}</div><small>{}</small></div>", esc(label), esc(tr("no revisado"))),
    }
}

fn facts_html(facts: &[(String, String)]) -> String {
    if facts.is_empty() {
        return String::new();
    }
    let mut s = String::from("<table class=\"facts\">");
    for (k, v) in facts {
        s.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v)));
    }
    s.push_str("</table>");
    s
}

fn finding_html(sev: Sev, title: &str, detail: &str, fix: &str, host: &str) -> String {
    let fix = if fix.is_empty() { String::new() } else { format!("<p class=\"fix\">{}</p>", esc(&tf("Cómo arreglarlo: {}", &[&fix]))) };
    let host = if host.is_empty() { String::new() } else { format!("<code>{}</code> ", esc(host)) };
    format!(
        "<div class=\"f\"><span class=\"badge {}\">{}</span> {}<b>{}</b><p>{}</p>{}</div>",
        sev_class(sev), esc(sev.label()), host, esc(title), esc(detail), fix
    )
}

fn not_run(what: &str) -> String {
    format!("<p class=\"muted\">{}</p>", esc(&tf("No se ha ejecutado todavía. Abre «{}» en la app y vuelve a crear el informe.", &[&tr(what)])))
}

pub fn build_html(d: &ReportData) -> String {
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    let mut h = String::new();
    h.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">");
    h.push_str(&format!("<title>{} · {}</title>", esc(tr("Informe de red y seguridad")), esc(&d.info.hostname)));
    h.push_str("<style>
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;max-width:980px;margin:24px auto;padding:0 18px;color:#1f2937;line-height:1.45}
h1{margin:0;color:#4c1d95}h2{margin-top:34px;border-bottom:2px solid #ede9fe;padding-bottom:4px;color:#4c1d95}
.sub{color:#6b7280;margin-top:2px}.scores{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.score{flex:1;min-width:150px;border:1px solid #e5e7eb;border-radius:10px;padding:12px;text-align:center}
.score b{font-size:34px}.score span{color:#6b7280}.score div{font-weight:600}.score small{color:#9ca3af}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #f3f4f6;vertical-align:top}
table.facts th{width:40%;color:#6b7280;font-weight:500}thead th{background:#f5f3ff;color:#4c1d95}
.f{border-left:4px solid #e5e7eb;padding:6px 10px;margin:8px 0;background:#fafafa;border-radius:4px}.f p{margin:3px 0;color:#4b5563;font-size:14px}
.fix{color:#15803d!important}.badge{display:inline-block;font-size:12px;padding:1px 8px;border-radius:9px;color:#fff;font-weight:600}
.crit{background:#7f1d1d}.high{background:#dc2626}.med{background:#d97706}.low{background:#2563eb}.info{background:#6b7280}
.muted{color:#9ca3af}code{background:#f3f4f6;padding:0 4px;border-radius:4px}
footer{margin:40px 0 10px;color:#9ca3af;font-size:12px;text-align:center}
@media print{h2{page-break-after:avoid}.f{page-break-inside:avoid}}
</style></head><body>");
    h.push_str(&format!("<h1>RedVisión · {}</h1><div class=\"sub\">{} · {} · {}</div>", esc(tr("Informe de red y seguridad")), esc(&d.info.hostname), esc(&d.info.os), esc(&now)));

    // Resumen
    let all_sev: Vec<Sev> = d.host_findings.iter().map(|f| f.sev).chain(d.net_findings.iter().map(|f| f.sev)).chain(d.lan_findings.iter().map(|f| f.sev)).collect();
    let grave = all_sev.iter().filter(|s| matches!(s, Sev::Critical | Sev::High)).count();
    let medium = all_sev.iter().filter(|s| matches!(s, Sev::Medium)).count();
    h.push_str("<div class=\"scores\">");
    h.push_str(&score_html(tr("Seguridad de este equipo"), d.host_score));
    h.push_str(&score_html(tr("Vulnerabilidades de la red"), d.net_score));
    h.push_str(&score_html(tr("Diagnóstico de la LAN"), d.lan_score));
    h.push_str("</div>");
    let summary = if grave > 0 {
        tf("Hay {} problemas graves y {} medios. Empieza por los marcados en rojo.", &[&grave, &medium])
    } else if medium > 0 {
        tf("No hay problemas graves, pero sí {} medios que conviene revisar.", &[&medium])
    } else {
        tr("No se han encontrado problemas importantes en lo revisado.").to_string()
    };
    h.push_str(&format!("<p><b>{}</b></p>", esc(&summary)));

    // Red
    h.push_str(&format!("<h2>{}</h2>", esc(tr("Tu red"))));
    let dns = d.info.dns.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ");
    let net_facts = vec![
        (tr("Este equipo").to_string(), format!("{} · {}", d.info.local_ip.map(|i| format!("{}/{}", i, d.info.prefix)).unwrap_or_else(|| "?".into()), d.info.iface)),
        (tr("Red").to_string(), d.info.network_label()),
        (tr("Puerta de enlace").to_string(), d.info.gateway.map(|g| g.to_string()).unwrap_or_else(|| "?".into())),
        (tr("Servidores DNS").to_string(), dns),
        (tr("Dispositivos en la red").to_string(), if d.hosts.is_empty() { "—".into() } else { d.hosts.len().to_string() }),
    ];
    h.push_str(&facts_html(&net_facts));

    // Seguridad de este equipo
    h.push_str(&format!("<h2>{}</h2>", esc(tr("Seguridad de este equipo"))));
    if d.host_score.is_none() {
        h.push_str(&not_run("Vulnerabilidades"));
    } else {
        h.push_str(&facts_html(&d.host_facts));
        for f in &d.host_findings {
            h.push_str(&finding_html(f.sev, &f.title, &f.detail, &f.fix, ""));
        }
    }

    // Vulnerabilidades de la red
    h.push_str(&format!("<h2>{}</h2>", esc(tr("Vulnerabilidades de la red"))));
    if d.net_score.is_none() {
        h.push_str(&not_run("Vulnerabilidades"));
    } else if d.net_findings.is_empty() {
        h.push_str(&format!("<p>{}</p>", esc(tr("No se han encontrado problemas en este equipo"))));
    } else {
        for f in &d.net_findings {
            let host = match f.port {
                Some(p) => format!("{}:{}", f.host, p),
                None => f.host.clone(),
            };
            h.push_str(&finding_html(f.sev, &f.title, &f.detail, &f.fix, &host));
        }
    }

    // Diagnóstico de la LAN
    h.push_str(&format!("<h2>{}</h2>", esc(tr("Diagnóstico de la LAN"))));
    if d.lan_score.is_none() {
        h.push_str(&not_run("Diagnóstico de la LAN"));
    } else {
        h.push_str(&facts_html(&d.lan_facts));
        for f in &d.lan_findings {
            h.push_str(&finding_html(f.sev, &f.title, &f.detail, &f.fix, ""));
        }
    }

    // Dispositivos
    h.push_str(&format!("<h2>{}</h2>", esc(tr("Dispositivos en la red"))));
    if d.hosts.is_empty() {
        h.push_str(&not_run("Red y topología"));
    } else {
        h.push_str(&format!(
            "<table><thead><tr><th>IP</th><th>{}</th><th>MAC</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
            esc(tr("Nombre")), esc(tr("Fabricante")), esc(tr("Tipo")), esc(tr("Puertos"))
        ));
        let mut hosts = d.hosts.clone();
        hosts.sort_by_key(|x| u32::from(x.ip));
        for x in &hosts {
            let ports = x.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                x.ip, esc(&x.name), esc(&x.mac), esc(&x.vendor), esc(x.kind.label()), esc(&ports)
            ));
        }
        h.push_str("</tbody></table>");
    }

    // Alertas
    h.push_str(&format!("<h2>{}</h2>", esc(tr("Alertas recientes"))));
    if d.alerts.is_empty() {
        h.push_str(&format!("<p class=\"muted\">{}</p>", esc(tr("Sin alertas en los últimos 7 días."))));
    } else {
        h.push_str(&format!(
            "<table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
            esc(tr("Hora")), esc(tr("Nivel")), esc(tr("Tipo")), esc(tr("Origen")), esc(tr("Detalle"))
        ));
        for a in d.alerts.iter().rev().take(100) {
            let t = chrono::DateTime::from_timestamp(a.ts as i64, 0).map(|t| t.with_timezone(&chrono::Local).format("%d/%m %H:%M").to_string()).unwrap_or_default();
            h.push_str(&format!(
                "<tr><td>{}</td><td><span class=\"badge {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                t, sev_class(a.sev), esc(a.sev.label()), esc(&a.cat), esc(&a.src), esc(&a.msg)
            ));
        }
        h.push_str("</tbody></table>");
    }
    h.push_str(&format!("<footer>{}</footer></body></html>", esc(&tf("Creado con RedVisión {} el {}. Para guardarlo como PDF, usa «Imprimir» en el navegador.", &[&env!("CARGO_PKG_VERSION"), &now]))));
    h
}

#[cfg(test)]
mod tests {
    #[test]
    fn html_is_escaped_and_complete() {
        let mut info = crate::util::NetInfo::default();
        info.hostname = "pc<1>".into();
        let d = super::ReportData {
            info, hosts: vec![], host_facts: vec![("k".into(), "<v>".into())], host_findings: vec![], host_score: Some(90),
            net_findings: vec![], net_score: None, lan_facts: vec![], lan_findings: vec![], lan_score: None, alerts: vec![],
        };
        let h = super::build_html(&d);
        assert!(h.contains("pc&lt;1&gt;") && h.contains("&lt;v&gt;") && !h.contains("<v>"));
        assert!(h.ends_with("</html>"));
    }
    /// Informe real de este equipo: `cargo test -- --ignored report_here`
    #[test]
    #[ignore]
    fn report_here() {
        let info = crate::util::detect();
        let (f, facts) = crate::hostcheck::check(&info);
        let d = super::ReportData {
            host_score: Some(crate::hostcheck::score(&f)), host_findings: f, host_facts: facts, info,
            hosts: vec![], net_findings: vec![], net_score: None, lan_facts: vec![], lan_findings: vec![], lan_score: None, alerts: crate::history::load(),
        };
        std::fs::write("/tmp/rv_report.html", super::build_html(&d)).unwrap();
    }
}

/// Abre un archivo con el programa predeterminado del sistema.
pub fn open_path(p: &std::path::Path) {
    let s = p.to_string_lossy().to_string();
    let _ = if cfg!(windows) {
        command("explorer").arg(&s).spawn()
    } else if cfg!(target_os = "macos") {
        command("open").arg(&s).spawn()
    } else {
        command("xdg-open").arg(&s).spawn()
    };
}

pub fn save(html: &str, hostname: &str) -> Result<PathBuf, String> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M");
    let safe: String = hostname.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    let path = PathBuf::from(home).join(format!("RedVision-informe-{}-{}.html", safe, stamp));
    std::fs::write(&path, html).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Crea el informe en segundo plano. Si este equipo aún no se ha revisado, lo revisa antes.
pub fn start(state: Shared<ReportState>, mut data: ReportData, host_audit: Shared<crate::lanaudit::LanAudit>, open: bool, ctx: egui::Context) {
    *lock(&state) = ReportState { running: true, result: None };
    std::thread::spawn(move || {
        if data.host_score.is_none() {
            let (f, facts) = crate::hostcheck::check(&data.info);
            let score = crate::hostcheck::score(&f);
            {
                let mut a = lock(&host_audit);
                a.findings = f.clone();
                a.facts = facts.clone();
                a.score = Some(score);
                a.progress = 1.0;
            }
            data.host_findings = f;
            data.host_facts = facts;
            data.host_score = Some(score);
        }
        let html = build_html(&data);
        let r = save(&html, &data.info.hostname);
        if open {
            if let Ok(p) = &r {
                open_path(p);
            }
        }
        let mut s = lock(&state);
        s.result = Some(r);
        s.running = false;
        ctx.request_repaint();
    });
}
