//! Idiomas de la interfaz. Cada línea de TABLE es (español, inglés, portugués);
//! el texto en español es la clave. Para añadir un idioma: una columna más y su nombre en LANGS.
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub const LANGS: &[(&str, &str)] = &[("es", "Español"), ("en", "English"), ("pt", "Português"), ("fr", "Français"), ("de", "Deutsch")];

static LANG: AtomicUsize = AtomicUsize::new(0);

pub fn set_lang(i: usize) {
    LANG.store(i.min(LANGS.len() - 1), Ordering::Relaxed);
}
pub fn lang() -> usize {
    LANG.load(Ordering::Relaxed)
}

/// Idioma del sistema (variables LANG/LC_ALL); inglés si no se reconoce.
pub fn system_lang() -> usize {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.to_lowercase();
            if let Some(i) = LANGS.iter().position(|(code, _)| v.starts_with(code)) {
                return i;
            }
        }
    }
    if cfg!(windows) {
        if let Some(out) = crate::util::run("powershell", &["-NoProfile", "-Command", "(Get-UICulture).TwoLetterISOLanguageName"]) {
            let v = out.trim().to_lowercase();
            if let Some(i) = LANGS.iter().position(|(code, _)| v.starts_with(code)) {
                return i;
            }
        }
    }
    1
}

/// Español -> [inglés, portugués, francés, alemán]. Francés y alemán van en el mismo orden que TABLE.
fn map() -> &'static HashMap<&'static str, [&'static str; 4]> {
    static M: OnceLock<HashMap<&'static str, [&'static str; 4]>> = OnceLock::new();
    M.get_or_init(|| {
        TABLE
            .iter()
            .enumerate()
            .map(|(i, (es, en, pt))| {
                let fr = crate::i18n_fr::FR.get(i).copied().unwrap_or(en);
                let de = crate::i18n_de::DE.get(i).copied().unwrap_or(en);
                (*es, [*en, *pt, fr, de])
            })
            .collect()
    })
}

/// Traduce un texto (escrito en español) al idioma activo.
pub fn tr(s: &str) -> &str {
    let l = lang();
    if l == 0 {
        return s;
    }
    match map().get(s) {
        Some(v) => v[l - 1],
        None => s,
    }
}

/// Como format!, con la plantilla traducida. Admite {}, {:.0}, {:.1}, {:.2}, {:>2} y {:>4}.
pub fn tf(tmpl: &str, args: &[&dyn Display]) -> String {
    let tmpl = tr(tmpl);
    let mut out = String::with_capacity(tmpl.len() + 16);
    let mut it = args.iter();
    let mut chars = tmpl.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            if chars.peek() == Some(&'{') {
                chars.next();
                out.push('{');
                continue;
            }
            let mut spec = String::new();
            for d in chars.by_ref() {
                if d == '}' {
                    break;
                }
                spec.push(d);
            }
            if let Some(a) = it.next() {
                let s = match spec.trim_start_matches(':') {
                    ".0" => format!("{:.0}", a),
                    ".1" => format!("{:.1}", a),
                    ".2" => format!("{:.2}", a),
                    ">2" => format!("{:>2}", a),
                    ">4" => format!("{:>4}", a),
                    _ => format!("{}", a),
                };
                out.push_str(&s);
            }
        } else if c == '}' && chars.peek() == Some(&'}') {
            chars.next();
            out.push('}');
        } else {
            out.push(c);
        }
    }
    out
}

#[rustfmt::skip]
const TABLE: &[(&str, &str, &str)] = &[
    // navegación
    ("Panel", "Dashboard", "Painel"),
    ("Red y topología", "Network & topology", "Rede e topologia"),
    ("Puertos", "Ports", "Portas"),
    ("Captura de paquetes", "Packet capture", "Captura de pacotes"),
    ("Análisis profundo", "Deep analysis", "Análise profunda"),
    ("Latencia y pérdida", "Latency & loss", "Latência e perda"),
    ("Calidad (QoE)", "Quality (QoE)", "Qualidade (QoE)"),
    ("Análisis DNS", "DNS analysis", "Análise DNS"),
    ("Vulnerabilidades", "Vulnerabilities", "Vulnerabilidades"),
    ("Intrusos y anomalías", "Intrusions & anomalies", "Intrusões e anomalias"),
    ("Monitorización", "Monitoring", "Monitoramento"),
    ("Herramientas", "Tools", "Ferramentas"),
    ("Ajustes", "Settings", "Configurações"),
    ("Analizador de red", "Network analyzer", "Analisador de rede"),
    ("Permisos de administrador", "Administrator rights", "Permissões de administrador"),
    ("Sin permisos de administrador", "No administrator rights", "Sem permissões de administrador"),
    ("Detectando red…", "Detecting network…", "Detectando rede…"),
    ("No se pudo guardar la captura: {}", "Could not save the screenshot: {}", "Não foi possível salvar a captura: {}"),
    ("Escribe una IP o un nombre de equipo", "Type an IP or a host name", "Digite um IP ou nome de host"),
    ("hace {:.0} s", "{:.0} s ago", "há {:.0} s"),
    ("hace {:.0} min", "{:.0} min ago", "há {:.0} min"),
    ("hace {:.0} h", "{:.0} h ago", "há {:.0} h"),
    ("Este equipo", "This computer", "Este computador"),
    ("Router {}", "Router {}", "Roteador {}"),
    ("{}  {}\n{}{}\nLatencia {}", "{}  {}\n{}{}\nLatency {}", "{}  {}\n{}{}\nLatência {}"),
    // panel
    ("Panel de red", "Network dashboard", "Painel de rede"),
    ("Resumen en tiempo real de tu red, su calidad y su seguridad", "Real-time overview of your network, its quality and its security", "Resumo em tempo real da sua rede, qualidade e segurança"),
    ("interfaz", "interface", "interface"),
    ("Puerta de enlace", "Gateway", "Gateway"),
    ("{:.1} ms · pérdida {:.0}%", "{:.1} ms · loss {:.0}%", "{:.1} ms · perda {:.0}%"),
    ("midiendo latencia…", "measuring latency…", "medindo latência…"),
    ("Dispositivos en la red", "Devices on the network", "Dispositivos na rede"),
    ("escaneando…", "scanning…", "escaneando…"),
    ("escaneado {}", "scanned {}", "escaneado {}"),
    ("pulsa «Escanear la red»", "press «Scan network»", "clique em «Escanear a rede»"),
    ("Alertas de seguridad", "Security alerts", "Alertas de segurança"),
    ("{} altas o críticas", "{} high or critical", "{} altos ou críticos"),
    ("sin alertas graves", "no serious alerts", "sem alertas graves"),
    ("Tráfico de la red", "Network traffic", "Tráfego da rede"),
    ("últimos 2 minutos", "last 2 minutes", "últimos 2 minutos"),
    ("Latencia hasta el router", "Latency to the router", "Latência até o roteador"),
    ("media {}", "average {}", "média {}"),
    ("jitter {:.1} ms", "jitter {:.1} ms", "jitter {:.1} ms"),
    ("pérdida {:.0}%", "loss {:.0}%", "perda {:.0}%"),
    ("Seguridad", "Security", "Segurança"),
    ("puntuación", "score", "pontuação"),
    ("Resultado de la última auditoría.", "Result of the last audit.", "Resultado da última auditoria."),
    ("Aún no has auditado tu red.", "You haven't audited your network yet.", "Você ainda não auditou sua rede."),
    ("Auditar mi red", "Audit my network", "Auditar minha rede"),
    ("Calidad de la conexión", "Connection quality", "Qualidade da conexão"),
    ("Experiencia {}", "Experience: {}", "Experiência {}"),
    ("Mide voz, vídeo, juegos y web.", "Measures voice, video, gaming and web.", "Mede voz, vídeo, jogos e web."),
    ("Medir calidad", "Measure quality", "Medir qualidade"),
    ("Alertas recientes", "Recent alerts", "Alertas recentes"),
    ("Sin alertas. El vigilante revisa la tabla ARP, los equipos vigilados y el tráfico capturado.", "No alerts. The watcher checks the ARP table, watched hosts and captured traffic.", "Sem alertas. O vigia verifica a tabela ARP, os hosts monitorados e o tráfego capturado."),
    ("Acciones rápidas", "Quick actions", "Ações rápidas"),
    ("🌐 Escanear la red", "🌐 Scan network", "🌐 Escanear a rede"),
    ("📦 Capturar paquetes", "📦 Capture packets", "📦 Capturar pacotes"),
    ("⏱ Probar latencia", "⏱ Test latency", "⏱ Testar latência"),
    ("🔎 Analizar DNS", "🔎 Analyze DNS", "🔎 Analisar DNS"),
    ("🔌 Ver puertos abiertos", "🔌 View open ports", "🔌 Ver portas abertas"),
    ("🔧 Herramientas", "🔧 Tools", "🔧 Ferramentas"),
    // red
    ("Descubre los equipos activos de tu subred y cómo se conectan", "Discover the active hosts on your subnet and how they connect", "Descubra os hosts ativos da sua sub-rede e como se conectam"),
    ("Detener", "Stop", "Parar"),
    ("Escanear la red {}", "Scan network {}", "Escanear a rede {}"),
    ("Mapa", "Map", "Mapa"),
    ("Lista", "List", "Lista"),
    ("Comprobando direcciones", "Checking addresses", "Verificando endereços"),
    ("{} equipos encontrados en {:.0} s", "{} hosts found in {:.0} s", "{} hosts encontrados em {:.0} s"),
    ("Usa ping y conexiones TCP; no necesita permisos especiales.", "Uses ping and TCP connections; no special rights needed.", "Usa ping e conexões TCP; não precisa de permissões especiais."),
    ("Nombre", "Name", "Nome"),
    ("Fabricante", "Vendor", "Fabricante"),
    ("Tipo", "Type", "Tipo"),
    ("Latencia", "Latency", "Latência"),
    ("Puertos abiertos", "Open ports", "Portas abertas"),
    ("Todavía no hay equipos. Pulsa «Escanear la red».", "No hosts yet. Press «Scan network».", "Ainda não há hosts. Clique em «Escanear a rede»."),
    ("(sin nombre)", "(no name)", "(sem nome)"),
    ("(desconocida)", "(unknown)", "(desconhecido)"),
    ("Fabricante (estimado)", "Vendor (estimated)", "Fabricante (estimado)"),
    ("Puertos detectados", "Detected ports", "Portas detectadas"),
    ("ninguno de los comprobados", "none of the checked ones", "nenhuma das verificadas"),
    ("Escanear todos sus puertos", "Scan all its ports", "Escanear todas as portas"),
    ("Auditar seguridad", "Audit security", "Auditar segurança"),
    ("Medir latencia", "Measure latency", "Medir latência"),
    ("Vigilar", "Watch", "Monitorar"),
    ("Despertar (Wake-on-LAN)", "Wake up (Wake-on-LAN)", "Despertar (Wake-on-LAN)"),
    ("Pulsa un equipo del mapa para ver sus detalles.", "Click a host on the map to see its details.", "Clique em um host do mapa para ver os detalhes."),
    ("Exportar CSV", "Export CSV", "Exportar CSV"),
    ("Guardado en {}", "Saved to {}", "Salvo em {}"),
    ("No se pudo guardar: {}", "Could not save: {}", "Não foi possível salvar: {}"),
    // puertos
    ("Qué escucha este equipo y qué servicios ofrecen otros", "What this computer listens on and what services others offer", "O que este computador escuta e quais serviços os outros oferecem"),
    ("Escáner de puertos", "Port scanner", "Scanner de portas"),
    ("Puertos a la escucha", "Listening ports", "Portas em escuta"),
    ("servicios que aceptan conexiones", "services accepting connections", "serviços que aceitam conexões"),
    ("Conexiones establecidas", "Established connections", "Conexões estabelecidas"),
    ("comunicaciones activas", "active communications", "comunicações ativas"),
    ("Total de sockets", "Total sockets", "Total de sockets"),
    ("actualizado {}", "updated {}", "atualizado {}"),
    ("leyendo…", "reading…", "lendo…"),
    ("Filtrar:", "Filter:", "Filtrar:"),
    ("puerto, IP, programa…", "port, IP, program…", "porta, IP, programa…"),
    ("Mostrar también las conexiones (no solo los puertos a la escucha)", "Also show connections (not only listening ports)", "Mostrar também as conexões (não só portas em escuta)"),
    ("Protocolo", "Protocol", "Protocolo"),
    ("Dirección local", "Local address", "Endereço local"),
    ("Puerto", "Port", "Porta"),
    ("Servicio", "Service", "Serviço"),
    ("Remoto", "Remote", "Remoto"),
    ("Estado", "State", "Estado"),
    ("Programa", "Program", "Programa"),
    ("PID {}", "PID {}", "PID {}"),
    ("En ámbar: puertos abiertos a toda la red (0.0.0.0). El nombre del programa solo aparece para procesos propios o con permisos de administrador.", "In amber: ports open to the whole network (0.0.0.0). Program names only appear for your own processes or with administrator rights.", "Em âmbar: portas abertas para toda a rede (0.0.0.0). O nome do programa só aparece para processos próprios ou com permissões de administrador."),
    ("Escáner de puertos TCP", "TCP port scanner", "Scanner de portas TCP"),
    ("Equipo:", "Host:", "Host:"),
    ("192.168.1.1 o nombre", "192.168.1.1 or name", "192.168.1.1 ou nome"),
    ("Puertos:", "Ports:", "Portas:"),
    ("comunes, 1-1024, 22,80,443, todos", "comunes, 1-1024, 22,80,443, todos", "comunes, 1-1024, 22,80,443, todos"),
    ("Espera (ms):", "Timeout (ms):", "Espera (ms):"),
    ("Leer banners", "Grab banners", "Ler banners"),
    ("Puertos comprobados", "Ports checked", "Portas verificadas"),
    ("Escanear", "Scan", "Escanear"),
    ("Comunes", "Common", "Comuns"),
    ("Todos", "All", "Todas"),
    ("{}: {} abiertos · {} cerrados · {} filtrados · {:.1} s", "{}: {} open · {} closed · {} filtered · {:.1} s", "{}: {} abertas · {} fechadas · {} filtradas · {:.1} s"),
    ("Respuesta", "Response", "Resposta"),
    ("Banner / versión", "Banner / version", "Banner / versão"),
    ("desconocido", "unknown", "desconhecido"),
    ("Buscando…", "Searching…", "Procurando…"),
    ("Sin resultados todavía.", "No results yet.", "Ainda sem resultados."),
    ("Escanea solo equipos propios o con permiso de su dueño.", "Only scan your own hosts or with the owner's permission.", "Escaneie apenas hosts próprios ou com permissão do dono."),
    // captura
    ("Mira el tráfico paquete a paquete, guárdalo o abre capturas .pcap/.pcapng", "Inspect traffic packet by packet, save it or open .pcap/.pcapng captures", "Veja o tráfego pacote a pacote, salve-o ou abra capturas .pcap/.pcapng"),
    ("Interfaz:", "Interface:", "Interface:"),
    ("predeterminada", "default", "padrão"),
    ("Volver a buscar interfaces", "Search interfaces again", "Procurar interfaces novamente"),
    ("Iniciar captura", "Start capture", "Iniciar captura"),
    ("ruta de un .pcap o .pcapng", "path to a .pcap or .pcapng", "caminho de um .pcap ou .pcapng"),
    ("Abrir archivo", "Open file", "Abrir arquivo"),
    ("Guardar .pcap", "Save .pcap", "Salvar .pcap"),
    ("Guardados {} paquetes en {}", "Saved {} packets to {}", "{} pacotes salvos em {}"),
    ("Filtro:", "Filter:", "Filtro:"),
    ("dns, tcp, 443, 192.168.1.10, google…", "dns, tcp, 443, 192.168.1.10, google…", "dns, tcp, 443, 192.168.1.10, google…"),
    ("Seguir los últimos", "Follow latest", "Seguir os últimos"),
    ("{} · {} paquetes · {}", "{} · {} packets · {}", "{} · {} pacotes · {}"),
    ("sin captura", "no capture", "sem captura"),
    ("Para capturar en vivo hace falta Wireshark/Npcap instalado y abrir la app como administrador. Sin permisos puedes abrir archivos .pcap.", "Live capture needs Wireshark/Npcap installed and the app run as administrator. Without rights you can open .pcap files.", "Para capturar ao vivo é preciso ter Wireshark/Npcap instalado e abrir o app como administrador. Sem permissões você pode abrir arquivos .pcap."),
    ("Para capturar en vivo abre la app con sudo (o dale permiso una vez con setcap). Sin permisos puedes abrir archivos .pcap.", "For live capture run the app with sudo (or grant it once with setcap). Without rights you can open .pcap files.", "Para capturar ao vivo abra o app com sudo (ou dê permissão uma vez com setcap). Sem permissões você pode abrir arquivos .pcap."),
    ("Hora", "Time", "Hora"),
    ("Origen", "Source", "Origem"),
    ("Destino", "Destination", "Destino"),
    ("Información", "Info", "Informação"),
    ("No hay paquetes. Inicia una captura o abre un archivo.", "No packets. Start a capture or open a file.", "Não há pacotes. Inicie uma captura ou abra um arquivo."),
    ("Ningún paquete coincide con el filtro.", "No packet matches the filter.", "Nenhum pacote corresponde ao filtro."),
    ("Paquete {} · capas", "Packet {} · layers", "Pacote {} · camadas"),
    ("Bytes en hexadecimal", "Hex bytes", "Bytes em hexadecimal"),
    ("Pulsa un paquete para ver sus capas y bytes.", "Click a packet to see its layers and bytes.", "Clique em um pacote para ver camadas e bytes."),
    // análisis profundo
    ("Análisis profundo de paquetes", "Deep packet analysis", "Análise profunda de pacotes"),
    ("Protocolos, quién habla con quién, sitios visitados y salud de TCP", "Protocols, who talks to whom, sites visited and TCP health", "Protocolos, quem fala com quem, sites visitados e saúde do TCP"),
    ("Todavía no hay tráfico analizado. Inicia una captura (o abre un archivo .pcap) y vuelve aquí.", "No traffic analyzed yet. Start a capture (or open a .pcap file) and come back.", "Ainda não há tráfego analisado. Inicie uma captura (ou abra um .pcap) e volte aqui."),
    ("Paquetes", "Packets", "Pacotes"),
    ("{:.0} por segundo", "{:.0} per second", "{:.0} por segundo"),
    ("Datos", "Data", "Dados"),
    ("Protocolos distintos", "Distinct protocols", "Protocolos distintos"),
    ("detectados por contenido y puerto", "detected by content and port", "detectados por conteúdo e porta"),
    ("Conversaciones", "Conversations", "Conversas"),
    ("{} equipos", "{} hosts", "{} hosts"),
    ("Protocolos (por volumen)", "Protocols (by volume)", "Protocolos (por volume)"),
    ("{} · {} paq.", "{} · {} pkts", "{} · {} pac."),
    ("Tráfico capturado por segundo", "Captured traffic per second", "Tráfego capturado por segundo"),
    ("Equipos que más hablan", "Top talkers", "Hosts que mais falam"),
    ("Dirección", "Address", "Endereço"),
    ("Enviado", "Sent", "Enviado"),
    ("Recibido", "Received", "Recebido"),
    ("Conversaciones principales", "Top conversations", "Principais conversas"),
    ("Equipo A", "Host A", "Host A"),
    ("Equipo B", "Host B", "Host B"),
    ("Nombres consultados por DNS", "Names queried via DNS", "Nomes consultados por DNS"),
    ("Sin consultas DNS en la captura.", "No DNS queries in the capture.", "Sem consultas DNS na captura."),
    ("Sitios cifrados (TLS · nombre del servidor)", "Encrypted sites (TLS · server name)", "Sites criptografados (TLS · nome do servidor)"),
    ("Sin conexiones TLS nuevas en la captura.", "No new TLS connections in the capture.", "Sem novas conexões TLS na captura."),
    ("Salud de las conexiones TCP", "TCP connection health", "Saúde das conexões TCP"),
    ("Intentos de conexión (SYN)", "Connection attempts (SYN)", "Tentativas de conexão (SYN)"),
    ("Aceptadas (SYN-ACK)", "Accepted (SYN-ACK)", "Aceitas (SYN-ACK)"),
    ("Reinicios (RST)", "Resets (RST)", "Reinícios (RST)"),
    ("Muchas conexiones sin respuesta: puede haber un escaneo, un cortafuegos bloqueando o un servicio caído.", "Many unanswered connections: there may be a scan, a blocking firewall or a service down.", "Muitas conexões sem resposta: pode haver um escaneamento, um firewall bloqueando ou um serviço fora do ar."),
    ("Las conexiones se establecen con normalidad.", "Connections are being established normally.", "As conexões estão sendo estabelecidas normalmente."),
    ("Peticiones web sin cifrar (HTTP) y DHCP", "Unencrypted web requests (HTTP) and DHCP", "Requisições web sem criptografia (HTTP) e DHCP"),
    ("Nada que mostrar.", "Nothing to show.", "Nada para mostrar."),
    // latencia
    ("Latencia y pérdida de paquetes", "Latency and packet loss", "Latência e perda de pacotes"),
    ("Mide el retardo, la variación (jitter) y los paquetes perdidos, y sigue la ruta", "Measure delay, variation (jitter) and lost packets, and trace the route", "Meça o atraso, a variação (jitter) e os pacotes perdidos, e siga a rota"),
    ("Destino:", "Target:", "Destino:"),
    ("Ping (ICMP)", "Ping (ICMP)", "Ping (ICMP)"),
    ("Conexión TCP al puerto", "TCP connection to port", "Conexão TCP à porta"),
    ("Cada", "Every", "A cada"),
    ("Iniciar", "Start", "Iniciar"),
    ("Rápidos:", "Quick:", "Rápidos:"),
    ("· midiendo {}", "· measuring {}", "· medindo {}"),
    ("Enviados / recibidos", "Sent / received", "Enviados / recebidos"),
    ("Pérdida", "Loss", "Perda"),
    ("Latencia media", "Average latency", "Latência média"),
    ("mín {:.1} · máx {:.1}", "min {:.1} · max {:.1}", "mín {:.1} · máx {:.1}"),
    ("desv. {:.1} ms", "dev. {:.1} ms", "desv. {:.1} ms"),
    ("Percentil 95", "95th percentile", "Percentil 95"),
    ("MOS (voz)", "MOS (voice)", "MOS (voz)"),
    ("de 1 a 4.5", "from 1 to 4.5", "de 1 a 4,5"),
    ("Latencia en el tiempo (marcas rojas = paquetes perdidos)", "Latency over time (red marks = lost packets)", "Latência no tempo (marcas vermelhas = pacotes perdidos)"),
    ("Hay pérdida de paquetes ({:.1} %): revisa el Wi-Fi, el cable o la saturación de la línea.", "There is packet loss ({:.1} %): check the Wi-Fi, the cable or line congestion.", "Há perda de pacotes ({:.1} %): verifique o Wi-Fi, o cabo ou a saturação da linha."),
    ("El jitter es alto: las llamadas y videollamadas pueden cortarse.", "Jitter is high: calls and video calls may break up.", "O jitter está alto: chamadas e videochamadas podem falhar."),
    ("La latencia es alta para juegos y llamadas.", "Latency is high for gaming and calls.", "A latência está alta para jogos e chamadas."),
    ("Gran parte del retardo está ya en tu red local (router o Wi-Fi).", "Much of the delay is already in your local network (router or Wi-Fi).", "Grande parte do atraso já está na sua rede local (roteador ou Wi-Fi)."),
    ("Conexión estable: sin pérdidas ni retardos relevantes.", "Stable connection: no significant loss or delay.", "Conexão estável: sem perdas nem atrasos relevantes."),
    ("Ruta hasta el destino (traceroute)", "Route to target (traceroute)", "Rota até o destino (traceroute)"),
    ("Trazando…", "Tracing…", "Rastreando…"),
    ("Trazar ruta", "Trace route", "Rastrear rota"),
    ("* (sin respuesta)", "* (no reply)", "* (sem resposta)"),
    ("Salida completa", "Full output", "Saída completa"),
    // calidad
    ("Calidad de experiencia (QoE)", "Quality of experience (QoE)", "Qualidade de experiência (QoE)"),
    ("Cómo se sentirá tu conexión en llamadas, vídeo, juegos y navegación", "How your connection will feel for calls, video, gaming and browsing", "Como sua conexão vai se comportar em chamadas, vídeo, jogos e navegação"),
    ("Medir calidad ahora", "Measure quality now", "Medir qualidade agora"),
    ("Archivo de prueba de velocidad:", "Speed test file:", "Arquivo de teste de velocidade:"),
    ("Descarga en curso: {}", "Downloading: {}", "Download em andamento: {}"),
    ("Tarda unos 20 segundos: mide el router, Internet (1.1.1.1), el DNS, el tiempo de conexión y la velocidad de descarga.", "Takes about 20 seconds: measures the router, Internet (1.1.1.1), DNS, connection time and download speed.", "Leva uns 20 segundos: mede o roteador, a Internet (1.1.1.1), o DNS, o tempo de conexão e a velocidade de download."),
    ("Nota global", "Overall score", "Nota geral"),
    ("de 100", "out of 100", "de 100"),
    ("MOS de voz {:.2} · factor R {:.0}", "Voice MOS {:.2} · R factor {:.0}", "MOS de voz {:.2} · fator R {:.0}"),
    ("Velocidad no medida: {}", "Speed not measured: {}", "Velocidade não medida: {}"),
    ("Por tipo de uso", "By type of use", "Por tipo de uso"),
    ("resolución de nombres", "name resolution", "resolução de nomes"),
    ("Conexión web", "Web connection", "Conexão web"),
    ("tiempo de conexión TCP", "TCP connect time", "tempo de conexão TCP"),
    ("Descarga", "Download", "Download"),
    ("Subida", "Upload", "Upload"),
    // dns
    ("Consulta registros, compara servidores y revisa la seguridad del dominio", "Query records, compare servers and check the domain's security", "Consulte registros, compare servidores e verifique a segurança do domínio"),
    ("Consulta", "Query", "Consulta"),
    ("Dominio:", "Domain:", "Domínio:"),
    ("Servidor:", "Server:", "Servidor:"),
    ("Otro…", "Other…", "Outro…"),
    ("IP del servidor", "Server IP", "IP do servidor"),
    ("Consultar", "Query", "Consultar"),
    ("Análisis completo", "Full analysis", "Análise completa"),
    ("{} · {:.1} ms · indicadores: {}", "{} · {:.1} ms · flags: {}", "{} · {:.1} ms · flags: {}"),
    ("DNSSEC verificado", "DNSSEC verified", "DNSSEC verificado"),
    ("Valor", "Value", "Valor"),
    ("autoridad · ", "authority · ", "autoridade · "),
    ("La respuesta no trae registros.", "The answer has no records.", "A resposta não traz registros."),
    ("Velocidad de los servidores DNS", "DNS server speed", "Velocidade dos servidores DNS"),
    ("sin respuesta", "no reply", "sem resposta"),
    ("Registros del dominio", "Domain records", "Registros do domínio"),
    ("Diagnóstico y seguridad del DNS", "DNS diagnosis and security", "Diagnóstico e segurança do DNS"),
    ("Analizando…", "Analyzing…", "Analisando…"),
    ("Sistema", "System", "Sistema"),
    // seguridad
    ("Seguridad y vulnerabilidades", "Security and vulnerabilities", "Segurança e vulnerabilidades"),
    ("Busca servicios expuestos, contraseñas por defecto y software antiguo", "Find exposed services, default passwords and outdated software", "Procure serviços expostos, senhas padrão e software antigo"),
    ("IP o nombre", "IP or name", "IP ou nome"),
    ("Auditar este equipo", "Audit this host", "Auditar este host"),
    ("Auditar el router", "Audit the router", "Auditar o roteador"),
    ("Auditar toda la red ({} equipos)", "Audit whole network ({} hosts)", "Auditar toda a rede ({} hosts)"),
    ("Primero escanea la red", "Scan the network first", "Primeiro escaneie a rede"),
    ("Audita solo equipos propios o con permiso. Se comprueban unos 60 puertos habituales, banners, accesos anónimos (FTP, Redis, Memcached, Docker, Elasticsearch), SNMP «public», UPnP y DNS abiertos.", "Only audit your own hosts or with permission. About 60 common ports are checked, plus banners, anonymous access (FTP, Redis, Memcached, Docker, Elasticsearch), SNMP «public», UPnP and open DNS.", "Audite apenas hosts próprios ou com permissão. São verificadas cerca de 60 portas comuns, banners, acessos anônimos (FTP, Redis, Memcached, Docker, Elasticsearch), SNMP «public», UPnP e DNS abertos."),
    ("Puntuación de seguridad", "Security score", "Pontuação de segurança"),
    ("{} hallazgos", "{} findings", "{} achados"),
    ("Servicios abiertos encontrados", "Open services found", "Serviços abertos encontrados"),
    ("Ninguno todavía.", "None yet.", "Nenhum ainda."),
    ("Hallazgos", "Findings", "Achados"),
    ("Cómo arreglarlo: {}", "How to fix it: {}", "Como corrigir: {}"),
    // ids
    ("Detección de intrusos y anomalías", "Intrusion and anomaly detection", "Detecção de intrusões e anomalias"),
    ("Vigila escaneos, suplantaciones, inundaciones, túneles DNS y contraseñas en claro", "Watches for scans, spoofing, floods, DNS tunnels and cleartext passwords", "Vigia escaneamentos, falsificações, inundações, túneis DNS e senhas em texto claro"),
    ("Alertas {}", "{} alerts", "Alertas {}"),
    ("Fuentes vigiladas", "Watched sources", "Fontes monitoradas"),
    ("Detector activo", "Detector on", "Detector ativo"),
    ("Captura en vivo: activa", "Live capture: on", "Captura ao vivo: ativa"),
    ("Captura en vivo: parada", "Live capture: stopped", "Captura ao vivo: parada"),
    ("{} paquetes analizados", "{} packets analyzed", "{} pacotes analisados"),
    ("Iniciar captura para el detector", "Start capture for the detector", "Iniciar captura para o detector"),
    ("Tabla ARP: cada 10 s", "ARP table: every 10 s", "Tabela ARP: a cada 10 s"),
    ("Equipos vigilados: {}", "Watched hosts: {}", "Hosts monitorados: {}"),
    ("Tráfico por interfaz: cada 1 s", "Traffic per interface: every 1 s", "Tráfego por interface: a cada 1 s"),
    ("Sin captura solo se detectan suplantaciones ARP, equipos nuevos o caídos y picos de tráfico. Con captura se analizan todos los paquetes.", "Without capture only ARP spoofing, new or down hosts and traffic spikes are detected. With capture every packet is analyzed.", "Sem captura só são detectadas falsificações ARP, hosts novos ou fora do ar e picos de tráfego. Com captura todos os pacotes são analisados."),
    ("Alertas", "Alerts", "Alertas"),
    ("Mostrar desde:", "Show from:", "Mostrar a partir de:"),
    ("Borrar alertas", "Clear alerts", "Apagar alertas"),
    ("Nivel", "Level", "Nível"),
    ("Descripción", "Description", "Descrição"),
    ("Sin alertas por ahora.", "No alerts for now.", "Sem alertas por enquanto."),
    ("Reglas de detección", "Detection rules", "Regras de detecção"),
    // monitor
    ("Tráfico de cada interfaz y disponibilidad de los equipos que te importan", "Traffic of each interface and availability of the hosts you care about", "Tráfego de cada interface e disponibilidade dos hosts que importam"),
    ("Tráfico", "Traffic", "Tráfego"),
    ("Todas", "All", "Todas"),
    ("Interfaz", "Interface", "Interface"),
    ("Total recibido", "Total received", "Total recebido"),
    ("Total enviado", "Total sent", "Total enviado"),
    ("Equipos vigilados (ping cada 5 s)", "Watched hosts (ping every 5 s)", "Hosts monitorados (ping a cada 5 s)"),
    ("IP o nombre, p. ej. 192.168.1.20 o google.com", "IP or name, e.g. 192.168.1.20 or google.com", "IP ou nome, ex. 192.168.1.20 ou google.com"),
    ("Añadir", "Add", "Adicionar"),
    ("Vigilar el router", "Watch the router", "Monitorar o roteador"),
    ("Activo", "Up", "Ativo"),
    ("Caído", "Down", "Fora do ar"),
    ("Comprobando", "Checking", "Verificando"),
    ("disponible {:.1}%", "available {:.1}%", "disponível {:.1}%"),
    ("Quitar", "Remove", "Remover"),
    ("Añade servidores, cámaras o el router: si dejan de responder aparecerá una alerta.", "Add servers, cameras or the router: if they stop responding you'll get an alert.", "Adicione servidores, câmeras ou o roteador: se pararem de responder aparecerá um alerta."),
    ("Latencia al router (cada 2 s)", "Latency to router (every 2 s)", "Latência até o roteador (a cada 2 s)"),
    // herramientas
    ("Utilidades rápidas para la red", "Quick network utilities", "Utilitários rápidos para a rede"),
    ("Mi IP pública", "My public IP", "Meu IP público"),
    ("Consultar IP pública", "Look up public IP", "Consultar IP público"),
    ("IP pública", "Public IP", "IP público"),
    ("País", "Country", "País"),
    ("Ciudad", "City", "Cidade"),
    ("Proveedor", "Provider", "Provedor"),
    ("Sistema autónomo", "Autonomous system", "Sistema autônomo"),
    ("Zona horaria", "Time zone", "Fuso horário"),
    ("Usa el servicio público ip-api.com.", "Uses the public ip-api.com service.", "Usa o serviço público ip-api.com."),
    ("Calculadora de subredes", "Subnet calculator", "Calculadora de sub-redes"),
    ("Dirección/prefijo:", "Address/prefix:", "Endereço/prefixo:"),
    ("Red", "Network", "Rede"),
    ("Máscara", "Mask", "Máscara"),
    ("Comodín", "Wildcard", "Curinga"),
    ("Difusión", "Broadcast", "Broadcast"),
    ("Primer equipo", "First host", "Primeiro host"),
    ("Último equipo", "Last host", "Último host"),
    ("Equipos utilizables", "Usable hosts", "Hosts utilizáveis"),
    ("Clase / ámbito", "Class / scope", "Classe / escopo"),
    ("Formato no válido. Ejemplo: 192.168.1.10/24", "Invalid format. Example: 192.168.1.10/24", "Formato inválido. Exemplo: 192.168.1.10/24"),
    ("privada", "private", "privada"),
    ("pública", "public", "pública"),
    ("Encender equipos a distancia (Wake-on-LAN)", "Wake computers remotely (Wake-on-LAN)", "Ligar computadores remotamente (Wake-on-LAN)"),
    ("MAC del equipo:", "Host MAC:", "MAC do host:"),
    ("Enviar paquete mágico", "Send magic packet", "Enviar pacote mágico"),
    ("Paquete mágico enviado a {}", "Magic packet sent to {}", "Pacote mágico enviado para {}"),
    ("MAC no válida", "Invalid MAC", "MAC inválido"),
    ("El equipo debe tener Wake-on-LAN activado en la BIOS y en la tarjeta de red.", "The computer needs Wake-on-LAN enabled in the BIOS and network card.", "O computador precisa ter Wake-on-LAN ativado na BIOS e na placa de rede."),
    ("Buscar fabricante por MAC", "Look up vendor by MAC", "Procurar fabricante por MAC"),
    ("Fabricante: {}", "Vendor: {}", "Fabricante: {}"),
    ("No está en la lista interna de fabricantes.", "Not in the built-in vendor list.", "Não está na lista interna de fabricantes."),
    // ajustes
    ("Idioma, aspecto y preferencias (se guardan solas)", "Language, appearance and preferences (saved automatically)", "Idioma, aparência e preferências (salvos automaticamente)"),
    ("Idioma", "Language", "Idioma"),
    ("Tema", "Theme", "Tema"),
    ("Oscuro", "Dark", "Escuro"),
    ("Claro", "Light", "Claro"),
    ("Medianoche", "Midnight", "Meia-noite"),
    ("Terminal", "Terminal", "Terminal"),
    ("Tamaño de la interfaz", "Interface size", "Tamanho da interface"),
    ("Acerca de", "About", "Sobre"),
    ("Versión {}", "Version {}", "Versão {}"),
    ("Ajustes guardados en {}", "Settings saved in {}", "Configurações salvas em {}"),
    ("Escanear la red al abrir la app", "Scan the network when the app opens", "Escanear a rede ao abrir o app"),
    ("Analizador de red ligero y multiplataforma (Linux, Windows y macOS).", "Lightweight cross-platform network analyzer (Linux, Windows and macOS).", "Analisador de rede leve e multiplataforma (Linux, Windows e macOS)."),
    ("El destino no responde al ping.", "The target doesn't answer ping.", "O destino não responde ao ping."),
    ("Tamaño máximo de paquete (MTU de la ruta)", "Maximum packet size (path MTU)", "Tamanho máximo de pacote (MTU da rota)"),
    ("Medir MTU", "Measure MTU", "Medir MTU"),
    ("Probando con {} bytes…", "Trying {} bytes…", "Testando com {} bytes…"),
    ("MTU de la ruta: {} bytes", "Path MTU: {} bytes", "MTU da rota: {} bytes"),
    ("Menor de 1500: hay un túnel, VPN o PPPoE en el camino. Si algunas webs no cargan, baja la MTU del equipo a este valor.", "Below 1500: there's a tunnel, VPN or PPPoE on the way. If some sites don't load, lower this computer's MTU to this value.", "Menor que 1500: há um túnel, VPN ou PPPoE no caminho. Se alguns sites não carregam, reduza a MTU do computador para esse valor."),
    ("Encuentra el paquete más grande que llega sin partirse; útil para problemas con VPN o webs que no cargan.", "Finds the largest packet that arrives unfragmented; useful for VPN issues or sites that won't load.", "Encontra o maior pacote que chega sem ser fragmentado; útil para problemas com VPN ou sites que não carregam."),
    ("Tabla ARP del sistema", "System ARP table", "Tabela ARP do sistema"),
    ("Actualizar", "Refresh", "Atualizar"),
    ("Dispositivos UPnP (televisores, routers, NAS…)", "UPnP devices (TVs, routers, NAS…)", "Dispositivos UPnP (TVs, roteadores, NAS…)"),
    ("Buscar dispositivos UPnP", "Find UPnP devices", "Procurar dispositivos UPnP"),
    ("Modelo", "Model", "Modelo"),
    ("Sin respuestas UPnP.", "No UPnP replies.", "Sem respostas UPnP."),
    ("Servicios Bonjour / mDNS (impresoras, Chromecast, AirPlay…)", "Bonjour / mDNS services (printers, Chromecast, AirPlay…)", "Serviços Bonjour / mDNS (impressoras, Chromecast, AirPlay…)"),
    ("Buscar servicios mDNS", "Find mDNS services", "Procurar serviços mDNS"),
    ("Sin respuestas mDNS.", "No mDNS replies.", "Sem respostas mDNS."),
    ("Interfaces y rutas del sistema", "System interfaces and routes", "Interfaces e rotas do sistema"),
    ("Ver interfaces", "Show interfaces", "Ver interfaces"),
    ("Ver rutas", "Show routes", "Ver rotas"),
    ("Escáner", "Scanner", "Scanner"),
    ("Altavoz (AirPlay)", "Speaker (AirPlay)", "Alto-falante (AirPlay)"),
    ("Archivos (SMB)", "Files (SMB)", "Arquivos (SMB)"),
    ("Cómo arreglarlo", "How to fix", "Como corrigir"),
    ("Equipo", "Host", "Host"),
    // backend: niveles, tipos, notas
    ("Info", "Info", "Info"),
    ("Baja", "Low", "Baixa"),
    ("Media", "Medium", "Média"),
    ("Alta", "High", "Alta"),
    ("Crítica", "Critical", "Crítica"),
    ("Router", "Router", "Roteador"),
    ("Ordenador", "Computer", "Computador"),
    ("Móvil/Tablet", "Phone/Tablet", "Celular/Tablet"),
    ("Impresora", "Printer", "Impressora"),
    ("Servidor", "Server", "Servidor"),
    ("TV/Multimedia", "TV/Media", "TV/Multimídia"),
    ("IoT/Cámara", "IoT/Camera", "IoT/Câmera"),
    ("Desconocido", "Unknown", "Desconhecido"),
    ("Excelente", "Excellent", "Excelente"),
    ("Buena", "Good", "Boa"),
    ("Aceptable", "Fair", "Aceitável"),
    ("Mala", "Poor", "Ruim"),
    ("Muy mala", "Very poor", "Muito ruim"),
    // reglas y alertas
    ("Escaneo de puertos", "Port scan", "Escaneamento de portas"),
    ("Un equipo prueba 20 o más puertos distintos en 10 segundos.", "A host probes 20 or more different ports in 10 seconds.", "Um host testa 20 ou mais portas diferentes em 10 segundos."),
    ("Escaneo sigiloso", "Stealth scan", "Escaneamento furtivo"),
    ("Paquetes TCP NULL, FIN o XMAS, típicos de herramientas de escaneo.", "TCP NULL, FIN or XMAS packets, typical of scanning tools.", "Pacotes TCP NULL, FIN ou XMAS, típicos de ferramentas de escaneamento."),
    ("Barrido de red", "Network sweep", "Varredura de rede"),
    ("Un equipo contacta 25 o más direcciones distintas en 10 segundos.", "A host contacts 25 or more different addresses in 10 seconds.", "Um host contata 25 ou mais endereços diferentes em 10 segundos."),
    ("Inundación SYN", "SYN flood", "Inundação SYN"),
    ("Más de 300 intentos de conexión por segundo a un mismo destino.", "More than 300 connection attempts per second to one target.", "Mais de 300 tentativas de conexão por segundo para um mesmo destino."),
    ("Inundación ICMP", "ICMP flood", "Inundação ICMP"),
    ("Más de 50 pings por segundo desde un mismo equipo.", "More than 50 pings per second from one host.", "Mais de 50 pings por segundo de um mesmo host."),
    ("Suplantación ARP", "ARP spoofing", "Falsificação ARP"),
    ("Una IP cambia de MAC o una MAC se hace pasar por la puerta de enlace.", "An IP changes MAC or a MAC impersonates the gateway.", "Um IP muda de MAC ou um MAC se passa pelo gateway."),
    ("DHCP no autorizado", "Rogue DHCP", "DHCP não autorizado"),
    ("Ofertas DHCP de un servidor que no es el router.", "DHCP offers from a server that isn't the router.", "Ofertas DHCP de um servidor que não é o roteador."),
    ("Túnel DNS", "DNS tunnel", "Túnel DNS"),
    ("Nombres DNS muy largos o aleatorios, típicos de exfiltración de datos.", "Very long or random DNS names, typical of data exfiltration.", "Nomes DNS muito longos ou aleatórios, típicos de exfiltração de dados."),
    ("Puertos sospechosos", "Suspicious ports", "Portas suspeitas"),
    ("Tráfico hacia puertos usados por troyanos o botnets (4444, 31337, 6667…).", "Traffic to ports used by trojans or botnets (4444, 31337, 6667…).", "Tráfego para portas usadas por trojans ou botnets (4444, 31337, 6667…)."),
    ("Credenciales en claro", "Cleartext credentials", "Credenciais em texto claro"),
    ("Usuarios y contraseñas enviados sin cifrar (FTP, Telnet, POP3, HTTP Basic).", "Usernames and passwords sent unencrypted (FTP, Telnet, POP3, HTTP Basic).", "Usuários e senhas enviados sem criptografia (FTP, Telnet, POP3, HTTP Basic)."),
    ("Nuevo dispositivo", "New device", "Novo dispositivo"),
    ("Aparece en la red una MAC que no se había visto.", "A MAC not seen before appears on the network.", "Aparece na rede um MAC nunca visto."),
    ("Pico de tráfico", "Traffic spike", "Pico de tráfego"),
    ("El tráfico de una interfaz supera mucho su comportamiento normal.", "An interface's traffic far exceeds its normal behaviour.", "O tráfego de uma interface supera muito o normal."),
    ("Equipo caído", "Host down", "Host fora do ar"),
    ("Un equipo vigilado deja de responder.", "A watched host stops responding.", "Um host monitorado para de responder."),
    ("{} está ofreciendo direcciones DHCP y no es el router ({}).", "{} is offering DHCP addresses and is not the router ({}).", "{} está oferecendo endereços DHCP e não é o roteador ({})."),
    ("Escaneo TCP {} desde {} hacia {}:{}", "TCP {} scan from {} to {}:{}", "Escaneamento TCP {} de {} para {}:{}"),
    ("{} probó {} puertos distintos en 10 s (último destino {}).", "{} probed {} different ports in 10 s (last target {}).", "{} testou {} portas diferentes em 10 s (último destino {})."),
    ("{} contactó {} equipos distintos en 10 s.", "{} contacted {} different hosts in 10 s.", "{} contatou {} hosts diferentes em 10 s."),
    ("Más de 300 conexiones/s hacia {} (posible ataque de denegación de servicio).", "More than 300 connections/s to {} (possible denial-of-service attack).", "Mais de 300 conexões/s para {} (possível ataque de negação de serviço)."),
    ("{} envía más de 50 pings por segundo.", "{} sends more than 50 pings per second.", "{} envia mais de 50 pings por segundo."),
    ("Consulta DNS anómala ({} caracteres): {}", "Anomalous DNS query ({} characters): {}", "Consulta DNS anômala ({} caracteres): {}"),
    ("Tráfico {} → {} en el puerto {}, usado a menudo por malware.", "Traffic {} → {} on port {}, often used by malware.", "Tráfego {} → {} na porta {}, usada com frequência por malware."),
    ("{} envió una contraseña sin cifrar a {}:{} ({}).", "{} sent an unencrypted password to {}:{} ({}).", "{} enviou uma senha sem criptografia para {}:{} ({})."),
    ("La IP {} cambió de MAC: {} → {}. Puede ser un ataque de intermediario (ARP spoofing).", "IP {} changed MAC: {} → {}. It may be a man-in-the-middle attack (ARP spoofing).", "O IP {} mudou de MAC: {} → {}. Pode ser um ataque man-in-the-middle (ARP spoofing)."),
    ("La MAC del router ({}) también aparece en {}. Puede ser un router con varias IP o un ataque de intermediario.", "The router's MAC ({}) also appears on {}. It may be a router with several IPs or a man-in-the-middle attack.", "O MAC do roteador ({}) também aparece em {}. Pode ser um roteador com vários IPs ou um ataque man-in-the-middle."),
    ("Nuevo equipo en la red: {} ({}) {}", "New host on the network: {} ({}) {}", "Novo host na rede: {} ({}) {}"),
    ("Apareció {} {} {} desde el último escaneo.", "{} {} {} appeared since the last scan.", "{} {} {} apareceu desde o último escaneamento."),
    ("La interfaz {} alcanzó {} (lo normal es {}).", "Interface {} reached {} (normal is {}).", "A interface {} atingiu {} (o normal é {})."),
    ("{} vuelve a responder.", "{} is responding again.", "{} voltou a responder."),
    ("{} ha dejado de responder.", "{} has stopped responding.", "{} parou de responder."),
    // auditoría
    ("No se pudo resolver", "Could not resolve", "Não foi possível resolver"),
    ("El nombre no existe o no hay DNS.", "The name doesn't exist or there's no DNS.", "O nome não existe ou não há DNS."),
    ("Telnet activo", "Telnet enabled", "Telnet ativo"),
    ("Telnet envía usuario y contraseña sin cifrar.", "Telnet sends username and password unencrypted.", "Telnet envia usuário e senha sem criptografia."),
    ("Desactiva Telnet y usa SSH.", "Disable Telnet and use SSH.", "Desative o Telnet e use SSH."),
    ("FTP con acceso anónimo", "FTP with anonymous access", "FTP com acesso anônimo"),
    ("Cualquiera puede entrar al FTP sin contraseña.", "Anyone can log into the FTP without a password.", "Qualquer um pode entrar no FTP sem senha."),
    ("Desactiva el acceso anónimo.", "Disable anonymous access.", "Desative o acesso anônimo."),
    ("FTP sin cifrar", "Unencrypted FTP", "FTP sem criptografia"),
    ("Usa SFTP o FTPS.", "Use SFTP or FTPS.", "Use SFTP ou FTPS."),
    ("Compartición de archivos (SMB) expuesta", "File sharing (SMB) exposed", "Compartilhamento de arquivos (SMB) exposto"),
    ("SMB ha sido vía de ataques graves (p. ej. WannaCry).", "SMB has been the path of serious attacks (e.g. WannaCry).", "O SMB já foi via de ataques graves (ex. WannaCry)."),
    ("Limita SMB a la red local y mantén el sistema actualizado.", "Limit SMB to the local network and keep the system updated.", "Limite o SMB à rede local e mantenha o sistema atualizado."),
    ("Escritorio remoto (RDP) abierto", "Remote desktop (RDP) open", "Área de trabalho remota (RDP) aberta"),
    ("Los ataques de fuerza bruta contra RDP son muy comunes.", "Brute-force attacks against RDP are very common.", "Ataques de força bruta contra RDP são muito comuns."),
    ("Usa VPN o activa la autenticación a nivel de red.", "Use a VPN or enable network level authentication.", "Use VPN ou ative a autenticação em nível de rede."),
    ("VNC abierto", "VNC open", "VNC aberto"),
    ("Control remoto accesible. {}", "Remote control reachable. {}", "Controle remoto acessível. {}"),
    ("Protégelo con contraseña fuerte o túnel SSH.", "Protect it with a strong password or an SSH tunnel.", "Proteja com senha forte ou túnel SSH."),
    ("Redis sin contraseña", "Redis without password", "Redis sem senha"),
    ("La base de datos Redis responde sin autenticación.", "The Redis database answers without authentication.", "O banco Redis responde sem autenticação."),
    ("Activa requirepass y no la expongas a la red.", "Enable requirepass and don't expose it to the network.", "Ative requirepass e não o exponha à rede."),
    ("Redis expuesto", "Redis exposed", "Redis exposto"),
    ("Redis acepta conexiones desde la red.", "Redis accepts connections from the network.", "O Redis aceita conexões da rede."),
    ("Limítalo a localhost.", "Restrict it to localhost.", "Limite-o ao localhost."),
    ("Memcached sin protección", "Unprotected Memcached", "Memcached sem proteção"),
    ("Memcached responde a cualquiera y puede usarse para ataques de amplificación.", "Memcached answers anyone and can be used for amplification attacks.", "O Memcached responde a qualquer um e pode ser usado em ataques de amplificação."),
    ("Escucha solo en localhost.", "Listen on localhost only.", "Escute apenas no localhost."),
    ("Elasticsearch sin autenticación", "Elasticsearch without authentication", "Elasticsearch sem autenticação"),
    ("Los datos del índice son accesibles.", "The index data is reachable.", "Os dados do índice estão acessíveis."),
    ("Activa la seguridad de Elasticsearch.", "Enable Elasticsearch security.", "Ative a segurança do Elasticsearch."),
    ("API de Docker sin protección", "Unprotected Docker API", "API do Docker sem proteção"),
    ("Quien acceda puede controlar todo el equipo.", "Whoever reaches it can control the whole machine.", "Quem acessar pode controlar todo o computador."),
    ("Cierra el puerto 2375 o usa TLS (2376).", "Close port 2375 or use TLS (2376).", "Feche a porta 2375 ou use TLS (2376)."),
    ("MongoDB expuesto", "MongoDB exposed", "MongoDB exposto"),
    ("La base de datos acepta conexiones de la red.", "The database accepts network connections.", "O banco de dados aceita conexões da rede."),
    ("Activa autenticación y limita el acceso.", "Enable authentication and restrict access.", "Ative autenticação e limite o acesso."),
    ("Base de datos accesible en la red", "Database reachable on the network", "Banco de dados acessível na rede"),
    ("{} escucha en {}. {}", "{} listens on {}. {}", "{} escuta em {}. {}"),
    ("Permite solo los equipos que la necesitan.", "Allow only the hosts that need it.", "Permita apenas os hosts que precisam."),
    ("Puerto típico de puerta trasera", "Typical backdoor port", "Porta típica de backdoor"),
    ("El puerto {} suele usarlo malware. {}", "Port {} is often used by malware. {}", "A porta {} costuma ser usada por malware. {}"),
    ("Revisa qué programa lo abre y analiza el equipo.", "Check which program opens it and scan the machine.", "Verifique qual programa a abre e analise o computador."),
    ("MQTT sin cifrar", "Unencrypted MQTT", "MQTT sem criptografia"),
    ("Mensajería IoT accesible sin TLS.", "IoT messaging reachable without TLS.", "Mensageria IoT acessível sem TLS."),
    ("Usa 8883 con TLS y usuario/contraseña.", "Use 8883 with TLS and user/password.", "Use 8883 com TLS e usuário/senha."),
    ("SSH versión 1", "SSH version 1", "SSH versão 1"),
    ("SSH-1 tiene fallos criptográficos.", "SSH-1 has cryptographic flaws.", "O SSH-1 tem falhas criptográficas."),
    ("Usa solo SSH-2.", "Use SSH-2 only.", "Use apenas SSH-2."),
    ("OpenSSH antiguo", "Outdated OpenSSH", "OpenSSH antigo"),
    ("Versión {}.", "Version {}.", "Versão {}."),
    ("Actualiza OpenSSH a una versión reciente.", "Update OpenSSH to a recent version.", "Atualize o OpenSSH para uma versão recente."),
    ("El servidor web muestra su versión", "The web server shows its version", "O servidor web mostra sua versão"),
    ("Cabecera Server: {}", "Server header: {}", "Cabeçalho Server: {}"),
    ("Oculta la versión para no dar pistas a atacantes.", "Hide the version so as not to help attackers.", "Oculte a versão para não dar pistas a atacantes."),
    ("Panel web en puerto alternativo", "Web panel on alternative port", "Painel web em porta alternativa"),
    ("Servicio web en {}: {}", "Web service on {}: {}", "Serviço web em {}: {}"),
    ("Comprueba que tenga contraseña y esté actualizado.", "Check it has a password and is up to date.", "Verifique se tem senha e está atualizado."),
    ("Web sin HTTPS", "Web without HTTPS", "Web sem HTTPS"),
    ("El equipo ofrece web sin cifrar.", "The host serves unencrypted web.", "O host oferece web sem criptografia."),
    ("Activa HTTPS.", "Enable HTTPS.", "Ative o HTTPS."),
    ("SNMP con comunidad «public»", "SNMP with «public» community", "SNMP com comunidade «public»"),
    ("Responde con la comunidad por defecto: {}", "Answers with the default community: {}", "Responde com a comunidade padrão: {}"),
    ("Cambia la comunidad o usa SNMPv3.", "Change the community or use SNMPv3.", "Mude a comunidade ou use SNMPv3."),
    ("UPnP activo", "UPnP enabled", "UPnP ativo"),
    ("El equipo anuncia servicios UPnP; algunos programas pueden abrir puertos solos.", "The host announces UPnP services; some programs can open ports by themselves.", "O host anuncia serviços UPnP; alguns programas podem abrir portas sozinhos."),
    ("Desactiva UPnP en el router si no lo necesitas.", "Disable UPnP on the router if you don't need it.", "Desative o UPnP no roteador se não precisar."),
    ("El router resuelve DNS", "The router resolves DNS", "O roteador resolve DNS"),
    ("Normal en redes domésticas.", "Normal on home networks.", "Normal em redes domésticas."),
    ("Resolvedor DNS abierto", "Open DNS resolver", "Resolvedor DNS aberto"),
    ("Responde consultas recursivas de cualquiera; puede usarse para ataques de amplificación.", "Answers recursive queries from anyone; can be used for amplification attacks.", "Responde consultas recursivas de qualquer um; pode ser usado em ataques de amplificação."),
    ("Limita la recursión a tus equipos.", "Limit recursion to your hosts.", "Limite a recursão aos seus hosts."),
    ("Sin puertos habituales abiertos", "No common ports open", "Sem portas comuns abertas"),
    ("No se encontraron servicios en los puertos comprobados.", "No services found on the checked ports.", "Nenhum serviço encontrado nas portas verificadas."),
    ("Auditando {}…", "Auditing {}…", "Auditando {}…"),
    ("Auditoría terminada", "Audit finished", "Auditoria concluída"),
    // dns (motor)
    ("NOERROR (correcto)", "NOERROR (ok)", "NOERROR (correto)"),
    ("FORMERR (formato)", "FORMERR (format)", "FORMERR (formato)"),
    ("SERVFAIL (fallo del servidor)", "SERVFAIL (server failure)", "SERVFAIL (falha do servidor)"),
    ("NXDOMAIN (no existe)", "NXDOMAIN (doesn't exist)", "NXDOMAIN (não existe)"),
    ("NOTIMP (no implementado)", "NOTIMP (not implemented)", "NOTIMP (não implementado)"),
    ("REFUSED (rechazada)", "REFUSED (refused)", "REFUSED (recusada)"),
    ("Sin respuesta (tiempo agotado)", "No reply (timed out)", "Sem resposta (tempo esgotado)"),
    ("Respuesta no válida", "Invalid reply", "Resposta inválida"),
    ("Comparando servidores DNS…", "Comparing DNS servers…", "Comparando servidores DNS…"),
    ("Servidor más rápido: {} ({})", "Fastest server: {} ({})", "Servidor mais rápido: {} ({})"),
    ("Respondió en {:.1} ms.", "Answered in {:.1} ms.", "Respondeu em {:.1} ms."),
    ("El DNS del sistema no responde", "The system DNS isn't responding", "O DNS do sistema não responde"),
    ("Las páginas tardarán en abrir o no abrirán. Revisa el router o usa un DNS público.", "Pages will be slow or won't open. Check the router or use a public DNS.", "As páginas vão demorar ou não vão abrir. Verifique o roteador ou use um DNS público."),
    ("DNS del sistema lento ({:.0} ms)", "Slow system DNS ({:.0} ms)", "DNS do sistema lento ({:.0} ms)"),
    ("Un DNS por encima de 150 ms ralentiza la navegación.", "A DNS above 150 ms slows down browsing.", "Um DNS acima de 150 ms deixa a navegação lenta."),
    ("Respuestas distintas entre tu DNS y uno público", "Different answers from your DNS and a public one", "Respostas diferentes entre seu DNS e um público"),
    ("Sistema: {} · Cloudflare: {}. Es normal en servicios con CDN, pero también puede indicar manipulación.", "System: {} · Cloudflare: {}. Normal for CDN services, but it can also indicate tampering.", "Sistema: {} · Cloudflare: {}. É normal em serviços com CDN, mas também pode indicar manipulação."),
    ("Consultando registros del dominio…", "Querying domain records…", "Consultando registros do domínio…"),
    ("El dominio no tiene dirección (A/AAAA)", "The domain has no address (A/AAAA)", "O domínio não tem endereço (A/AAAA)"),
    ("No se puede abrir como web.", "It can't be opened as a website.", "Não pode ser aberto como site."),
    ("Sin IPv6 (AAAA)", "No IPv6 (AAAA)", "Sem IPv6 (AAAA)"),
    ("El dominio solo responde por IPv4.", "The domain only answers over IPv4.", "O domínio só responde por IPv4."),
    ("Falta registro SPF", "Missing SPF record", "Falta registro SPF"),
    ("Sin SPF es más fácil suplantar correos de este dominio.", "Without SPF it's easier to spoof email from this domain.", "Sem SPF é mais fácil falsificar e-mails deste domínio."),
    ("Falta política DMARC", "Missing DMARC policy", "Falta política DMARC"),
    ("Añade _dmarc con v=DMARC1 para proteger el correo.", "Add _dmarc with v=DMARC1 to protect email.", "Adicione _dmarc com v=DMARC1 para proteger o e-mail."),
    ("DMARC configurado", "DMARC configured", "DMARC configurado"),
    ("El dominio publica una política DMARC.", "The domain publishes a DMARC policy.", "O domínio publica uma política DMARC."),
    ("Sin registro CAA", "No CAA record", "Sem registro CAA"),
    ("CAA limita qué autoridades pueden emitir certificados.", "CAA limits which authorities can issue certificates.", "CAA limita quais autoridades podem emitir certificados."),
    ("Comprobando DNSSEC…", "Checking DNSSEC…", "Verificando DNSSEC…"),
    ("DNSSEC válido", "Valid DNSSEC", "DNSSEC válido"),
    ("Las respuestas están firmadas y verificadas (bit AD).", "Answers are signed and verified (AD bit).", "As respostas estão assinadas e verificadas (bit AD)."),
    ("Sin DNSSEC", "No DNSSEC", "Sem DNSSEC"),
    ("Las respuestas no están firmadas; son más fáciles de falsificar.", "Answers aren't signed; they're easier to forge.", "As respostas não estão assinadas; são mais fáceis de falsificar."),
    ("No se pudo comprobar DNSSEC", "Could not check DNSSEC", "Não foi possível verificar o DNSSEC"),
    ("Buscando redirecciones de dominios inexistentes…", "Looking for redirects of non-existent domains…", "Procurando redirecionamentos de domínios inexistentes…"),
    ("Tu DNS responde a dominios inexistentes", "Your DNS answers non-existent domains", "Seu DNS responde a domínios inexistentes"),
    ("{} devolvió {}. El proveedor o un intruso redirige errores (secuestro de NXDOMAIN).", "{} returned {}. Your provider or an intruder redirects errors (NXDOMAIN hijacking).", "{} retornou {}. O provedor ou um intruso redireciona erros (sequestro de NXDOMAIN)."),
    ("Sin secuestro de NXDOMAIN", "No NXDOMAIN hijacking", "Sem sequestro de NXDOMAIN"),
    ("Los dominios inexistentes se informan correctamente.", "Non-existent domains are reported correctly.", "Domínios inexistentes são informados corretamente."),
    ("Análisis terminado", "Analysis finished", "Análise concluída"),
    // calidad (motor)
    ("Sin dirección", "No address", "Sem endereço"),
    ("El servidor respondió: {}", "The server replied: {}", "O servidor respondeu: {}"),
    ("No se recibieron datos", "No data received", "Nenhum dado recebido"),
    ("Midiendo la red local…", "Measuring the local network…", "Medindo a rede local…"),
    ("Midiendo latencia a Internet…", "Measuring Internet latency…", "Medindo latência para a Internet…"),
    ("Midiendo el tiempo de DNS…", "Measuring DNS time…", "Medindo o tempo de DNS…"),
    ("Midiendo el tiempo de conexión web…", "Measuring web connection time…", "Medindo o tempo de conexão web…"),
    ("Midiendo la velocidad de descarga (10 s)…", "Measuring download speed (10 s)…", "Medindo a velocidade de download (10 s)…"),
    ("Llamadas de voz (VoIP)", "Voice calls (VoIP)", "Chamadas de voz (VoIP)"),
    ("MOS {:.2} de 4.5 · factor R {:.0}", "MOS {:.2} of 4.5 · R factor {:.0}", "MOS {:.2} de 4,5 · fator R {:.0}"),
    ("Videollamadas", "Video calls", "Videochamadas"),
    ("{:.0} ms · jitter {:.1} ms · pérdida {:.1}%", "{:.0} ms · jitter {:.1} ms · loss {:.1}%", "{:.0} ms · jitter {:.1} ms · perda {:.1}%"),
    ("Vídeo en streaming", "Video streaming", "Vídeo em streaming"),
    ("{:.1} Mbps de descarga", "{:.1} Mbps download", "{:.1} Mbps de download"),
    ("sin prueba de velocidad", "no speed test", "sem teste de velocidade"),
    ("Juegos en línea", "Online gaming", "Jogos online"),
    ("latencia {:.0} ms · jitter {:.1} ms", "latency {:.0} ms · jitter {:.1} ms", "latência {:.0} ms · jitter {:.1} ms"),
    ("Navegación web", "Web browsing", "Navegação web"),
    ("DNS {} · conexión {}", "DNS {} · connect {}", "DNS {} · conexão {}"),
    ("Medición terminada", "Measurement finished", "Medição concluída"),
    // escáneres y captura
    ("Rango no válido: {}", "Invalid range: {}", "Intervalo inválido: {}"),
    ("Puerto no válido: {}", "Invalid port: {}", "Porta inválida: {}"),
    ("El puerto 0 no es válido", "Port 0 is not valid", "A porta 0 não é válida"),
    ("No se pudo resolver «{}»", "Could not resolve «{}»", "Não foi possível resolver «{}»"),
    ("No se encontró «traceroute» ni «tracepath» en el sistema. Instálalo para ver la ruta.", "Neither «traceroute» nor «tracepath» was found. Install one to see the route.", "Nem «traceroute» nem «tracepath» foram encontrados. Instale um para ver a rota."),
    ("Archivo cortado", "Truncated file", "Arquivo cortado"),
    ("Sin datos", "No data", "Sem dados"),
    ("No es un archivo pcap/pcapng válido", "Not a valid pcap/pcapng file", "Não é um arquivo pcap/pcapng válido"),
    ("Cabecera pcap incompleta", "Incomplete pcap header", "Cabeçalho pcap incompleto"),
    ("Registro pcap demasiado grande", "pcap record too large", "Registro pcap grande demais"),
    ("Bloque pcapng no válido", "Invalid pcapng block", "Bloco pcapng inválido"),
    ("En vivo · {}", "Live · {}", "Ao vivo · {}"),
    ("Archivo · {}", "File · {}", "Arquivo · {}"),
    ("No se pudo abrir el archivo: {}", "Could not open the file: {}", "Não foi possível abrir o arquivo: {}"),
    ("Para capturar en Windows instala Wireshark (incluye Npcap y dumpcap) y vuelve a intentarlo.", "To capture on Windows install Wireshark (includes Npcap and dumpcap) and try again.", "Para capturar no Windows instale o Wireshark (inclui Npcap e dumpcap) e tente novamente."),
    ("No se encontró «tcpdump». Instálalo para capturar paquetes.", "«tcpdump» was not found. Install it to capture packets.", "«tcpdump» não encontrado. Instale-o para capturar pacotes."),
    ("Ejecuta la app como administrador.", "Run the app as administrator.", "Execute o app como administrador."),
    ("Ejecuta la app con sudo.", "Run the app with sudo.", "Execute o app com sudo."),
    ("La captura no arrancó. {} {}", "Capture did not start. {} {}", "A captura não iniciou. {} {}"),
    ("No hay permiso para capturar ({}). Ejecuta la app con sudo, o dale permiso una vez con: sudo setcap cap_net_raw,cap_net_admin=eip <ruta de la app>", "No permission to capture ({}). Run the app with sudo, or grant it once with: sudo setcap cap_net_raw,cap_net_admin=eip <app path>", "Sem permissão para capturar ({}). Execute o app com sudo, ou dê permissão uma vez com: sudo setcap cap_net_raw,cap_net_admin=eip <caminho do app>"),
    ("La interfaz «{}» no existe", "Interface «{}» doesn't exist", "A interface «{}» não existe"),
    ("todas", "all", "todas"),
    ("Esperando datos…", "Waiting for data…", "Aguardando dados…"),
    ("MAC privada (aleatoria)", "Private (random) MAC", "MAC privado (aleatório)"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn holes(s: &str) -> Vec<String> {
        let mut v = Vec::new();
        let mut rest = s;
        while let Some(i) = rest.find('{') {
            let j = rest[i..].find('}').map(|j| i + j + 1).unwrap_or(rest.len());
            v.push(rest[i..j].to_string());
            rest = &rest[j..];
        }
        v
    }

    #[test]
    fn every_language_lines_up() {
        for (name, list) in [("fr", crate::i18n_fr::FR), ("de", crate::i18n_de::DE)] {
            assert_eq!(list.len(), TABLE.len(), "{}: número de textos", name);
            for (i, (es, en, pt)) in TABLE.iter().enumerate() {
                let h = holes(es);
                assert_eq!(holes(en), h, "en {}: {}", i + 1, es);
                assert_eq!(holes(pt), h, "pt {}: {}", i + 1, es);
                assert_eq!(holes(list[i]), h, "{} {}: {} / {}", name, i + 1, es, list[i]);
            }
        }
    }
}
