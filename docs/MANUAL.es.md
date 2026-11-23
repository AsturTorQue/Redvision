# Manual de uso de RedVisión

## Qué es RedVisión

RedVisión es un analizador de red de escritorio, ligero y gratuito, para Linux, Windows y macOS. Reúne en una sola ventana lo que normalmente se hace con muchas herramientas distintas: ver qué equipos hay en tu red, qué puertos tienen abiertos, capturar y analizar el tráfico, medir la latencia y la velocidad, revisar el DNS, buscar fallos de seguridad y vigilar intrusos.

Está pensado tanto para quien solo quiere saber «por qué va lento Internet» como para técnicos que necesitan datos concretos.

> Usa RedVisión solo en redes y equipos propios o con permiso de su dueño. Escanear o auditar redes ajenas puede ser ilegal.

## Instalación y primer arranque

Descarga el paquete de tu sistema desde la sección Releases del repositorio:

- **Linux**: el archivo `.AppImage` (dale permiso de ejecución y ábrelo), el paquete `.deb` para Debian/Ubuntu o el `.tar.gz`.
- **Windows**: el instalador `setup.exe` o la versión portable `.exe`.
- **macOS**: el `.dmg` de tu procesador (Apple Silicon o Intel). Arrástralo a Aplicaciones.

La app no está firmada digitalmente. La primera vez:

- En **Windows**, si aparece «Windows protegió su PC», pulsa «Más información» y luego «Ejecutar de todas formas».
- En **macOS**, abre la app con clic derecho y elige «Abrir».

Al arrancar, RedVisión detecta tu dirección IP, la puerta de enlace (el router), los servidores DNS y el idioma del sistema. Casi todo funciona sin permisos especiales; solo la **captura de paquetes en vivo** los necesita (ver «Captura de paquetes»).

## La ventana

- **Menú lateral**: cada apartado es una herramienta. El número rojo junto a «Intrusos y anomalías» indica alertas altas o críticas; el punto rojo junto a «Captura de paquetes» indica que hay una captura en marcha.
- **Pie del menú**: tu IP, tu sistema y si la app tiene permisos de administrador.
- **Idioma y aspecto**: en «Ajustes» puedes cambiar el idioma (español, inglés, portugués, francés y alemán), el tema de color y el tamaño de la interfaz. Se guardan solos.
- Casi todas las tareas largas (escaneos, auditorías, mediciones) se ejecutan en segundo plano: puedes cambiar de apartado mientras terminan.

## Panel

Resumen en tiempo real de tu red:

- **Este equipo**: tu IP, la máscara (por ejemplo /24) y la interfaz de red.
- **Puerta de enlace**: la IP del router y su latencia actual.
- **Dispositivos en la red**: cuántos equipos encontró el último escaneo.
- **Alertas de seguridad**: total de alertas del detector de intrusos.
- **Tráfico de la red**: bajada y subida de los últimos 2 minutos.
- **Latencia hasta el router**: se mide cada 2 segundos. Si sube o aparecen marcas rojas (paquetes perdidos), el problema está en tu red local.
- **Seguridad** y **Calidad de la conexión**: muestran la nota de la última auditoría y de la última medición de calidad.
- **Acciones rápidas**: atajos a las tareas más habituales.

## Red y topología

Descubre todos los equipos activos de tu subred.

1. Pulsa **Escanear la red**. Se prueban todas las direcciones con ping y con conexiones TCP a puertos habituales (no hacen falta permisos). Una red /24 tarda entre 10 y 40 segundos.
2. Elige **Mapa** para ver Internet arriba, el router en el centro y los equipos alrededor, coloreados por tipo (ordenador, móvil, impresora, servidor, multimedia, IoT…). Pasa el ratón por encima para ver sus datos y haz clic para seleccionarlo.
3. Elige **Lista** para ver la tabla completa: IP, nombre, MAC, fabricante, tipo, latencia y puertos abiertos detectados.

Con un equipo seleccionado puedes: **escanear todos sus puertos**, **auditar su seguridad**, **medir su latencia**, **vigilarlo** (aparecerá en Monitorización) o **despertarlo** con Wake-on-LAN.

Notas:

- El **fabricante** se estima por la MAC y es aproximado. «MAC privada (aleatoria)» significa que el dispositivo (normalmente un móvil) oculta su MAC real.
- El **tipo** se deduce de los puertos abiertos y del fabricante; puede equivocarse.
- Los equipos que bloquean el ping y no tienen puertos abiertos pueden no aparecer.
- Si escaneas de nuevo y aparece un equipo que no estaba, se genera una alerta «Nuevo dispositivo».
- **Exportar CSV** guarda la lista en tu carpeta personal.

## Puertos

Tiene dos pestañas:

- **Este equipo**: los puertos en los que tu ordenador está escuchando y sus conexiones activas, con el programa que los usa. Los puertos en **ámbar** escuchan en todas las interfaces (0.0.0.0): cualquier equipo de la red puede intentar conectarse. Activa «Mostrar también las conexiones» para ver con quién está hablando tu equipo ahora mismo. El nombre del programa solo aparece para tus procesos o con permisos de administrador.
- **Escáner de puertos**: comprueba qué puertos TCP tiene abiertos otro equipo. Escribe la IP o el nombre y elige los puertos: `comunes` (unos 60 habituales), `1-1024`, `todos` o una lista como `22,80,443,8000-8100`. Con «Leer banners» la app intenta leer qué programa y versión responde en cada puerto. Al terminar verás cuántos puertos están abiertos, cerrados (el equipo responde que no) o filtrados (un cortafuegos no responde).

## Captura de paquetes

Muestra el tráfico de red paquete a paquete, como Wireshark pero más sencillo.

**Permisos necesarios para capturar en vivo:** lo más fácil es pulsar **Elevar a superusuario** (en Windows se llama **Elevar a administrador**), el botón que aparece abajo en el menú lateral mientras la app no tiene permisos de superusuario. Pide la contraseña (o la confirmación de Windows) y vuelve a abrir la app con los permisos necesarios. En Linux solo le da a la app el permiso de captura, sin ejecutarla entera como root. A mano:

- **Linux**: abre la app con `sudo`, o dale permiso una sola vez: `sudo setcap cap_net_raw,cap_net_admin=eip /ruta/a/redvision`.
- **Windows**: instala Wireshark (incluye Npcap y dumpcap) y abre RedVisión como administrador.
- **macOS**: abre la app con `sudo` (usa tcpdump).

Uso:

1. Elige la **interfaz** (en Linux, `any` captura todas) y pulsa **Iniciar captura**.
2. Escribe en **Filtro** para ver solo lo que te interesa: un protocolo (`dns`, `tcp`, `tls`, `arp`), un puerto (`443`), una IP o cualquier texto (`google`). Puedes combinar varias palabras.
3. Haz clic en un paquete para ver sus **capas** (Ethernet, IP, TCP/UDP y aplicación: DNS, HTTP, TLS, DHCP…) y sus **bytes en hexadecimal**.
4. **Guardar .pcap** guarda la captura para abrirla luego aquí o en Wireshark. **Abrir archivo** carga capturas `.pcap` y `.pcapng` (esto no necesita permisos).

Se guardan en memoria los últimos 50 000 paquetes. Desactiva «Seguir los últimos» para que la lista no se mueva mientras lees.

## Análisis profundo

Resume lo capturado (en vivo o desde un archivo):

- **Protocolos por volumen**: qué tipo de tráfico ocupa la red.
- **Tráfico por segundo**: gráfica de la captura.
- **Equipos que más hablan** y **conversaciones principales**: quién consume la red.
- **Nombres consultados por DNS** y **sitios cifrados (TLS)**: a qué sitios se conectan los equipos (el nombre del servidor viaja visible al iniciar una conexión HTTPS).
- **Salud de las conexiones TCP**: muchos intentos sin respuesta indican un escaneo, un cortafuegos o un servicio caído.
- **Peticiones web sin cifrar (HTTP) y DHCP**: tráfico web inseguro y equipos pidiendo dirección.

## Latencia y pérdida

Mide de forma continua el tiempo de respuesta de un destino.

1. Escribe un destino o usa los botones rápidos (Router, Cloudflare, Google).
2. Elige **Ping (ICMP)** o **Conexión TCP al puerto** (útil si el destino bloquea el ping) y cada cuánto medir.
3. Pulsa **Iniciar**.

Qué significan los datos:

- **Pérdida**: porcentaje de respuestas que no llegan. Más de un 1-2 % ya se nota.
- **Latencia media, mínima y máxima**: en milisegundos (ms).
- **Jitter**: cuánto varía la latencia entre una medida y la siguiente. Por encima de 30 ms afecta a llamadas.
- **Percentil 95**: el 95 % de las medidas están por debajo de este valor.
- **MOS (voz)**: calidad estimada de una llamada, de 1 (mala) a 4,5 (excelente).

Debajo aparece un diagnóstico en lenguaje sencillo. Compara la latencia al router con la de Internet: si el router ya va lento, el problema está en tu casa (Wi-Fi o cable), no en tu proveedor.

**Ruta hasta el destino (traceroute)** muestra cada salto que da tu tráfico hasta llegar. Un salto con mucha más latencia que los anteriores indica dónde está el atasco. Necesita `traceroute` o `tracepath` en Linux y macOS; en Windows usa `tracert`.

## Calidad (QoE)

Calcula cómo se sentirá tu conexión en el uso real. Pulsa **Medir calidad ahora** (unos 30 segundos): mide el router, la latencia a Internet, el DNS, el tiempo de conexión a una web y la velocidad de **descarga** y de **subida** a Internet.

Obtendrás una **nota global** y una nota para llamadas de voz, videollamadas, vídeo en streaming, juegos en línea y navegación web. Las videollamadas dependen sobre todo de la subida: con 1 Mbps van justas y con 5 Mbps o más, holgadas. El archivo de prueba de descarga y el servidor de subida (debe aceptar envíos POST) se pueden cambiar por otros; ambos deben empezar por `http://`. Si el de descarga no responde, se usa uno de respaldo.

## Análisis DNS

El DNS traduce nombres (como `ejemplo.com`) a direcciones IP. Un DNS lento o manipulado hace que todo parezca lento o inseguro.

- **Consulta**: pregunta un tipo de registro (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA…) a un servidor concreto: el de tu sistema, Cloudflare, Google, Quad9, OpenDNS u otro. Para PTR puedes escribir directamente una IP.
- **Análisis completo**: compara la velocidad de varios servidores DNS, lista los registros del dominio y revisa su seguridad: DNSSEC, SPF y DMARC (protección del correo), CAA (quién puede emitir certificados) y si tu proveedor redirige los dominios inexistentes (secuestro de NXDOMAIN).

## Vulnerabilidades

Busca problemas de seguridad en equipos de tu red.

**Seguridad de este equipo** (arriba de la página): pulsa **Revisar este equipo** y la app mira tu propio ordenador: si el cortafuegos está activo, el antivirus en tiempo real (Windows), si el disco está cifrado (BitLocker, FileVault o LUKS), qué servicios peligrosos están abiertos a toda la red, la configuración de SSH, si usas un DNS poco habitual, si hay un proxy configurado, si el archivo hosts redirige sitios importantes, si estás en una Wi-Fi abierta o con WEP y cuántos días lleva sin reiniciar. También comprueba el **arranque seguro** (Secure Boot), las **actualizaciones automáticas**, si hay **programas de control remoto** en marcha (TeamViewer, AnyDesk…, muy usados en estafas), qué **puertos abre tu router a Internet por UPnP**, si tu DNS **responde a webs que no existen** (señal de manipulación) y si **valida DNSSEC**. Cada problema viene con su explicación y cómo arreglarlo.

**¿Contraseña filtrada?**: escribe una contraseña y la app te dice si aparece en filtraciones conocidas (Have I Been Pwned). La contraseña no sale de tu equipo: solo se envían los 5 primeros caracteres de su huella SHA-1. Necesita Internet y el programa `curl` (viene con Windows 10/11, macOS y casi todos los Linux).

- **Auditar este equipo**: escribe una IP o un nombre.
- **Auditar el router**: revisa tu puerta de enlace.
- **Auditar toda la red**: revisa todos los equipos del último escaneo.

Se comprueban unos 60 puertos habituales y servicios peligrosos (y, si hay HTTPS, la caducidad y validez de su certificado): Telnet, FTP anónimo, SMB, escritorio remoto, VNC, bases de datos accesibles (Redis, MongoDB, MySQL…), Elasticsearch, Docker, Memcached sin protección, SNMP con la comunidad «public», UPnP, resolvedores DNS abiertos, versiones antiguas de SSH y servidores web que muestran su versión.

Cada hallazgo tiene un nivel (Crítica, Alta, Media, Baja, Info), una explicación y **cómo arreglarlo**. La **puntuación de seguridad** empieza en 100 y baja según la gravedad de lo encontrado. Puedes exportar los hallazgos a CSV.

## Intrusos y anomalías

Un detector de intrusos que vigila tu red mientras la app está abierta.

**Sin captura** vigila: suplantación ARP (alguien haciéndose pasar por el router), equipos nuevos en la red, equipos vigilados que dejan de responder, picos de tráfico anómalos y **cambios de router o de DNS** (cada 30 segundos comprueba si la puerta de enlace o los servidores DNS han cambiado sin que cambies de red, un truco habitual para desviar tu tráfico).

**Con captura en vivo** además analiza cada paquete y detecta: escaneos de puertos y barridos de red, escaneos sigilosos (NULL, FIN, XMAS), inundaciones SYN e ICMP, servidores DHCP no autorizados, túneles DNS (exfiltración de datos), tráfico a puertos de malware y contraseñas enviadas sin cifrar.

Las alertas se pueden filtrar por nivel, borrar y exportar. Se guardan los últimos 7 días, así que al volver a abrir la app sigues viendo lo que pasó. Si salta una alerta **alta o crítica** (o un equipo vigilado deja de responder), la app lo avisa con una **notificación del sistema** aunque estés en otra ventana; se puede desactivar en Ajustes. Al final de la página está la lista completa de reglas.

> Una alerta no es siempre un ataque. Por ejemplo, «La MAC del router aparece en otras IP» puede deberse a un router con varias direcciones. Revisa el contexto antes de actuar.

## Monitorización

- **Tráfico**: bajada y subida de cada interfaz o de todas juntas, con una tabla de velocidades actuales y totales.
- **Equipos vigilados**: añade IPs o nombres (servidores, cámaras, el router, una web). Se comprueban con ping cada 5 segundos y verás si están activos, su latencia y su disponibilidad en %. Si uno deja de responder aparece una alerta. La lista se guarda entre sesiones.
- **Latencia al router**: gráfica continua.

## Velocidad entre equipos

Mide la velocidad real entre dos ordenadores de tu red (como iperf). Sirve para comprobar un cable, un switch, un enlace Wi-Fi o un repetidor.

1. En el **otro equipo**, abre RedVisión, entra en este apartado y pulsa **Activar servidor**. Verás su dirección (por ejemplo `192.168.1.20:5201`).
2. En **este equipo**, escribe esa IP en «Servidor» (o elígela de la lista si escaneaste la red) y pulsa **Medir velocidad**.
3. Se mide la **latencia**, la **bajada** (el servidor envía) y la **subida** (este equipo envía).

Consejos:

- Usa 4 **conexiones en paralelo** para aprovechar enlaces rápidos.
- Si no conecta, permite el puerto TCP 5201 en el cortafuegos del equipo servidor.
- Por cable gigabit deberías ver más de 900 Mbps. Cerca de 95 Mbps indica que algo (cable, puerto o switch) está limitando a 100 Mb/s.
- Puedes probar contra `127.0.0.1` con el servidor activo en el mismo equipo para comprobar que todo funciona.

## Diagnóstico de la LAN

Busca automáticamente las causas habituales de una red local lenta o inestable. Pulsa **Diagnosticar la red**; tarda unos segundos.

Revisa:

- Si tienes dirección IP y si el DHCP funciona (las direcciones 169.254.x.x indican que el router no te ha dado IP).
- Pérdida, latencia y jitter hasta el router (20 pings).
- Velocidad negociada del cable y si va en dúplex medio (en Linux).
- Intensidad de la señal Wi-Fi (Linux y Windows).
- Errores y paquetes descartados en la tarjeta de red (Linux).
- Varias rutas por defecto o dos conexiones a la misma red a la vez.
- DNS que no responde o va lento.
- Salida a Internet, portales cautivos o proxys que interceptan la web.
- MTU de la ruta, IPv6 y si la MAC del router aparece en otras IP.

Opcionalmente, **Incluir prueba de carga** mide el *bufferbloat*: cuánto sube la latencia mientras se descarga algo durante unos 10 segundos. Si sube mucho, activa SQM o QoS en el router.

Obtendrás una nota de salud, los datos de tu red y cada problema con su solución.

## Analizador Wi-Fi

Si el equipo tiene tarjeta Wi-Fi (o un adaptador USB Wi-Fi), este apartado muestra las redes que hay alrededor aunque estés conectado por cable. Si no hay tarjeta, la página lo indica.

- **Tu conexión Wi-Fi**: red, BSSID (el punto de acceso concreto), canal y banda, velocidad del enlace e intensidad de la señal en dBm, con una gráfica de la señal en el tiempo. Como referencia: más de -55 dBm es excelente, hasta -67 buena, hasta -75 aceptable y por debajo, mala.
- **Canales recomendados**: lo ocupado que está cada canal en 2.4 GHz y 5 GHz y cuál es el **canal más libre**. En 2.4 GHz usa solo los canales 1, 6 u 11.
- **Espectro**: cada red se dibuja como una campana centrada en su canal y tan alta como su señal. Si varias campanas se pisan, esas redes se interfieren.
- **Seguridad y problemas**: avisa si tu red está abierta o usa WEP o WPA antiguo, si hay otra red con tu mismo nombre y distinta seguridad (posible punto de acceso falso), si tu señal es débil, si estás en 2.4 GHz pudiendo usar 5 GHz, si tu canal está saturado y de las redes abiertas u ocultas cercanas.
- **Redes cercanas**: tabla con nombre, BSSID, fabricante, canal, banda, señal y seguridad. Se puede exportar a CSV.

Pulsa **Buscar redes Wi-Fi** o activa **Actualizar cada 10 s** para seguir la señal mientras te mueves.

Requisitos: en Linux usa NetworkManager (`nmcli`); en Windows, `netsh` (Windows 11 pide el permiso de **ubicación** para listar redes); en macOS, la información del sistema (puede no mostrar el BSSID).

## Certificados HTTPS

Está en el menú lateral, justo debajo de «Vulnerabilidades». Escribe uno o varios servidores (`debian.org mail.ejemplo.com:993`) y verás cuántos días le quedan a su certificado (en rojo si ha caducado o caduca en menos de 7 días, naranja y ámbar si queda menos de un mes), a quién cubre, quién lo emitió, el tipo de clave y firma, la cadena de certificados y qué versiones de TLS acepta (✔ en rojo para TLS 1.0 y 1.1, que son obsoletos). Avisa de certificados caducados, de otro nombre, autofirmados, con firma o clave débil y de TLS antiguo. Se lee el certificado que envía el servidor; **no se verifica la firma de la cadena de confianza**, y los servidores que solo admiten TLS 1.3 cifran su certificado y no se pueden leer así.

## Herramientas

- **Mi IP pública**: tu IP en Internet, país, ciudad y proveedor (usa el servicio ip-api.com).
- **Calculadora de subredes**: escribe `IP/prefijo` (por ejemplo `192.168.1.10/24`) y obtén la red, máscara, difusión, primer y último equipo y cuántos equipos caben.
- **Wake-on-LAN**: enciende un equipo apagado enviándole un «paquete mágico» a su MAC. El equipo debe tener Wake-on-LAN activado en la BIOS y en la tarjeta de red.
- **Buscar fabricante por MAC**.
- **MTU de la ruta**: el paquete más grande que llega sin partirse a un destino. Útil con VPN o webs que no cargan.
- **Tabla ARP del sistema**: qué IP corresponde a qué MAC en tu red.
- **Dispositivos UPnP**: televisores, routers, NAS y otros aparatos que se anuncian en la red, con nombre y modelo.
- **Whois**: quién es el dueño registrado de un dominio o de una IP, con fechas y contactos públicos. Sigue las referencias hasta el servidor del registro.
- **Servicios Bonjour / mDNS**: impresoras, Chromecast, AirPlay, carpetas compartidas…
- **Interfaces y rutas del sistema**: la configuración de red tal como la ve el sistema operativo.

## Ajustes

- **Idioma**: español, English, Português, Français o Deutsch. La primera vez se usa el idioma del sistema.
- **Tema**: Oscuro, Claro, Medianoche o Terminal.
- **Tamaño de la interfaz**: del 70 % al 160 %.
- **Escanear la red al abrir la app**.
- **Notificaciones del sistema** para las alertas graves, con un botón para probarlas.

Las preferencias y los equipos vigilados se guardan en:

- Linux: `~/.config/redvision/settings.conf`
- Windows: `%APPDATA%\RedVision\settings.conf`
- macOS: `~/Library/Application Support/RedVision/settings.conf`

## Casos prácticos

### Internet va lento

1. Ve a **Diagnóstico de la LAN** y pulsa «Diagnosticar la red». Si hay problemas de Wi-Fi, cable o router, aparecerán arriba.
2. En **Latencia y pérdida**, mide primero el **Router** y luego **Cloudflare**. Si el router ya tiene pérdida o mucha latencia, el problema está en casa; si solo falla Internet, es cosa del proveedor.
3. Mide la **Calidad (QoE)** para ver la velocidad de descarga y cómo afecta a cada uso.
4. Si notas que va mal cuando alguien descarga, activa la prueba de carga del diagnóstico (bufferbloat).

### El Wi-Fi se corta

1. **Diagnóstico de la LAN** te dirá la señal y la pérdida hasta el router.
2. Deja **Latencia y pérdida** midiendo el router durante unos minutos mientras te mueves por la casa: las marcas rojas indican cortes.

### ¿Hay alguien desconocido en mi red?

1. Escanea en **Red y topología** y revisa la lista: fabricante, nombre y tipo.
2. Deja la app abierta: el detector avisará de **nuevos dispositivos** y de suplantaciones ARP.
3. Para un análisis más completo, inicia una captura y revisa **Intrusos y anomalías**.

### Comprobar la seguridad de mi red

1. Escanea la red y pulsa **Auditar toda la red** en **Vulnerabilidades**.
2. Empieza por los hallazgos críticos y altos; cada uno dice cómo arreglarlo.
3. Revisa también el router con **Auditar el router** y el apartado **Puertos -> Este equipo**.

### Medir el cable o el Wi-Fi entre dos ordenadores

Usa **Velocidad entre equipos**: servidor en uno, medición en el otro.

## Exportar y guardar datos

- **CSV**: los botones «Exportar CSV» (equipos, conexiones, alertas y hallazgos) guardan un archivo `RedVision-…-fecha.csv` en tu carpeta personal. Se abre con Excel, LibreOffice o Google Sheets.
- **Capturas**: «Guardar .pcap» en Captura de paquetes (por defecto `captura-redvision.pcap` en tu carpeta personal).

## Privacidad y uso responsable

- RedVisión no envía datos a ningún servidor propio. Solo se conecta a Internet cuando tú lo pides: medir latencia o calidad, consultar DNS públicos, la IP pública (ip-api.com) o el archivo de prueba de velocidad.
- Las capturas pueden contener información personal. Guárdalas con cuidado.
- Escanea y audita solo redes y equipos propios o con permiso.

## Problemas frecuentes

- **«No hay permiso para capturar»**: pulsa **Elevar a superusuario** (**administrador** en Windows) en el menú lateral o mira los permisos en «Captura de paquetes».
- **En Windows (por ejemplo en una máquina virtual) la app no abre o se cierra sola**: la app intenta primero con OpenGL y, si no hay, se reabre sola con DirectX (por software si hace falta) y lo recuerda. Si aun así falla, verás un mensaje con la causa y se guarda en `%APPDATA%\RedVision\error.log`. Puedes forzar el motor con `redvision.exe --renderer wgpu` (DirectX) o `--renderer glow` (OpenGL); para volver al automático borra `%APPDATA%\RedVision\renderer`. En la VM conviene activar la aceleración 3D, aunque no es obligatoria.
- **No aparece un equipo que sé que está encendido**: puede bloquear el ping y no tener puertos abiertos. Prueba a escanear sus puertos directamente.
- **El traceroute no funciona en Linux**: instala el paquete `traceroute` (o `iputils-tracepath`).
- **La velocidad entre equipos no conecta**: activa el servidor en el otro equipo y abre el puerto TCP 5201 en su cortafuegos.
- **La prueba de calidad no mide la velocidad**: el archivo de prueba puede no estar disponible; cambia la dirección por otro archivo grande `http://`.
- **El icono no aparece en Linux (Wayland)**: abre la app una vez de forma normal; se registra sola en el menú de aplicaciones.
- **El fabricante sale vacío**: la lista interna solo incluye fabricantes comunes.

## Glosario

- **IP**: dirección de un equipo en la red (por ejemplo 192.168.1.10).
- **Máscara / prefijo**: indica el tamaño de la red; /24 son 254 equipos.
- **Puerta de enlace (gateway)**: el router que conecta tu red con Internet.
- **MAC**: identificador físico de la tarjeta de red.
- **ARP**: protocolo que relaciona IPs con MACs dentro de la red local.
- **DHCP**: servicio del router que reparte direcciones IP.
- **DNS**: traduce nombres de dominio a direcciones IP.
- **Puerto**: «puerta» numerada por la que un programa recibe conexiones (80 web, 443 web segura, 22 SSH…).
- **Latencia**: tiempo que tarda un paquete en ir y volver, en milisegundos.
- **Jitter**: variación de la latencia.
- **Pérdida de paquetes**: porcentaje de datos que no llegan.
- **MOS**: nota de calidad de voz de 1 a 4,5.
- **QoE**: calidad de experiencia, cómo percibe el usuario la conexión.
- **MTU**: tamaño máximo de paquete que cabe sin partirse (normalmente 1500 bytes).
- **Bufferbloat**: aumento de la latencia cuando la línea está cargada.
- **TLS / SNI**: cifrado de las webs seguras; el SNI es el nombre del sitio que se ve al conectar.
- **UPnP / mDNS**: sistemas con los que los aparatos se anuncian solos en la red.
- **Wake-on-LAN**: encender un equipo por la red.
