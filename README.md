# RedVisión

Analizador de red de escritorio para **Linux, Windows y macOS**, escrito en Rust con egui.

## Funciones

- **Panel**: resumen en tiempo real (equipo, router, dispositivos, alertas, tráfico y latencia).
- **Red y topología**: descubre los equipos activos de la subred y los dibuja en un mapa.
- **Puertos**: puertos a la escucha y conexiones de este equipo, y escáner de puertos TCP con lectura de banners.
- **Captura de paquetes**: captura en vivo, filtro, detalle por capas y vista hexadecimal; abre y guarda `.pcap`/`.pcapng`.
- **Análisis profundo**: protocolos, equipos que más hablan, conversaciones, DNS, sitios TLS (SNI), HTTP, DHCP y salud de TCP.
- **Latencia y pérdida**: ping o TCP continuo, jitter, percentil 95, MOS y traceroute.
- **Calidad (QoE)**: nota para voz, videollamadas, streaming, juegos y navegación.
- **Análisis DNS**: consultas de cualquier tipo, comparación de servidores, DNSSEC, SPF/DMARC/CAA y secuestro de NXDOMAIN.
- **Vulnerabilidades**: servicios expuestos, accesos anónimos, SNMP «public», UPnP, software antiguo.
- **Intrusos y anomalías**: escaneos, suplantación ARP, DHCP no autorizado, inundaciones, túneles DNS, credenciales en claro, equipos nuevos o caídos, picos de tráfico.
- **Monitorización**: tráfico por interfaz y disponibilidad de equipos vigilados.
- **Herramientas**: IP pública y proveedor, calculadora de subredes, Wake-on-LAN y fabricante por MAC.
- **Exportar a CSV**: equipos, conexiones, alertas y hallazgos.
- **Idiomas**: español, inglés y portugués (usa el del sistema la primera vez).
- **Temas**: oscuro, claro, medianoche y terminal; tamaño de la interfaz ajustable.
- Las preferencias y los equipos vigilados se guardan entre sesiones.

## Descargas

En **Releases** encontrarás, para cada versión:

| Sistema | Archivo |
|---|---|
| Linux | `RedVision-x.y.z-linux-x86_64.AppImage` (dale permiso de ejecución y ábrelo), `redvision_x.y.z_amd64.deb`, `.tar.gz` |
| Windows | `RedVision-x.y.z-windows-x64-setup.exe` (instalador) o `...-portable.exe` |
| macOS | `RedVision-x.y.z-macos-arm64.dmg` (Apple Silicon) o `...-macos-x86_64.dmg` (Intel) |

La app no está firmada: en Windows pulsa «Más información → Ejecutar de todas formas»; en macOS,
la primera vez abre la app con clic derecho → «Abrir».

Para publicar una versión nueva: `git tag v0.2.0 && git push origin v0.2.0`. GitHub Actions compila
los paquetes y los sube a Releases solo. Cada cambio en `main` también se compila y deja los paquetes en **Actions**.

## Requisitos para capturar paquetes en vivo

- **Linux**: ejecutar con `sudo`, o dar permiso una vez:
  `sudo setcap cap_net_raw,cap_net_admin=eip ./redvision`
- **Windows**: instalar Wireshark (incluye Npcap y `dumpcap`) y abrir la app como administrador.
- **macOS**: ejecutar con `sudo` (usa `tcpdump`).

El resto de funciones no necesitan permisos especiales. La ruta (traceroute) usa `traceroute`/`tracepath` en Linux y macOS y `tracert` en Windows.

## Compilar a mano

```sh
cargo build --release
./target/release/redvision
```

Úsala solo en redes y equipos propios o con permiso de su dueño.
