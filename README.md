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

## Descargas

Cada cambio en `main` se compila automáticamente para Linux, Windows y macOS (Intel y Apple Silicon)
en la pestaña **Actions** del repositorio. Al crear una etiqueta `v*` (por ejemplo `v0.1.0`)
los ejecutables se publican en **Releases**.

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
