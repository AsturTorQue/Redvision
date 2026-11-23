# RedVisión user manual

## What RedVisión is

RedVisión is a lightweight, free desktop network analyzer for Linux, Windows and macOS. It brings together in one window what usually takes many different tools: seeing which devices are on your network and which ports they have open, capturing and analyzing traffic, measuring latency and speed, checking DNS, finding security problems and watching for intruders.

It's meant both for people who just want to know "why is the Internet slow" and for technicians who need hard data.

> Only use RedVisión on networks and devices you own or have permission to test. Scanning or auditing other people's networks may be illegal.

## Installation and first start

Download the package for your system from the repository's Releases section:

- **Linux**: the `.AppImage` file (make it executable and open it), the `.deb` package for Debian/Ubuntu, or the `.tar.gz`.
- **Windows**: the `setup.exe` installer or the portable `.exe`.
- **macOS**: the `.dmg` for your processor (Apple Silicon or Intel). Drag it to Applications.

The app is not digitally signed. The first time:

- On **Windows**, if "Windows protected your PC" appears, click "More info" and then "Run anyway".
- On **macOS**, right-click the app and choose "Open".

On start, RedVisión detects your IP address, the gateway (the router), the DNS servers and the system language. Almost everything works without special rights; only **live packet capture** needs them (see "Packet capture").

## The window

- **Side menu**: each entry is a tool. The red number next to "Intrusions & anomalies" shows high or critical alerts; the red dot next to "Packet capture" means a capture is running.
- **Menu footer**: your IP, your system and whether the app has administrator rights.
- **Language and look**: in "Settings" you can change the language (Spanish, English, Portuguese, French and German), the colour theme and the interface size. They're saved automatically.
- Almost all long tasks (scans, audits, measurements) run in the background: you can switch pages while they finish.

## Dashboard

A real-time summary of your network:

- **This computer**: your IP, the mask (for example /24) and the network interface.
- **Gateway**: the router's IP and its current latency.
- **Devices on the network**: how many hosts the last scan found.
- **Security alerts**: total alerts from the intrusion detector.
- **Network traffic**: download and upload over the last 2 minutes.
- **Latency to the router**: measured every 2 seconds. If it rises or red marks appear (lost packets), the problem is in your local network.
- **Security** and **Connection quality**: the score of the last audit and of the last quality measurement.
- **Quick actions**: shortcuts to the most common tasks.

## Network & topology

Discovers every active host on your subnet.

1. Press **Scan network**. Every address is tried with ping and with TCP connections to common ports (no special rights needed). A /24 network takes 10 to 40 seconds.
2. Choose **Map** to see the Internet at the top, the router in the middle and the devices around it, coloured by type (computer, phone, printer, server, media, IoT…). Hover to see details and click to select one.
3. Choose **List** for the full table: IP, name, MAC, vendor, type, latency and detected open ports.

With a host selected you can **scan all its ports**, **audit its security**, **measure its latency**, **watch it** (it will appear in Monitoring) or **wake it up** with Wake-on-LAN.

Notes:

- The **vendor** is estimated from the MAC and is approximate. "Private (random) MAC" means the device (usually a phone) hides its real MAC.
- The **type** is guessed from open ports and vendor; it can be wrong.
- Hosts that block ping and have no open ports may not appear.
- If you scan again and a new host shows up, a "New device" alert is raised.
- **Export CSV** saves the list in your home folder.

## Ports

It has two tabs:

- **This computer**: the ports your computer is listening on and its active connections, with the program using them. Ports in **amber** listen on all interfaces (0.0.0.0): any device on the network can try to connect. Tick "Also show connections" to see who your computer is talking to right now. Program names only appear for your own processes or with administrator rights.
- **Port scanner**: checks which TCP ports another host has open. Type the IP or name and choose the ports: `comunes` (about 60 common ones), `1-1024`, `todos` (all) or a list like `22,80,443,8000-8100`. With "Grab banners" the app tries to read which program and version answers on each port. At the end you'll see how many ports are open, closed (the host says no) or filtered (a firewall doesn't answer).

## Packet capture

Shows network traffic packet by packet, like a simpler Wireshark.

**Rights needed for live capture:** the easiest way is the **Elevate to superuser** button (called **Elevate to administrator** on Windows) at the bottom of the side menu while the app has no superuser rights. It asks for your password (or the Windows confirmation) and reopens the app with the rights it needs. On Linux it only gives the app the capture permission, without running the whole app as root. Manually:

- **Linux**: run the app with `sudo`, or grant it once: `sudo setcap cap_net_raw,cap_net_admin=eip /path/to/redvision`.
- **Windows**: install Wireshark (includes Npcap and dumpcap) and run RedVisión as administrator.
- **macOS**: run the app with `sudo` (it uses tcpdump).

How to use it:

1. Choose the **interface** (on Linux, `any` captures all of them) and press **Start capture**.
2. Type in **Filter** to see only what interests you: a protocol (`dns`, `tcp`, `tls`, `arp`), a port (`443`), an IP or any text (`google`). You can combine several words.
3. Click a packet to see its **layers** (Ethernet, IP, TCP/UDP and application: DNS, HTTP, TLS, DHCP…) and its **hex bytes**.
4. **Save .pcap** stores the capture to open later here or in Wireshark. **Open file** loads `.pcap` and `.pcapng` captures (no rights needed).

The last 50,000 packets are kept in memory. Untick "Follow latest" so the list stops moving while you read.

## Deep analysis

Summarizes what was captured (live or from a file):

- **Protocols by volume**: what kind of traffic fills the network.
- **Traffic per second**: a chart of the capture.
- **Top talkers** and **top conversations**: who uses the network.
- **Names queried via DNS** and **encrypted sites (TLS)**: which sites devices connect to (the server name is visible when an HTTPS connection starts).
- **TCP connection health**: many unanswered attempts point to a scan, a firewall or a service that's down.
- **Unencrypted web requests (HTTP) and DHCP**: insecure web traffic and devices asking for an address.

## Latency & loss

Continuously measures how fast a target answers.

1. Type a target or use the quick buttons (Router, Cloudflare, Google).
2. Choose **Ping (ICMP)** or **TCP connection to port** (useful if the target blocks ping) and how often to measure.
3. Press **Start**.

What the numbers mean:

- **Loss**: percentage of replies that don't arrive. More than 1-2 % is already noticeable.
- **Average, minimum and maximum latency**: in milliseconds (ms).
- **Jitter**: how much latency varies from one measurement to the next. Above 30 ms it affects calls.
- **95th percentile**: 95 % of measurements are below this value.
- **MOS (voice)**: estimated call quality, from 1 (bad) to 4.5 (excellent).

Below it a plain-language diagnosis appears. Compare the latency to the router with the latency to the Internet: if the router is already slow, the problem is at home (Wi-Fi or cable), not your provider.

**Route to target (traceroute)** shows every hop your traffic takes. A hop with much more latency than the previous ones shows where the bottleneck is. It needs `traceroute` or `tracepath` on Linux and macOS; Windows uses `tracert`.

## Quality (QoE)

Estimates how your connection will feel in real use. Press **Measure quality now** (about 30 seconds): it measures the router, Internet latency, DNS, connection time to a website and **download** and **upload** speed to the Internet.

You'll get an **overall score** and a score for voice calls, video calls, video streaming, online gaming and web browsing. Video calls depend mostly on upload: 1 Mbps is tight and 5 Mbps or more is comfortable. The download test file and the upload server (it must accept POST requests) can be replaced; both must start with `http://`. If the download one doesn't answer, a backup is used.

## DNS analysis

DNS turns names (like `example.com`) into IP addresses. A slow or tampered DNS makes everything feel slow or insecure.

- **Query**: asks for a record type (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA…) from a specific server: your system's, Cloudflare, Google, Quad9, OpenDNS or another. For PTR you can type an IP directly.
- **Full analysis**: compares the speed of several DNS servers, lists the domain's records and checks its security: DNSSEC, SPF and DMARC (email protection), CAA (who may issue certificates) and whether your provider redirects non-existent domains (NXDOMAIN hijacking).

## Vulnerabilities

Looks for security problems on devices in your network.

**This computer's security** (top of the page): press **Check this computer** and the app looks at your own computer: whether the firewall is on, real-time antivirus (Windows), whether the disk is encrypted (BitLocker, FileVault or LUKS), which dangerous services are open to the whole network, the SSH settings, whether you use an unusual DNS, whether a proxy is configured, whether the hosts file redirects important sites, whether you're on an open or WEP Wi-Fi and how many days since the last restart. Every problem comes with an explanation and how to fix it.

- **Audit this host**: type an IP or name.
- **Audit the router**: checks your gateway.
- **Audit whole network**: checks every host from the last scan.

About 60 common ports and dangerous services are checked (and, if there's HTTPS, the expiry and validity of its certificate): Telnet, anonymous FTP, SMB, remote desktop, VNC, reachable databases (Redis, MongoDB, MySQL…), Elasticsearch, Docker, unprotected Memcached, SNMP with the «public» community, UPnP, open DNS resolvers, old SSH versions and web servers showing their version.

Each finding has a level (Critical, High, Medium, Low, Info), an explanation and **how to fix it**. The **security score** starts at 100 and drops according to how serious the findings are. You can export the findings to CSV.

## Intrusions & anomalies

An intrusion detector that watches your network while the app is open.

**Without capture** it watches for: ARP spoofing (someone impersonating the router), new devices on the network, watched hosts that stop responding, abnormal traffic spikes and **router or DNS changes** (every 30 seconds it checks whether the gateway or DNS servers changed without you switching networks, a common trick to redirect your traffic).

**With live capture** it also analyzes every packet and detects: port scans and network sweeps, stealth scans (NULL, FIN, XMAS), SYN and ICMP floods, rogue DHCP servers, DNS tunnels (data exfiltration), traffic to malware ports and passwords sent unencrypted.

Alerts can be filtered by level, cleared and exported. The last 7 days are kept, so when you reopen the app you still see what happened. If a **high or critical** alert fires (or a watched host stops responding), the app warns you with a **system notification** even when you're in another window; you can turn it off in Settings. The full list of rules is at the bottom of the page.

> An alert isn't always an attack. For example, "The router's MAC appears on other IPs" may simply be a router with several addresses. Check the context before acting.

## Monitoring

- **Traffic**: download and upload for each interface or all together, with a table of current and total speeds.
- **Watched hosts**: add IPs or names (servers, cameras, the router, a website). They're pinged every 5 seconds and you'll see if they're up, their latency and their availability in %. If one stops responding an alert appears. The list is kept between sessions.
- **Latency to router**: a continuous chart.

## Speed between computers

Measures the real speed between two computers on your network (like iperf). Use it to check a cable, a switch, a Wi-Fi link or a repeater.

1. On the **other computer**, open RedVisión, go to this page and press **Start server**. You'll see its address (for example `192.168.1.20:5201`).
2. On **this computer**, type that IP in "Server" (or pick it from the list if you scanned the network) and press **Measure speed**.
3. It measures **latency**, **download** (the server sends) and **upload** (this computer sends).

Tips:

- Use 4 **parallel connections** to make the most of fast links.
- If it doesn't connect, allow TCP port 5201 in the server computer's firewall.
- Over gigabit cable you should see more than 900 Mbps. Around 95 Mbps means something (cable, port or switch) is limiting the link to 100 Mb/s.
- You can test against `127.0.0.1` with the server running on the same computer to check everything works.

## LAN diagnosis

Automatically looks for the usual causes of a slow or unstable local network. Press **Diagnose the network**; it takes a few seconds.

It checks:

- Whether you have an IP address and DHCP works (169.254.x.x addresses mean the router didn't give you one).
- Loss, latency and jitter to the router (20 pings).
- Negotiated cable speed and half duplex (on Linux).
- Wi-Fi signal strength (Linux and Windows).
- Errors and dropped packets on the network card (Linux).
- Several default routes or two connections to the same network at once.
- DNS that doesn't answer or is slow.
- Internet access, captive portals or proxies intercepting the web.
- Path MTU, IPv6 and whether the router's MAC appears on other IPs.

Optionally, **Include load test** measures *bufferbloat*: how much latency rises while downloading for about 10 seconds. If it rises a lot, enable SQM or QoS on the router.

You'll get a health score, your network's facts and every problem with its fix.

## Wi-Fi analyzer

If the computer has a Wi-Fi card (or a USB Wi-Fi adapter), this page shows the networks around you even while you're on cable. Without a card, the page says so.

- **Your Wi-Fi connection**: network, BSSID (the specific access point), channel and band, link speed and signal strength in dBm, with a chart of the signal over time. As a guide: above -55 dBm is excellent, down to -67 good, down to -75 fair, and below that poor.
- **Recommended channels**: how busy each 2.4 GHz and 5 GHz channel is and which is the **freest channel**. On 2.4 GHz use only channels 1, 6 or 11.
- **Spectrum**: each network is drawn as a bell centred on its channel and as tall as its signal. Overlapping bells mean those networks interfere with each other.
- **Security and problems**: warns if your network is open or uses WEP or old WPA, if another network has your name with different security (possible fake access point), if your signal is weak, if you're on 2.4 GHz when 5 GHz is available, if your channel is crowded, and about nearby open or hidden networks.
- **Nearby networks**: a table with name, BSSID, vendor, channel, band, signal and security. It can be exported to CSV.

Press **Scan Wi-Fi networks** or tick **Refresh every 10 s** to follow the signal as you move around.

Requirements: on Linux it uses NetworkManager (`nmcli`); on Windows, `netsh` (Windows 11 asks for **location** permission to list networks); on macOS, the system information (it may not show the BSSID).

## HTTPS certificates

It's in the side menu, right below "Vulnerabilities". Type one or more servers (`debian.org mail.example.com:993`) to see how many days their certificate has left (red if it has expired or expires within 7 days, orange and amber under a month), who it covers, who issued it, key and signature type, the certificate chain and which TLS versions it accepts (a red ✔ for TLS 1.0 and 1.1, which are obsolete). It warns about expired certificates, a different name, self-signed ones, weak signature or key and old TLS. The certificate the server sends is read; **the trust chain signature isn't verified**, and servers that only support TLS 1.3 encrypt their certificate and can't be read this way.

## Tools

- **My public IP**: your Internet IP, country, city and provider (uses the ip-api.com service).
- **Subnet calculator**: type `IP/prefix` (for example `192.168.1.10/24`) to get the network, mask, broadcast, first and last host and how many hosts fit.
- **Wake-on-LAN**: turns on a powered-off computer by sending a "magic packet" to its MAC. The computer needs Wake-on-LAN enabled in the BIOS and network card.
- **Look up vendor by MAC**.
- **Path MTU**: the largest packet that reaches a target without being split. Useful with VPNs or sites that won't load.
- **System ARP table**: which IP belongs to which MAC on your network.
- **UPnP devices**: TVs, routers, NAS and other gadgets announcing themselves, with name and model.
- **Whois**: who the registered owner of a domain or IP is, with dates and public contacts. It follows referrals to the registry's server.
- **Bonjour / mDNS services**: printers, Chromecast, AirPlay, shared folders…
- **System interfaces and routes**: the network configuration as the operating system sees it.

## Settings

- **Language**: Español, English, Português, Français or Deutsch. The system language is used the first time.
- **Theme**: Dark, Light, Midnight or Terminal.
- **Interface size**: from 70 % to 160 %.
- **Scan the network when the app opens**.
- **System notifications** for serious alerts, with a button to test them.

Preferences and watched hosts are saved in:

- Linux: `~/.config/redvision/settings.conf`
- Windows: `%APPDATA%\RedVision\settings.conf`
- macOS: `~/Library/Application Support/RedVision/settings.conf`

## Practical cases

### The Internet is slow

1. Go to **LAN diagnosis** and press "Diagnose the network". Wi-Fi, cable or router problems will show at the top.
2. In **Latency & loss**, measure the **Router** first and then **Cloudflare**. If the router already shows loss or high latency, the problem is at home; if only the Internet fails, it's your provider.
3. Measure **Quality (QoE)** to see the download speed and how it affects each use.
4. If things get bad when someone downloads, enable the diagnosis load test (bufferbloat).

### The Wi-Fi keeps dropping

1. **LAN diagnosis** tells you the signal and the loss to the router.
2. Leave **Latency & loss** measuring the router for a few minutes while you move around the house: red marks show the drops.

### Is there a stranger on my network?

1. Scan in **Network & topology** and review the list: vendor, name and type.
2. Keep the app open: the detector will warn about **new devices** and ARP spoofing.
3. For a deeper look, start a capture and check **Intrusions & anomalies**.

### Checking my network's security

1. Scan the network and press **Audit whole network** in **Vulnerabilities**.
2. Start with critical and high findings; each one says how to fix it.
3. Also check the router with **Audit the router** and the **Ports -> This computer** tab.

### Measuring the cable or Wi-Fi between two computers

Use **Speed between computers**: server on one, measurement on the other.

## Exporting and saving data

- **CSV**: the "Export CSV" buttons (hosts, connections, alerts and findings) save a `RedVision-…-date.csv` file in your home folder. Open it with Excel, LibreOffice or Google Sheets.
- **Captures**: "Save .pcap" in Packet capture (by default `captura-redvision.pcap` in your home folder).

## Privacy and responsible use

- RedVisión sends no data to any server of its own. It only connects to the Internet when you ask it to: measuring latency or quality, querying public DNS, the public IP (ip-api.com) or the speed test file.
- Captures can contain personal information. Store them carefully.
- Only scan and audit networks and devices you own or have permission to test.

## Common problems

- **"No permission to capture"**: press **Elevate to superuser** (**administrator** on Windows) in the side menu or see the rights in "Packet capture".
- **On Windows (for example in a virtual machine) the app doesn't open or closes by itself**: the app tries OpenGL first and, if there isn't any, it reopens itself with DirectX (in software if needed) and remembers it. If it still fails you'll see a message with the cause, also saved in `%APPDATA%\RedVision\error.log`. You can force the engine with `redvision.exe --renderer wgpu` (DirectX) or `--renderer glow` (OpenGL); to go back to automatic, delete `%APPDATA%\RedVision\renderer`. Turning on 3D acceleration in the VM helps but isn't required.
- **A device I know is on doesn't appear**: it may block ping and have no open ports. Try scanning its ports directly.
- **Traceroute doesn't work on Linux**: install the `traceroute` package (or `iputils-tracepath`).
- **Speed between computers won't connect**: start the server on the other computer and open TCP port 5201 in its firewall.
- **The quality test doesn't measure speed**: the test file may be unavailable; change the address to another large `http://` file.
- **The icon doesn't show on Linux (Wayland)**: open the app normally once; it registers itself in the applications menu.
- **The vendor is empty**: the built-in list only includes common vendors.

## Glossary

- **IP**: a device's address on the network (for example 192.168.1.10).
- **Mask / prefix**: the size of the network; /24 means 254 hosts.
- **Gateway**: the router connecting your network to the Internet.
- **MAC**: the physical identifier of a network card.
- **ARP**: protocol that maps IPs to MACs inside the local network.
- **DHCP**: the router service that hands out IP addresses.
- **DNS**: turns domain names into IP addresses.
- **Port**: a numbered "door" through which a program receives connections (80 web, 443 secure web, 22 SSH…).
- **Latency**: time for a packet to go and come back, in milliseconds.
- **Jitter**: variation in latency.
- **Packet loss**: percentage of data that doesn't arrive.
- **MOS**: voice quality score from 1 to 4.5.
- **QoE**: quality of experience, how the user perceives the connection.
- **MTU**: the largest packet that fits without being split (usually 1500 bytes).
- **Bufferbloat**: latency increase when the line is busy.
- **TLS / SNI**: encryption for secure websites; SNI is the site name visible when connecting.
- **UPnP / mDNS**: systems devices use to announce themselves on the network.
- **Wake-on-LAN**: turning a computer on over the network.
