# Proxy Traversal and Evasion Reference

Contraband includes an autonomous proxy evaluation and evasion engine designed to bypass corporate enterprise gateways, next-generation firewalls, and TLS inspection appliances.

---

## 1. Proxy Evaluation Engine (`--proxy`)

The proxy engine supports automated environment discovery and explicit configuration:

| Mode | Syntax | Description |
| :--- | :--- | :--- |
| **Auto** (Default) | `--proxy auto` | Sequentially probes environment variables (`HTTP_PROXY`, `HTTPS_PROXY`), system PAC, WPAD, and direct outbound routing. |
| **Direct** | `--proxy direct` | Enforces direct socket connection bypassing all local proxy settings. |
| **Explicit HTTP** | `--proxy http://proxy.corp:8080` | Routes traffic through an explicit HTTP CONNECT forward proxy. |
| **SOCKS5** | `--proxy socks5://127.0.0.1:1080` | Routes all TCP probes and streams through a SOCKS5 proxy. |

### Authentication Modes (`--proxy-auth`)

| Mode | Authentication Protocol | Description |
| :--- | :--- | :--- |
| `basic` | Base64 Encoded Credentials | Transmits standard `Proxy-Authorization: Basic <credentials>`. |
| `ntlm` | NTLMv1 / NTLMv2 Challenge-Response | Pure Go Type 1 negotiation, Type 2 challenge parsing, and Type 3 response generation. |
| `negotiate` / `kerberos` | SPNEGO Encapsulation | Authenticates using Kerberos SPNEGO token exchange. |

---

## 2. TLS Fingerprint Masquerade (`--tls-fingerprint` / `--utls`)

Enterprise TLS inspection appliances (BlueCoat, Palo Alto, Zscaler) flag Go's default `crypto/tls` Client Hello signature. Contraband integrates `uTLS` to mirror authentic browser handshakes:

```bash
# Mimic modern Chrome browser
contraband-client --tls-fingerprint chrome

# Mimic Edge, Safari, Firefox, or curl
contraband-client --tls-fingerprint edge
contraband-client --tls-fingerprint safari
contraband-client --tls-fingerprint firefox
contraband-client --tls-fingerprint curl
```

This randomizes and aligns:
- TLS 1.3 Cipher Suites and Extension ordering
- Supported Elliptic Curves (`X25519`, `P-256`, `P-384`)
- Application Layer Protocol Negotiation (ALPN: `h2, http/1.1`)
- SNI extensions, session ticket parameters, and key share formatting

---

## 3. Traffic Cadence and Rate Limiting

To evade anomaly detection and volume thresholds in SIEM and NDR platforms:

```bash
# Rate limiting
contraband-client --throughput 500KB/s     # Cap outbound transfer speed
contraband-client --rate-limit 100         # Cap L4 sweep packets per second

# Cadence pacing
contraband-client --cadence steady         # Fixed-interval chunk emission
contraband-client --cadence jittered       # Randomized sleep between chunks (500ms - 4s)
contraband-client --cadence burst          # High-speed chunk emission followed by dormant periods
contraband-client --cadence office-hours   # Transmits exclusively during active business hours
```

---

## 4. Evasion Transforms (`--transforms`)

Data chunks can be processed through sequential transformation chains before transmission:

```bash
# Compress and encrypt payload chunks
contraband-client --transforms gzip,aes_gcm --passphrase "SecretPassphrase123"

# Base64 or Hex encoding for text-only inspection channels
contraband-client --transforms zstd,base64
```

Supported transforms: `raw`, `base64`, `hex`, `gzip`, `zstd`, `aes_gcm`.
