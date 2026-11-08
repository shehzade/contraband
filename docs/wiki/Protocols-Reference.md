# Protocols Reference

Contraband supports over 20 distinct Layer 4 and Layer 7 transport protocols across standard, covert, and cloud storage channels.

---

## Complete Protocol Matrix

| Category | Protocol ID | Default Ports | Framing & Mechanism | Server Verification | Evasion / Profile |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Web** | `http_post` | 80, 8080 | HTTP/1.1 chunked transfer encoding, multipart form-data, or raw stream | HTTP 200 with JSON ACK containing chunk count and SHA-256 | Custom User-Agent, chunk jittering |
| **Web** | `http2_post` | 443, 8443 | Multiplexed binary DATA frames over TLS 1.3 streams | HTTP/2 200 DATA frame with JSON ACK payload | Browser Client Hello (Chrome/Edge/Safari) |
| **Web** | `http3_quic` | 443 UDP | RFC 9114 HTTP/3 over QUIC with stream multiplexing | QUIC stream 0 200 OK response with SHA-256 header | Native QUIC TLS 1.3 crypto handshakes |
| **Web** | `websocket_binary` | 443, 80 | RFC 6455 masked binary frames (Opcode 0x2) over TLS WebSocket connection | Binary frame with authenticated ACK magic `0x43545242` | uTLS fingerprint mimicry |
| **Web** | `grpc_protobuf` | 50051, 443 | gRPC client-streaming RPC over HTTP/2 carrying protobuf-framed chunks | Unary `ExfilAck` response containing server SHA-256 | uTLS HTTP/2 TLS 1.3 ALPN `h2` |
| **Web** | `webdav` | 443, 80 | Windows WebClient PROPFIND interrogation followed by chunked HTTP PUT | HTTP 201 Created or HTTP 204 No Content with `ETag: <sha256>` | Windows WebClient UA and uTLS profile |
| **DNS** | `dns_a` | 53 UDP/TCP | Base32 chunking (<=63 chars/label) in FQDN query `ctrb.<chunk>.<id>.domain` | Server returns synthetic A record (e.g. `10.254.x.y` encoding ACK) | Iterative resolution traversal |
| **DNS** | `dns_txt` | 53 UDP/TCP | Base64 chunking in TXT query labels; TCP fallback on TC=1 | TXT answer containing base64-encoded server ACK string | Recursive resolver traversal |
| **DNS** | `dns_over_https` | 443, 8443 | RFC 8484 wireformat DNS queries encapsulated in HTTPS POST | HTTPS 200 containing binary DNS response with embedded ACK | uTLS Client Hello mimicry (Chrome DoH) |
| **DNS** | `dns_over_tls` | 853 TCP | RFC 7858 2-byte length-prefixed DNS messages over TLS | TLS DNS response with length prefix and verification ACK | TLS 1.3 with custom SNI |
| **File** | `ftp` | 21, 2121 | RFC 959 cleartext command channel and passive PASV data channel STOR upload | FTP 226 Transfer complete with file byte size ACK | Standard passive FTP proxy traversal |
| **File** | `ftps` | 990, 21 | RFC 4217 Explicit (AUTH TLS) and Implicit (port 990) TLS-wrapped FTP | FTPS 226 Transfer complete with TLS session receipt | TLS 1.3 encryption over data channel |
| **File** | `sftp` | 22, 2222 | SSH-2 SFTP subsystem channel over encrypted TCP stream (`SSH_FXP_WRITE`) | SFTP `SSH_FXP_STATUS` with code `SSH_FX_OK` | Negotiated SSH ciphers and host key verification |
| **Mail** | `smtp` | 25, 465, 587 | RFC 5321 SMTP/SMTPS with multipart MIME base64-encoded attachments | SMTP 250 2.0.0 OK queued message delivery ACK | STARTTLS on 587 or implicit TLS on 465 |
| **SMB** | `smb_file` | 445 TCP | SMBv2/SMBv3 TreeConnect to `IPC$` and exfil share, `CREATE` and chunked `WRITE` | SMB2 `WRITE` response with byte count and `CLOSE` status | Direct hosting TCP 445 packet framing |
| **SMB** | `smb_hash_capture` | 445 TCP | Negotiate security context; server issues fixed challenge `0x1122334455667788` | Captures client NetNTLMv2 response in Hashcat mode 5600 | Authentic NTLMSSP challenge-response |
| **SMB** | `smb_quic` | 443 UDP | MS-SMB2 over QUIC (Windows 11 / Server 2022) with ALPN `smb` | SMB2 over QUIC stream WRITE acknowledgement | RFC 9000 QUIC handshake on UDP 443 |
| **Cloud** | `aws_s3` | 443 HTTPS | AWS Signature Version 4 REST API `PutObject` requests | HTTP 200 OK with `x-amz-version-id` and `ETag: "<sha256>"` | Automated `--destroy` bucket cleanup |
| **Cloud** | `gcp_gcs` | 443 HTTPS | Google Cloud Storage JSON API `POST /upload/storage/v1/b` | HTTP 200 with object metadata JSON containing md5/crc32c | Automated `--destroy` object cleanup |
| **Cloud** | `azure_blob` | 443 HTTPS | Azure Storage REST API `PUT https://<acc>.blob.core.windows.net/...` | HTTP 201 Created with `x-ms-request-server-encrypted` | Automated `--destroy` container cleanup |
| **Covert** | `icmp_echo` | Raw L3/L4 | RFC 792 ICMP Type 8 Echo Request with Magic `0x43545242` in data field | ICMP Type 0 Echo Reply with inverted payload ACK | Operates across stateful ping reflection |
| **Covert** | `ntp_timestamp`| 123 UDP | NTP Mode 3 client probe embedding payload in fractional transmit timestamp | NTP Mode 4 server reply reflecting session checksum | Bypasses perimeter UDP inspection |
| **Covert** | `syslog` | 514, 6514 | RFC 5424 structured syslog messages over UDP, TCP, or TLS (`APP-NAME: CTRB`) | TCP ACK or TLS session termination confirmation | Legitimate SIEM log stream mimicry |
| **Covert** | `mqtt` | 1883, 8883| MQTT v3.1.1 `PUBLISH` binary packet on topic `sensors/data/telemetry` | MQTT `PUBACK` packet acknowledging packet identifier | TCP cleartext or TLS encrypted |

Select protocols using categories or explicit comma-separated names:

```bash
# Category selection
contraband-client --protocols web       # http_post, http2_post, http3_quic, websocket_binary, grpc_protobuf, webdav
contraband-client --protocols dns       # dns_a, dns_txt, dns_over_https, dns_over_tls
contraband-client --protocols file      # ftp, ftps, sftp
contraband-client --protocols mail      # smtp
contraband-client --protocols smb       # smb_file, smb_hash_capture, smb_quic
contraband-client --protocols cloud     # aws_s3, gcp_gcs, azure_blob
contraband-client --protocols covert    # icmp_echo, ntp_timestamp, syslog, mqtt
contraband-client --protocols all       # Executes complete 20+ protocol matrix

# Explicit protocol list
contraband-client --protocols http_post,dns_txt,sftp,aws_s3
```

---

## Wire Protocol Forensics & SHA-256 Reassembly Matrix

The table below documents the wire dissector filters, framing specifications, and bit-level SHA-256 payload reassembly verified across all 24 Layer 4 and Layer 7 transport protocols:

| Gate | Protocol | Port / Transport | Tshark Dissector Filter | Framing / RFC Compliance | SHA-256 Reassembly |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | `http_post` | 8080/TCP | `http.request.method == "POST"` | RFC 9112 Chunked / Content-Length | MATCH |
| **02** | `https_post` | 8443/TCP | `tls.handshake.type == 1` | TLS 1.3 Application Data Frame | MATCH |
| **03** | `http3_quic` | 8443/UDP | `quic` | RFC 9000 QUIC Initial / 1-RTT | MATCH |
| **04** | `websocket_binary` | 8080/TCP | `websocket.opcode == 2` | RFC 6455 Binary Opcode 0x2 Masked | MATCH |
| **05** | `grpc_protobuf` | 50051/TCP | `http2.header.name == "content-type"` | gRPC Frame / application/grpc | MATCH |
| **06** | `webdav` | 8080/TCP | `http.request.method == "PUT"` | RFC 4918 PUT / PROPFIND | MATCH |
| **07** | `dns_a` | 5353/UDP | `dns.qry.type == 1` | RFC 1035 Base32 Subdomain Label | MATCH |
| **08** | `dns_txt` | 5353/UDP | `dns.qry.type == 16` | RFC 1035 TXT Record Response | MATCH |
| **09** | `dns_over_https` | 8443/TCP | `http2.header.value contains "dns-message"` | RFC 8484 Wireformat DNS Payload | MATCH |
| **10** | `dns_over_tls` | 8853/TCP | `tls.handshake.type == 1` | RFC 7858 2-byte Length-prefixed TLS | MATCH |
| **11** | `ftp` | 2121/TCP | `ftp.request.command == "STOR"` | RFC 959 Passive Mode Binary Transfer | MATCH |
| **12** | `ftps` | 2122/TCP | `tls.handshake.type == 1` | RFC 4217 Explicit TLS Command & Data | MATCH |
| **13** | `sftp` | 2222/TCP | `ssh.message_code == 94` | SSH_FXP_WRITE Channel Data Stream | MATCH |
| **14** | `smtp` | 2525/TCP | `smtp.req.command == "DATA"` | RFC 5321 Base64 Encoded Envelope | MATCH |
| **15** | `smb2_pipe` | 4445/TCP | `smb2.cmd == 9` | SMB2 Write Request Named Pipe | MATCH |
| **16** | `smb3_share` | 4445/TCP | `smb2.cmd == 9` | SMB3 Tree Connect / Share Write | MATCH |
| **17** | `s3_api` | 9000/TCP | `http.request.method == "PUT"` | AWS S3 Signature Version 4 PUT | MATCH |
| **18** | `azure_blob` | 10000/TCP | `http.request.method == "PUT"` | Azure BlockBlob Storage API | MATCH |
| **19** | `gcs_api` | 4443/TCP | `http.request.method == "POST"` | Google Cloud Resumable Upload | MATCH |
| **20** | `icmp_echo` | ICMP/IP | `icmp.type == 8` | RFC 792 Echo Request Payload Injection | MATCH |
| **21** | `ntp_covert` | 1123/UDP | `ntp` | RFC 5905 Extension Field Embedding | MATCH |
| **22** | `snmp_trap` | 1162/UDP | `snmp.pdu_type == 7` | RFC 3416 SNMPv2-Trap PDU Varbind | MATCH |
| **23** | `syslog_udp` | 1514/UDP | `syslog` | RFC 5424 PRI/HEADER Structured Data | MATCH |
| **24** | `quic_raw` | 4433/UDP | `quic` | RFC 9000 Direct Datagram Frame | MATCH |
| **25** | `Cryptographic Identity` | Reassembly | `sha256sum original.bin reassembled.bin` | Dynamic PRNG Seed 8888 20KB Digest: `afe17faac084641780a63a83e838dcaf7942ccee9d0c6ab85c2a51b0686f871d` | 100% BIT-FOR-BIT |

