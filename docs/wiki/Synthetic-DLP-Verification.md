# Synthetic DLP Verification Reference

Contraband includes an in-memory procedural generation engine that constructs mathematically valid test records. These records match standard DLP, CASB, and firewall signatures without exposing real customer or enterprise data.

---

## 1. Supported Secret Categories (`--dlp`)

| Category | Flag | Synthetic Structure & Validation |
| :--- | :--- | :--- |
| **PCI-DSS** | `--dlp pci` | 16-digit Visa (prefix `4`), Mastercard (prefixes `51-55`), and 15-digit Amex (`34`, `37`). Strictly validates against the **Luhn Mod-10 algorithm**. Generated with realistic `MM/YY` expiration dates and CVVs. |
| **PII** | `--dlp pii` | **US SSN**: 9-digit format (`AAA-GG-SSSS`) excluding reserved area numbers (`000`, `666`, `900-999`).<br/>**UK NINO**: HMRC format (`^[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]$`).<br/>**Canadian SIN**: 9-digit format with regional leading digits passing Luhn Mod-10. |
| **Healthcare** | `--dlp hipaa` | **HL7 v2.5.1**: Pipe-and-hat delimited messages (`MSH`, `PID`, `PV1`, `DG1`).<br/>**FHIR JSON**: `Patient`, `Condition`, and `Observation` resources referencing authentic ICD-10-CM diagnosis codes (e.g. `E11.9`, `I10`). |
| **API Keys** | `--dlp secrets` | **AWS Access Keys**: 20-character IDs starting with `AKIA` + 40-character Base64 secret keys.<br/>**GitHub PAT**: Modern `ghp_` format + 36 alphanumeric characters.<br/>**GCP Service Account**: Valid JSON credential format with RSA private key blocks.<br/>**OpenAI / Anthropic**: `sk-[a-zA-Z0-9]{48}` and `sk-ant-[a-zA-Z0-9]{95}`.<br/>**PEM Keys**: In-memory generated 2048-bit RSA and ECDSA private keys. |
| **All** | `--dlp all` | Generates a balanced composite stream rotating across all four categories. |

---

## 2. Text Carrier Formatting (`--carrier-type`)

Payloads can be structured into business carrier formats to test deep content inspection:

```bash
contraband-client --carrier-type csv     # Transactional records with customer headers
contraband-client --carrier-type json    # Nested JSON object array
contraband-client --carrier-type sql     # SQL batch INSERT statements
contraband-client --carrier-type email   # RFC 5322 MIME messages with billing attachments
contraband-client --carrier-type syslog  # RFC 5424 structured syslog audit events
```

---

## 3. Steganographic Embedding (`--stego`)

To evaluate file carving and media analysis engines:

| Format | Flag | Mechanism |
| :--- | :--- | :--- |
| **PNG** | `--stego png` | Synthesizes an authentic RGB PNG in memory; modifies the least significant bit (LSB) of each color byte. Recomputes valid CRC32 chunk checksums. |
| **JPEG** | `--stego jpeg-zip` | Synthesizes a valid JPEG image and injects encrypted payload chunks into `COM` (0xFFFE) comment markers or `EXIF UserComment` metadata. |
| **PDF** | `--stego pdf-jar` | Synthesizes valid `%PDF-1.7` documents with authentic `xref` tables and compressed `/FlateDecode` streams, or creates dual-format PDF-ZIP polyglots. |
| **ZIP** | Built-in | Appends payload data into the variable-length End of Central Directory (EOCD) comment field without corrupting archive extractors (`unzip`, `7z`). |

---

## 4. Standalone Generator Command (`generate`)

To generate synthetic test payloads directly to disk or stdout for standalone DLP tuning:

```bash
# Generate 100 KB of synthetic credit card records as CSV
contraband generate --dlp pci --carrier-type csv --size 100KB -o pci_test.csv

# Generate 5 MB of healthcare HL7 records
contraband generate --dlp hipaa --carrier-type text --size 5MB -o hipaa_test.hl7

# Pipe synthetic secrets into an external tool
contraband generate --dlp secrets --carrier-type json --size 50KB | jq .
```
