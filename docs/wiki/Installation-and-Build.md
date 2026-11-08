# Installation and Build Reference

Contraband requires Go 1.22+ and compiles cleanly with `CGO_ENABLED=0` across Linux, macOS, and Windows.

---

## 1. Quick Build (Host Binary)

To build the unified `contraband` binary and dedicated standalone binaries for the local host architecture:

```bash
git clone https://github.com/shehzade/contraband.git
cd contraband
make build
```

This compiles:
- `bin/contraband`: Unified multi-tool binary containing all subcommands (`client`, `server`, `sweep`, `listen`, `soak`, `report`).
- `bin/contraband-client`: Dedicated client binary stripped for lightweight deployment.
- `bin/contraband-server`: Dedicated server binary for reflection and live dashboard services.

---

## 2. Cross-Compilation Matrix

To generate statically linked binaries for all target architectures:

```bash
make build-all
```

| Output File | Target OS | Architecture | Notes |
| :--- | :--- | :--- | :--- |
| `contraband-linux-amd64` | Linux | x86_64 / AMD64 | Static ELF, eBPF redirector capable |
| `contraband-linux-arm64` | Linux | AArch64 / ARM64 | AWS Graviton, Raspberry Pi |
| `contraband-darwin-amd64` | macOS | Intel x86_64 | Native POSIX socket engine |
| `contraband-darwin-arm64` | macOS | Apple Silicon (M1/M2/M3) | Native macOS arm64 |
| `contraband-windows-amd64.exe` | Windows | x86_64 | Native Win32 / SChannel proxy support |
| `contraband-windows-arm64.exe` | Windows | ARM64 | Surface Pro / WoA native |

---

## 3. Direct Go Build Commands

If you do not have `make` installed:

```bash
# Unified binary
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/contraband ./cmd/contraband

# Standalone Client
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/contraband-client ./cmd/contraband-client

# Standalone Server
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/contraband-server ./cmd/contraband-server
```

---

## 4. Verification

Verify build purity and version:

```bash
./bin/contraband version
file ./bin/contraband-client
```

Output should confirm statically linked execution without external `.so` or `.dll` runtime dependencies.
