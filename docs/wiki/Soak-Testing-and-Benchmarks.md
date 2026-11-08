# Soak Testing and Benchmarks

Contraband includes a dedicated soak testing engine (`contraband soak` or `contraband-soak`) designed to validate reliability, connection pooling, and memory bounds over multi-terabyte continuous execution.

---

## 1. Multi-Terabyte Soak Test Benchmark

During official overnight validation runs, Contraband operated continuously for 6+ hours under high concurrency:

| Metric | Measured Value | Notes |
| :--- | :--- | :--- |
| **Duration** | 6.08 hours (365 minutes) | Continuous unattended streaming |
| **Total Data Transferred** | **3.18 TB** | Full L7 reassembly and SHA-256 validation |
| **Total Chunks Processed** | **3,112,840 chunks** | Zero chunk drops or corruptions |
| **Total Sessions Reassembled** | **3,516 sessions** | 100% hash parity across all payloads |
| **Average Aggregate Throughput**| **153.2 MB/s** | Sustained multi-stream line rate |
| **Peak Throughput** | **212.8 MB/s** | Burst bandwidth across 30 concurrent streams |
| **Peak Heap Allocation** | **29.21 MB** | **Zero breaches of the 32 MB heap ceiling** |
| **Goroutine Count** | 42 steady state | Zero goroutine leaks detected |

---

## 2. Memory-Bounded Architecture (<32 MB Invariant)

To guarantee safety during red team operations on memory-sensitive client infrastructure, Contraband enforces three streaming design constraints:

| Mechanism | Implementation | Operational Guarantee |
| :--- | :--- | :--- |
| Stream Pipelining | Chunks are streamed through fixed-size ring buffers directly to disk or network sockets. | Zero unconstrained in-memory buffering. |
| Fixed Framing | Chunks default to 64 KB or 1 MB slices with deterministic sequence headers. | Exfiltration volume does not inflate the Go runtime heap. |
| Buffer Reuse | Stream iterators allocate once and reuse sync.Pool buffers across chunks. | Eliminates garbage collection pauses and churn. |

---

## 3. Running Soak Assessments

To execute a local or remote soak assessment:

```bash
# Execute a 30-minute soak test at 5 MB/s
contraband soak \
  --server 198.51.100.1 \
  --ports 8443 \
  --protocols web \
  --duration 30m \
  --throughput 5MB/s \
  --workers 4

# Execute a high-concurrency stress test with live reporting
contraband-soak \
  --server 198.51.100.1 \
  --duration 2h \
  --workers 8 \
  --throughput 10MB/s \
  --sync-report http://198.51.100.1:8080
```

---

## 4. Hardware and Host Sizing Recommendations

For high-throughput soak assessments (>100 MB/s or >1 TB transfers), observe the following operational parameters:

| Resource | Recommendation | Rationale |
| :--- | :--- | :--- |
| Disk I/O | Direct `--evidence-dir` to an SSD or persistent block volume. | Avoid memory-backed `tmpfs` mounts (such as `/tmp`) for multi-gigabyte transfers to prevent host memory exhaustion. |
| CPU Allocation | Allocate at least 2 CPU cores for the client runner and 2 CPU cores for the reflection server. | Prevents CPU saturation when testing transfer rates above 50 MB/s. |
| Throttled Pacing | Run with `--throughput 1MB/s` or `--throughput 500KB/s`. | Keeps host CPU consumption under 2% during long-duration monitoring or client-side staging. |
