# Anti-Cheat Scanner

A defensive anti-cheat scanner written in C for Linux. It detects common
cheating techniques: known cheat/debugger tools, library-injection vectors,
attached debuggers, tampered game files, live in-memory code patching, and
virtualized or reverse-engineering sandbox environments.

## What it does

- **Process scan** — enumerates `/proc` and flags:
  - processes running known cheat/debugger tools (Cheat Engine, GameConqueror, x64dbg, gdb, ...)
  - cheat-related keywords in command lines (aimbot, wallhack, trainer, ...)
  - executables launched from writable temp locations (`/tmp`, `/dev/shm`, ...)
  - processes with an attached tracer (live debugging)
- **Environment scan** — detects library-injection vectors (`LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, ...)
- **Debugger self-check** — detects if the scanner itself is being traced via
  `TracerPid` in `/proc/self/status` and a `ptrace(PTRACE_TRACEME)` probe
- **File integrity** — builds SHA-256 baselines of critical files and detects
  any later modification (tamper detection)
- **Live code-segment monitor** (background thread) — locates the executable's
  own `.text` region via `/proc/self/maps`, hashes it as a baseline, then
  continuously re-hashes it in a background thread to detect real-time RAM
  manipulation or code patching of the anti-cheat process itself
- **VM / sandbox detection** — detects virtualized or reverse-engineering
  sandbox environments:
  - CPUID hypervisor-present bit (EAX=1, ECX bit 31) plus the hypervisor
    signature string from CPUID 0x40000000 (VMware, Hyper-V, KVM, Xen,
    Parallels, VirtualBox, bhyve)
  - DMI/BIOS strings under `/sys/class/dmi/id/` (product_name, sys_vendor,
    board_vendor, bios_vendor) for markers like VirtualBox, QEMU, VMware, Bochs
  - `/proc/cpuinfo` `hypervisor` flag and CPU model-name markers
  - container indicators (`/.dockerenv`, `/run/.containerenv`, cgroup runtime
    names)
  - Classification: confirmed VM is **MEDIUM** (allows legitimate cloud-gaming
    users); escalates to **HIGH** when a debugger is attached (reverse-
    engineering sandbox)
- **Server-side telemetry validation** — a simulation of how a game server
  detects cheats from player telemetry alone (since a client-side scanner can
  be fooled by a root user):
  - `PlayerTick` packet: `x/y/z` position, `timestamp`, `pitch`/`yaw` view
    angles
  - **Speedhack** — distance delta between consecutive ticks divided by the
    time delta; if the resulting velocity exceeds the logical max speed
    (15 u/s) it is flagged **HIGH**
  - **Aimbot** — angular change-rate monitor; an instantaneous pixel-perfect
    view snap (>= 360 deg/s) that then locks onto a static vector with no
    natural sub-arc decay/accel curve is flagged **MEDIUM**
  - `--telemetry-sim` feeds an anomaly dataset (50 u/s movement, 90 deg
    instant snap) plus a clean control to prove the server-side logic works
- **Kernel-level cross-process monitor** (optional, root + libbpf) — an eBPF
  tracepoint program on `ptrace` / `process_vm_readv` / `process_vm_writev`
  that escalates any cross-process memory access to a `CRITICAL` kernel finding
  (graceful `[INFO]` fallback when unavailable — see below)
- **Live network reporting** (optional) — MEDIUM+ findings are streamed as
  compact JSON over a non-blocking UDP socket to a standalone dashboard
  (`dashboard.py`), so detections can be aggregated off-host

## Build

```bash
make
```

Requires gcc/clang and make. No external dependencies (SHA-256 is
self-contained in the project). When libbpf is detected at build time the
optional eBPF kernel monitor is compiled in and linked with `-lbpf`; otherwise
it degrades to a no-op fallback.

`make` produces two artifacts:

- `anticheat` — the standalone CLI scanner.
- `libanticheat.so` — a position-independent shared library (`-fPIC -shared`)
  that bundles every module for embedding inside a game engine.

## Engine integration (shared library)

The project can be linked into a game engine (Unreal, Unity, custom C/C++)
through `libanticheat.so`. All public entry points use C linkage and are safe
to call from a foreign game loop.

### Public API (`src/api.h`)

| Function | Purpose |
|----------|---------|
| `int initialize_security_runtime(int flags)` | Initialize the runtime: runs the requested one-shot checks and starts background threads, then returns immediately. Idempotent. Returns 0 on success, -1 if already initialized. |
| `void shutdown_security_runtime(void)` | Stops background threads and releases resources (call from the engine shutdown path). |
| `int security_runtime_verdict(void)` | Returns 0 if clean, 1 if any MEDIUM/HIGH/CRITICAL finding is present. |
| `void security_runtime_counts(int out_counts[5])` | Fills a 5-element array indexed by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL). |
| `int security_runtime_set_network_target(const char *server_ip, int port, const char *key)` | Configure the UDP alert destination (call before `initialize_security_runtime` with `SEC_RUNTIME_NETWORK_LOGGING`). `key` is the HMAC shared secret (or `NULL` to read `ANTICHEAT_NETWORK_KEY`). Returns 0 on success, -1 if the address is invalid or the key is missing (unauthenticated reporting is forbidden). |

`flags` is a bitmask: `SEC_RUNTIME_SCAN` (one-shot process/env/debugger
checks), `SEC_RUNTIME_BACKGROUND` (start the live `.text` integrity monitor
thread), `SEC_RUNTIME_KERNEL_MONITOR` (attempt the privileged eBPF monitor,
runs in its own thread, falls back gracefully), `SEC_RUNTIME_TELEMETRY` (run
the server-side telemetry simulation), `SEC_RUNTIME_QUIET` (suppress console
output — recommended for embedded use), `SEC_RUNTIME_NETWORK_LOGGING`
(stream MEDIUM+ findings over UDP; requires a target set via
`security_runtime_set_network_target` first).

### C usage

```c
#include "api.h"

/* Engine init: scan once, watch own code in the background, stay quiet. */
initialize_security_runtime(SEC_RUNTIME_SCAN |
                            SEC_RUNTIME_BACKGROUND |
                            SEC_RUNTIME_QUIET);

/* Each frame / tick: */
if (security_runtime_verdict() != 0) {
    /* disconnect or flag the player */
}

/* Engine shutdown: */
shutdown_security_runtime();
```

### C++ / Unreal / Unity usage

```cpp
extern "C" {
#include "api.h"
}

void FMyGameMode::Init() {
    initialize_security_runtime(SEC_RUNTIME_SCAN |
                                SEC_RUNTIME_BACKGROUND |
                                SEC_RUNTIME_QUIET);
}
```

Link with `-lanticheat -pthread` (and `-lbpf` when the eBPF monitor was built
in). The library drives its own background threads, so the game loop is never
blocked.

## Usage

```bash
# Run a full scan (process + environment + debugger + one-shot memory check)
./anticheat

# Also verify file integrity against a baseline manifest
./anticheat -m manifest.txt

# Build a baseline manifest for critical files
./anticheat -i manifest.txt -p /path/game,/path/config.bin

# Verify files against a baseline manifest only
./anticheat -v manifest.txt

# Continuously monitor own code segment in a background thread
./anticheat -w -W 250 -t 60

# Simulate an in-process code patch to verify the monitor detects it
./anticheat -s -W 100

# Run the server-side telemetry simulation (speedhack + aimbot heuristics)
./anticheat -T

# Write findings to a log file
./anticheat -l scan.log

# Quiet mode: findings only, no banner or summary
./anticheat -q

# Help
./anticheat -h
```

### Options

| Option | Description |
|--------|-------------|
| `-w, --watch` | run the live code-segment monitor thread |
| `-W, --watch-interval MS` | monitor check interval in ms (default 250) |
| `-t, --watch-time SEC` | stop monitoring after SEC seconds (default: run until signal) |
| `-s, --selftest` | simulate an in-process code patch to verify detection (implies `--watch`) |
| `-T, --telemetry-sim` | simulate player telemetry and run the speedhack/aimbot heuristics |
| `-E, --ebpf` | load the eBPF cross-process memory monitor (root + libbpf required) |
| `-N, --network IP:PORT` | stream MEDIUM+ findings to a UDP dashboard at `IP:PORT` |
| `-K, --network-key KEY` | HMAC shared secret for the `-N` stream (falls back to `ANTICHEAT_NETWORK_KEY`; required) |
| `-i, --init FILE` | build a baseline manifest from `--paths` and exit |
| `-v, --verify FILE` | verify files against a baseline manifest and exit |
| `-m, --manifest FILE` | verify file integrity against a baseline during the scan |
| `-p, --paths a,b,c` | comma-separated files to record in a manifest |
| `-l, --log FILE` | append findings to a log file |
| `-q, --quiet` | findings only, no banner or summary |
| `-h, --help` | show help |

### Exit status

- `0` — clean (no MEDIUM-or-higher findings)
- `1` — at least one MEDIUM, HIGH, or CRITICAL finding

## Example

```bash
$ ./anticheat
Anti-Cheat Scanner v1.0
=======================
self pid: 748
[HIGH] process: known cheat/debugger tool process found (pid=741 name=cheatengine)
[INFO] debugger: no debugger attached to this process
[INFO] memguard: baseline hash generated for own code segment (regions=1 code@0x55b466b9e000 size=12288)
[INFO] memguard: own code segment memory integrity verified

--- Scan summary ---
  INFO: 3 | LOW: 0 | MEDIUM: 0 | HIGH: 1 | CRITICAL: 0
```

## Project layout

```
anticheat/
├── Makefile
└── src/
    ├── main.c          CLI entry point, argument parsing
    ├── report.c/h      severity-ranked findings, summary, log, verdict
    ├── scanner.c/h     process and environment scanning
    ├── debugger.c/h    debugger detection (TracerPid + ptrace)
    ├── integrity.c/h   SHA-256 file hashing and manifest verification
    ├── sha256.c/h      self-contained SHA-256 (FIPS 180-4)
├── memguard.c/h    background-thread live .text integrity monitor
├── envguard.c/h    VM / sandbox / hypervisor detection (CPUID + DMI)
├── telemetry.c/h   server-side telemetry validation (speedhack/aimbot)
├── ebpf_program.c/h hand-assembled eBPF tracepoint program builder
├── ebpf_monitor.c/h kernel-level cross-process memory access monitor
├── api.c/h         shared-library entry point for game-engine integration
└── network.c/h     non-blocking UDP alert reporting engine
```

`dashboard.py` (repository root) is a standalone Python TUI that listens for
these UDP alerts and renders a severity-colored administration view.

## Notes

- This is a host-side scanner for Linux. Kernel-level protections, protected
  processes, or anti-cheat that runs inside the game's own process are out of
  scope.
- The command-line keyword heuristic can produce false positives; review
  MEDIUM findings before acting on them.
- The memory monitor hashes its own process's code region; it detects
  in-memory patching of the anti-cheat binary but cannot detect a replaced
  binary on disk (use the file-integrity manifest for that).
- DMI/BIOS data under `/sys/class/dmi/id/` is only readable by root on most
  systems; the module falls back gracefully and relies on CPUID and
  `/proc/cpuinfo` when it is unavailable.
- A confirmed VM is reported as MEDIUM, not a hard block, so legitimate
  cloud-gaming and CI users are not flagged; the finding escalates to HIGH
  when a debugger is attached.
- The telemetry module is a **server-side simulation**: it validates the
  speedhack/aimbot heuristics against a synthetic anomaly dataset. In a real
  deployment the server would feed live `PlayerTick` packets into
  `telemetry_check_speed` / `telemetry_check_aimbot`.

## Kernel-level eBPF monitor

The optional `ebpf_monitor` module lifts a subset of the anti-cheat checks into
the kernel so that cross-process memory tampering is caught regardless of
whether the user-mode scanner is running, debugged, or root-kited.

It loads a tiny eBPF tracepoint program (built by `ebpf_program.c`) and attaches
it to the three syscall-entry tracepoints that can be abused to read or write
another process's address space:

- `sys_enter_ptrace` — `ptrace(PTRACE_PEEKDATA / PTRACE_POKEDATA / ...)`
- `sys_enter_process_vm_readv` — cross-process memory read
- `sys_enter_process_vm_writev` — cross-process memory write

Every such syscall issued by any process on the host is recorded into a ring
buffer and escalated to a CRITICAL kernel-level finding:

```
[CRITICAL] KERNEL: Unauthorized cross-process memory access blocked!
```

### Graceful fallback

The kernel monitor is privileged and environment-dependent. It disables itself
gracefully (an `[INFO]` finding, no error) whenever any of the following hold,
and the scanner relies entirely on its user-mode protections:

- the process is **not running as root** (eBPF load/attach requires `CAP_BPF`
  / `CAP_SYS_ADMIN`);
- the **host kernel has no eBPF support**, or the required tracepoints /
  `ringbuf` map cannot be created;
- **libbpf headers were unavailable at build time** — in this case
  `ebpf_program.c` / `ebpf_monitor.c` compile to no-op stubs (see the Makefile
  `HAVE_LIBBPF` detection) and report the same `[INFO]` fallback.

### Usage

```bash
# As root, load the kernel monitor and watch for 60 seconds
sudo ./anticheat -E -t 60

# Without root / libbpf you simply get the INFO fallback:
./anticheat -E
[INFO] ebpf: kernel-level cross-process memory monitor disabled (not running as root); falling back to user-mode protections
```

## Network reporting (live UDP alerts)

The `network` module lets threat detections be streamed off-host to a standalone
dashboard instead of (or in addition to) the local report. It is fully optional
and degrades to a no-op when not configured, so the rest of the scanner can call
it unconditionally.

- `initialize_network_client(const char *server_ip, int port, const char *key)`
  opens a single **non-blocking** `SOCK_DGRAM` UDP socket (`O_NONBLOCK` +
  `MSG_DONTWAIT`), resolving `server_ip` via `getaddrinfo(AF_UNSPEC)` so both
  IPv4 and IPv6 targets work. `key` (or, if `NULL`, the `ANTICHEAT_NETWORK_KEY`
  environment variable) is the HMAC shared secret; a missing key is a hard
  failure — unauthenticated reporting is never allowed.
- `network_send_alert(int severity, const char *module, const char *message)`
  serializes a compact JSON payload, signs it with HMAC-SHA256, and transmits
  it. It is **non-blocking** and serialized through a short-lived mutex, so
  calling it from a scan loop, a background thread, or a foreign game frame can
  never stall on network lag. If the kernel send buffer is full the datagram is
  dropped (returns 0) rather than blocking. A per-(module,message) rate limiter
  caps identical alerts to one per second so a burst of findings cannot flood
  the dashboard or spike egress.
- `network_shutdown()` closes the socket and disables reporting.

Every time `report_add()` records a **MEDIUM, HIGH, or CRITICAL** finding it
automatically calls `network_send_alert()`, so no caller has to remember to
broadcast.

### Payload schema

One UDP datagram per alert, newline-terminated compact JSON. Every datagram
carries an HMAC-SHA256 signature (`sig`):

```json
{"severity":3,"sev_label":"HIGH","module":"envguard","message":"...","ts":1690000000,"sig":"<64 hex chars>"}
```

The dashboard **must** verify `sig` before trusting a datagram; datagrams with a
missing or invalid signature are rejected. The signature is
`HMAC-SHA256(key, "severity|sev_label|module|message|ts")` over the raw,
unescaped field values joined by `|`, so JSON escaping never affects the
signature.

| Field | Type | Meaning |
|-------|------|---------|
| `severity` | int | `0`=INFO, `1`=LOW, `2`=MEDIUM, `3`=HIGH, `4`=CRITICAL |
| `sev_label` | str | human-readable severity |
| `module` | str | originating module (ebpf, memguard, envguard, ...) |
| `message` | str | finding detail (JSON-escaped) |
| `ts` | int | unix epoch seconds |
| `sig` | str | HMAC-SHA256 hex digest of `severity\|sev_label\|module\|message\|ts` |

### Engine integration

```c
security_runtime_set_network_target("127.0.0.1", 9999, getenv("ANTICHEAT_NETWORK_KEY"));
initialize_security_runtime(SEC_RUNTIME_SCAN |
                            SEC_RUNTIME_BACKGROUND |
                            SEC_RUNTIME_NETWORK_LOGGING);
```

Standalone CLI equivalent (the shared secret comes from `-K/--network-key` or
the `ANTICHEAT_NETWORK_KEY` environment variable):

```bash
ANTICHEAT_NETWORK_KEY=secret ./anticheat -N 127.0.0.1:9999
./anticheat -N 127.0.0.1:9999 -K secret
```

### Dashboard

`dashboard.py` (repository root) is a standalone Python 3 TUI that binds the UDP
port (IPv4 or IPv6), parses the JSON payloads, verifies each HMAC signature, and
renders a severity-colored live view (counts per severity + scrolling alert
log). It falls back to plain colored line output when not attached to a TTY.

When started **without** a key it runs in legacy mode and warns that datagrams
are not authenticated — only suitable for local, trusted testing. Always pass
`--network-key` (or set `ANTICHEAT_NETWORK_KEY`) so the dashboard rejects
forged or tampered alerts.

```bash
./dashboard.py --host 0.0.0.0 --port 9999 --network-key secret
```

Keys: `q` quit, `c` clear, `r` reset counters.

## Architecture breakdown

| Layer | Module(s) | What it does | Privilege / dependency |
|-------|-----------|--------------|------------------------|
| CLI / orchestration | `main.c` | argument parsing, mode selection, report lifecycle | user |
| Reporting | `report.c/h` | severity-ranked findings, summary, verdict, log | user |
| Process scan | `scanner.c/h` | enumerates `/proc`, flags cheat/debugger tools & writable-temp launches | user |
| Environment scan | `envguard.c/h` | `LD_PRELOAD` / `LD_AUDIT` injection vectors; VM / sandbox / hypervisor detection (CPUID + DMI + cgroup) | user (DMI needs root) |
| Debugger self-check | `debugger.c/h` | `TracerPid` + `ptrace(PTRACE_TRACEME)` probe | user |
| File integrity | `integrity.c/h` + `sha256.c/h` | SHA-256 baseline manifest, tamper detection | user |
| Live code monitor | `memguard.c/h` | background thread re-hashes own `.text` to detect in-RAM patching | user |
| Server-side telemetry | `telemetry.c/h` | speedhack / aimbot heuristics over `PlayerTick` streams (simulation) | user |
| Kernel monitor | `ebpf_monitor.c/h` + `ebpf_program.c/h` | eBPF tracepoint program on `ptrace` / `process_vm_readv` / `process_vm_writev`; ring-buffer CRITICAL events | **root + eBPF + libbpf**, else INFO fallback |
| Network reporting | `network.c/h` | non-blocking UDP client; broadcasts MEDIUM+ findings as JSON to a dashboard | user (UDP egress) |
