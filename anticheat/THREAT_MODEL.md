# Threat Model

This document describes what the anti-cheat scanner is designed to defend
against, what is explicitly out of scope, the trust boundaries of each layer,
and how the pieces should be deployed. It is grounded in what the code in this
repository actually does — it is **not** a guarantee of cheat-proofing.

For test coverage of these modules see [README.md](README.md#testing).

## What this defends against

The scanner is a **host-side, user-mode** tool for Linux that raises the bar
against the following, on a system where the anti-cheat itself is running with
at least as much privilege as the software it is protecting:

- **Cheat / debugger tool processes** — `scanner.c` matches known cheat and
  debugger process names (e.g. cheatengine) among the processes it can see.
- **Library injection** (`LD_PRELOAD`, etc.) — process-environment inspection
  flags injection-style environment variables on the protected process.
- **Live debugging / tracing** — `debugger.c` detects an attached debugger via
  `/proc/self/status` `TracerPid` and `ptrace(PTRACE_TRACEME)`.
- **Tampered game files** — `integrity.c` builds and verifies a SHA-256 baseline
  manifest of critical files; a changed or missing file is reported.
- **In-memory code patching of the anti-cheat itself** — `memguard.c` hashes the
  scanner's own executable code regions and re-checks them from a background
  thread, reporting a MEDIUM/CRITICAL finding on modification.
- **VM / sandbox-based reverse engineering** — `envguard.c` inspects the CPUID
  hypervisor signature (VMware, Hyper-V, KVM, Xen, Parallels, VirtualBox, bhyve,
  QEMU/TCG, Bochs), DMI/BIOS vendor strings, `/proc/cpuinfo`, and container
  indicators. A confirmed VM is reported as MEDIUM and escalates to HIGH when a
  debugger is also attached.
- **Speedhack / aimbot patterns** — `telemetry.c` validates movement velocity
  and view-angle deltas (a snap above ~360°/s followed by a locked aim with no
  natural decay) from server-side `PlayerTick` data; this is a **server-side
  validation** path, not a client self-report.

## What is explicitly out of scope

Pulled directly from the project's documented scope (`README.md` "Notes") and
stated plainly:

- **Kernel-level cheats** (e.g. rootkits, malicious kernel modules, hooked
  syscalls) are not detected by the user-mode scanner.
- **Protected-process / anti-cheat-in-kernel designs** — there is no kernel
  component that owns or protects other processes by default; the optional eBPF
  monitor is a passive observer, not an enforcement boundary.
- **Anti-cheat running inside the game's own process** — the scanner is a
  separate process (and is also buildable as a shared library, but the trust
  model still assumes it is not collocated with an attacker inside the same
  compromised process).
- **Non-Linux platforms** — all detection logic targets Linux (`/proc`,
  `ptrace`, CPUID, eBPF). Other operating systems are unsupported.

The command-line keyword heuristic can produce **false positives**; MEDIUM
findings should be reviewed before any enforcement action, as the README notes.

## Trust boundaries, stated plainly

### User-mode checks (scanner, envguard, memguard, debugger, integrity)

These run in ordinary user (or root) space on the host. **A root-level attacker
on the host can defeat all of them**: they can unload or hide processes, forge
`/proc` contents, bypass `ptrace` detection, patch or `mprotect` the scanner's
own memory before `memguard` snapshots it, or simply replace the scanner binary
on disk (the integrity manifest checks *game* files, not the scanner itself).

Conclusion: these checks **raise the bar** for casual and user-level cheats.
They are not a hard guarantee against a privileged adversary. Treat their output
as evidence, not proof.

### eBPF kernel monitor

`ebpf_monitor.c` can load a cross-process memory-access tracepoint program, but
only when **root + libbpf + a compatible kernel** are all present. When any of
those are missing it **degrades to an INFO-level no-op fallback** (see
`README.md` "Kernel-level eBPF monitor"). Therefore it **cannot be assumed
present** in any given deployment, and the rest of the system must function
without it. It is an observation aid, not a guarantee that kernel-level
tampering is caught.

### Server-side telemetry (the resistant layer)

`telemetry.c` is, by design, **server-side**: it evaluates physically-plausible
movement and aim from `PlayerTick` packets the server already receives. Because
the validation happens on infrastructure the attacker does not control, it
remains meaningful even when the client is fully compromised or rooted —
the attacker can lie in their own self-report, but they cannot make impossible
motion look physically plausible without also defeating the game's own state
model. This is the layer that is actually resistant to a rooted client.

## Network reporting trust model

The UDP alert stream (`network.c`, documented in `README.md` "Network
reporting") is authenticated but only as trustworthy as its shared secret:

- Each datagram is signed with **HMAC-SHA256** over
  `severity|sev_label|module|message|ts` using a shared key. A missing key is a
  hard failure — unauthenticated reporting is never allowed.
- **Key compromise is fatal**: an attacker who learns the HMAC key can **forge**
  alerts (filling the dashboard with noise) or **suppress** real ones (by never
  sending, or by spoofing the client's silence). The whole stream's integrity
  rests on the key's confidentiality and distribution.
- **Replay protection** (enforced by the dashboard when a key is set) mitigates
  *replay*, not *theft*: a freshness window of **30 seconds** rejects stale
  datagrams, and a **60-second replay cache** rejects exact-duplicate signatures
  within that window. These stop a captured datagram from being replayed later,
  but they do nothing against an attacker who already holds the key.

Key hygiene matters: the shared secret should come from the
`ANTICHEAT_NETWORK_KEY` environment variable, not a command-line flag (which is
visible via `ps` and shell history).

## Recommended deployment posture

- **Treat server-side telemetry validation as the primary signal.** It is the
  only layer that holds up against a fully compromised or rooted client.
- **Use client-side findings (scanner / envguard / memguard / debugger /
  integrity) to inform, not to solely justify, enforcement.** They are excellent
  for triage, sandboxing decisions, and raising confidence, but a sufficiently
  privileged attacker can defeat each one.
- **Assume the eBPF monitor may be absent.** Do not build enforcement logic that
  depends on it being loaded.
- **Protect the HMAC key as a production secret.** Rotate it on suspected
  compromise; understand that while the key is safe, the alert channel is
  trustworthy, and once it leaks the channel is not.
- **Expect and tolerate false positives** from the keyword and VM heuristics;
  pair them with human review or corroborating server-side signals before
  punitive action.
