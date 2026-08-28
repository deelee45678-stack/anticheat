# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-08-28

### Added
- Initial public release
- Process scanning for known cheat/debugger tools
- Library injection vector detection (LD_PRELOAD, etc.)
- Debugger self-check via TracerPid and ptrace
- File integrity with SHA-256 baseline manifests
- Live code-segment integrity monitor (memguard)
- VM/sandbox detection via CPUID, DMI, and cgroups
- Server-side telemetry validation (speedhack/aimbot)
- Optional eBPF kernel monitor (graceful fallback)
- Network reporting with HMAC authentication
- Shared library API for game engine integration
- Comprehensive test suite
- AddressSanitizer/UBSan CI hardening
- QEMU (TCG) and Bochs CPUID detection
- Source tree split into `core/`, `detection/`, `net/`, and `ebpf/` subfolders

[1.0.0]: https://github.com/deelee45678-stack/anticheat/releases/tag/v1.0.0
