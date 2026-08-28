# Contributing to the Anti-Cheat Scanner

Thanks for your interest in improving this project! This document explains how
to set up a development environment, the style we follow, and how to get your
changes merged.

## Development setup

The project is a small, dependency-light C codebase. You need a C11 compiler
(`cc`/`gcc`/`clang`) and `make`. The optional kernel monitor needs `libbpf`
and root to actually load eBPF programs, but the build degrades gracefully
without it.

```bash
# Clone and build the standalone binary + shared library
git clone <your-fork>
cd anticheat
make

# Run the full test suite (unit + integration + live ptrace tests)
make test

# Optional: memory-safety build under AddressSanitizer + UBSan
make test-san
```

The build is verified in two configurations in CI:

- **With libbpf** (`pkg-config --exists libbpf`): the eBPF monitor is compiled in.
- **Without libbpf** (`PKG_CONFIG_LIBDIR=/nonexistent make`): the eBPF module
  becomes a graceful no-op fallback, and everything else still builds and tests.

## Code style

Match the existing code. In short:

- **Language**: C11 (`-std=c11`).
- **Indentation**: 4 spaces, no tabs.
- **Braces**: K&R style — opening brace on the same line as the statement/function.
- **Naming**: `snake_case` for functions and variables, `SCREAMING_SNAKE_CASE`
  for macros and constants.
- **Includes**: `#define _GNU_SOURCE` first, then local headers (`"foo.h"`),
  then a blank line, then system headers (`<foo.h>`).
- **Warnings**: code must build cleanly with `-Wall -Wextra`. Treat new warnings
  as errors to fix.
- **Modules**: source and header live together; headers are included by
  basename and resolved via the per-subfolder `-I` flags in the `Makefile`
  (`src/core`, `src/detection`, `src/net`, `src/ebpf`).
- **No dead code**: do not leave commented-out blocks or debug `printf`s in.

## Testing requirements

- `make test` must pass (26 tests across unit, integration, and live ptrace
  checks, plus the Python dashboard/smoke tests).
- If you add a detection module or change behavior, add or update a test under
  `tests/`.
- Run `make test-san` for any change that touches memory ownership, parsing, or
  networking — it must report no AddressSanitizer/UBSan findings.
- Keep both the libbpf and no-libbpf builds green.

## Pull request process

1. Fork the repository and create a topic branch
   (`git checkout -b fix/short-description`).
2. Make your change; keep commits focused and message lines under ~72 columns.
3. Run `make test` (and `make test-san` for relevant changes) and confirm green.
4. Update `README.md` / `CHANGELOG.md` if your change affects users or behavior.
5. Open the PR using the pull-request template; fill in the checklist.
6. Respond to review feedback; do not force-push over a reviewed branch without
   coordinating with the maintainer.

For large or architectural changes, please open an issue first so we can agree
on the approach before you invest the effort.

## Security disclosure policy

**Do not open public issues for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for private reporting instructions and the
coordinated-disclosure timeline. Publicly disclosing a flaw before a fix is
available puts users at risk and may delay a remedy.
