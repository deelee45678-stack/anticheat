name: Bug report
about: Report a defect in the anti-cheat scanner
title: "[BUG] "
labels: bug
assignees: ''

---

## Describe the bug
A clear and concise description of what the problem is.

## To reproduce
Steps to reproduce the behavior:
1. Build with '...'
2. Run '...'
3. See error

## Expected behavior
A clear and concise description of what you expected to happen.

## Environment
- OS / distribution:
- Kernel version (`uname -r`):
- Compiler and version (`cc --version`):
- libbpf present? (yes / no / `pkg-config --exists libbpf`)
- Built with: `make` / `make test-san` / other flags

## Logs / output
Paste the relevant output. If the scanner crashed, include any sanitizer or
backtrace output. Redact anything sensitive (hostnames, usernames, paths).

```
<paste output here>
```

## Additional context
Add any other context about the problem here (e.g., a specific game/engine,
a VM/hardware detail, or a screenshot).
