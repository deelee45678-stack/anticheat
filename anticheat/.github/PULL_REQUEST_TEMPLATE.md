## Description of changes
Briefly describe what this PR changes and why. Link any related issues
(e.g., "Closes #123").

## Type of change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation only
- [ ] Build / CI / test changes

## Testing performed
Describe how you verified the change:
- [ ] `make test` passes (both libbpf and no-libbpf builds)
- [ ] `make test-san` passes (if memory/parsing/networking changed)
- [ ] Added or updated tests under `tests/`
- [ ] Manually ran the scanner / dashboard and observed expected output

## Checklist
- [ ] My code follows the existing style (4-space indent, K&R braces, C11)
- [ ] I have added/updated tests as appropriate
- [ ] `make test` is green in both libbpf and no-libbpf configurations
- [ ] Documentation (README / CHANGELOG / SECURITY) updated if needed
- [ ] No secrets, credentials, or sensitive paths are committed
- [ ] I have read the CONTRIBUTING.md guidelines
