# Contributing to WebOSINT Pro

Thanks for your interest in improving WebOSINT Pro. This is a security tool, so
contributions are held to a high bar around safety, privacy and low-noise behaviour.

## Ground rules

1. **Authorized use only.** Never contribute code, tests, fixtures or examples that
   target systems without permission. Use `example.com` in all documentation and tests.
2. **No live network in tests.** The test suite must pass offline. Mock or stub any
   HTTP, DNS or subprocess interaction.
3. **No secrets.** Never commit API keys, tokens, `.env` files, scan results, logs,
   reports or anything containing real hostnames or personal data.
4. **Passive by default.** Any new capability that sends intrusive traffic must be
   gated behind `--active` and declared with `ACTIVE = True` on the module.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install
```

## Before you open a pull request

```bash
ruff check .        # lint
ruff format .       # format
pytest              # tests
```

All three must pass. CI runs the same commands.

## Coding standards

- Python 3.10+, typed function signatures, `from __future__ import annotations`.
- Dataclasses for structured data; avoid new heavyweight dependencies.
- Line length 100, formatted with `ruff format`.
- UTF-8 source files. Use plain ASCII in console strings where practical.
- Keep CLI, safety policy, target validation, networking, module execution, reporting
  and storage concerns separate.

## Security requirements for new code

| Requirement | How |
|---|---|
| Network requests | Use `self._request()` / `SafeSession`. Never call `requests` directly. |
| TLS | Never pass `verify=False`. The policy decides. |
| External tools | Use `SafeRunner`. Argument lists only, allowlisted binaries, no shell. |
| Target input | Validate through `SafetyController` before use. |
| Errors | Report via `self.redactor.exception(exc)`. Never print a traceback or a path. |
| Findings | Emit with `self.report(...)` so they are deduplicated and scored. |
| Logging | Use the module logger. Never `print()` from inside a module. |

## Adding a module

1. Create `modules/<name>_module.py` with a class extending `BaseModule`.
2. Set `ACTIVE = True` if it sends intrusive traffic; leave it `False` for passive work.
3. Implement `run()` and return a dict of findings; call `self.report(...)` for
   normalized findings with a severity, confidence and evidence summary.
4. Register it in `core/config.py` (`ALL_MODULES`, and `ACTIVE_MODULES` if intrusive)
   and add a one-line description to `MODULE_HELP` in `core/cli.py`.
5. Add tests that exercise the module offline.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`.

## Reporting bugs

Open an issue with the version, command used (with the target redacted), expected and
actual behaviour. For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead — do
not open a public issue.
