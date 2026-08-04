## Purpose

What problem does this solve?

## Files changed

- `path/to/file` — what changed and why

## Architecture impact

Does this alter the pipeline, plugin lifecycle, event bus, cache or schema?

## Backward compatibility

Any breaking change to configuration, report schema, CLI flags or plugin APIs?
If yes, describe the migration.

## Tests

- [ ] `pytest tests -q` passes locally
- [ ] New behaviour is covered by tests
- [ ] No test performs live reconnaissance against a third-party host

## Safety and privacy checklist

- [ ] The authorization gate cannot be bypassed by this change
- [ ] New network activity is passive, or gated behind `--active`
- [ ] Private and reserved address ranges remain blocked
- [ ] TLS verification stays on unless the explicit opt-in flag is used
- [ ] No secrets, tokens, personal data or local filesystem paths are written to
      reports, logs or error messages
- [ ] Redaction still applies to every new output field

## Performance impact

Request volume, concurrency and runtime effects.

## Potential risks

What could regress, and how would we notice?
