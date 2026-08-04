# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue, pull request,
or discussion for a vulnerability.

Preferred: use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
via the **Security** tab of this repository.

Please include:

- a description of the issue and its impact,
- the affected version, commit or file,
- clear reproduction steps or a minimal proof of concept,
- any suggested remediation.

**Do not include** real API keys, live scan results, customer data, personal data,
or details about third-party systems you tested.

## Response targets

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment | 10 business days |
| Fix or mitigation plan | 30 days for high or critical severity |

We will keep you updated on progress and credit you in the release notes unless you
prefer to stay anonymous.

## Disclosure

We follow coordinated disclosure. Please give us a reasonable window to ship a fix
before publishing details. We aim for 90 days and will work with you if more time is
genuinely needed.

## Scope

In scope:

- bypasses of the authorization gate or target confirmation,
- bypasses of target blocking (localhost, private, reserved ranges, cloud metadata),
- SSRF via redirect handling or user-supplied URLs,
- command or argument injection in external tool execution,
- TLS verification bypasses,
- leakage of secrets, tokens, credentials, personal data or local paths into console
  output, logs, reports or exception messages,
- dependency vulnerabilities with a practical exploit path in this project.

Out of scope:

- findings that require an already-compromised host or a malicious local operator,
- results produced by running the tool against systems you were not authorized to test,
- vulnerabilities in third-party tools (`nmap`, `nuclei`, `wpscan`, `amass`, and
  similar) — report those upstream,
- missing hardening that has no demonstrable impact.

## Using this project safely

This is an offensive-security tool. Only use it against systems you own or for which
you hold explicit written authorization. Keep API keys in environment variables rather
than in the CLI or a config file, keep TLS verification enabled, and prefer the default
passive mode unless active testing is covered by your rules of engagement.

## Supported versions

Security fixes are applied to the latest release on the default branch. Older versions
are not maintained.
