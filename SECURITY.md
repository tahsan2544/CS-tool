# Security Policy

## Supported versions

Security fixes are applied to the latest commit on the default branch (`Default-Branch` / `main`).

## Reporting a vulnerability

If you find a vulnerability **in CS Tools** (for example path traversal in an export writer, command injection in a wrapper, or unsafe deserialization):

1. **Do not** open a public GitHub issue.
2. Report privately via GitHub Security Advisories on [tahsan2544/CS-tool](https://github.com/tahsan2544/CS-tool/security/advisories), or contact the maintainer through GitHub.
3. Include: affected file/command, reproduction steps, impact, and suggested fix if you have one.

You should receive an acknowledgement within a few days. Fixes are coordinated before public disclosure.

## What CS Tools does against targets

- Analysis tools send ordinary HTTP(S)/DNS/TLS probes to the URL **you** supply.
- `loadstorm` generates load — only use it on systems you own or have explicit permission to test.
- The project does not include exploit payloads, credential-stuffing lists, or evasion modules.

## Secrets in this repository

- Never commit API keys, PATs, tokens, or `.env` files.
- GitHub Actions workflows use only the default `GITHUB_TOKEN` scope needed for CI.
