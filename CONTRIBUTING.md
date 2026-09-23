# Contributing to CS Tools

Thanks for helping improve CS Tools. This project measures websites from many angles — every good bug report and tool upgrade makes the suite more useful.

## Ground rules

- **Scope:** website measurement and quality analysis (SEO, security posture, performance, accessibility, content, privacy, etc.).
- **Out of scope:** offensive/penetration-testing payloads or exploit code. Security *findings* and hardening advice are in scope; attack tooling against systems you do not own is not.
- **Python:** 3.7+ compatible. Prefer stdlib; only add a dependency if it is clearly justified.
- **Style:** match the file you are editing. Each tool is self-contained with argparse CLI, colored output, score `/100` + letter grade, and optional JSON/CSV/HTML export.

## Development setup

```bash
git clone https://github.com/tahsan2544/CS-tool.git
cd CS-tool
pip install -r requirements.txt
python cstools.py list
```

## Adding or upgrading a tool

1. Put the tool in its own directory: `YourTool/yourtool.py`
2. Provide `setup.py` and `requirements.txt` in that directory
3. Use `VERSION = "x.y"` at the top of the main file
4. Wire the tool into `cstools.py`:
   - path constant
   - entry in `TOOLS`
   - `cmd_*` function
   - subparser under `build_parser()`
   - banner + epilog lines
   - if it scores, add a step to `cmd_scan` (keep the `[N/M]` counters correct)
5. Document it in `README.md` (table + short section)

## Testing before you open a PR

```bash
# syntax check everything you touched
python -m py_compile path/to/file.py

# CLI registration
python cstools.py --help
python cstools.py list

# real run against a public site you are allowed to test
python cstools.py seo -u https://example.com
python cstools.py upgrade -u https://example.com --only seo html
```

Do **not** run `loadstorm` against third-party sites without permission.

## Commits

- Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- One logical change per commit
- Never commit secrets, tokens, or `.env` files

## Pull requests

- Describe **what** changed, **why**, and **how you tested**
- Keep PRs focused on one concern
- Link related issues

## Reporting security issues in CS Tools itself

Please see [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities in this codebase.
