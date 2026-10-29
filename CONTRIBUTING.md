# Contributing to Triksha

Thanks for your interest in contributing. This document covers how to get set up, what to work on, and how to submit changes.

---

## Getting Started

1. Fork the repository
2. Clone your fork and follow the [local dev setup](docs/getting-started.md#option-2-local-development)
3. Create a feature branch: `git checkout -b feat/your-feature-name`
4. Make your changes
5. Open a pull request against `main`

---

## What to Work On

Good first contributions:
- **New attack techniques** — add to `api/templates.py` and `get_technique_description()`
- **MCP detector improvements** — add patterns to existing detectors in `api/mcp_detectors/`
- **Bug fixes** — check open issues
- **Documentation** — corrections, clarifications, examples

Larger contributions (discuss in an issue first):
- New scan types
- New LLM provider integrations
- Frontend features
- Database schema changes

---

## Adding an Attack Technique

1. Add the technique name to `get_template_categories()` in `api/templates.py`
2. Add a description to `get_technique_description()`
3. Add at least 3 prompt templates to the appropriate section
4. Add the technique to the template map in `get_random_template()`
5. Document it in `docs/attack-techniques.md`

Keep technique templates use-case-neutral in code. The attack engine parameterizes them with the user's context at scan time — do not hardcode domain-specific content in templates.

---

## Code Style

- Python: follow existing style (no strict linter enforced, but match the surrounding code)
- Async: use `asyncio.to_thread()` for any blocking I/O inside async functions
- Pydantic: use V2 style (`@field_validator`, `model_config = ConfigDict(...)`, `json_schema_extra`)
- No new dependencies without discussion — keep the install footprint lean

---

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include a clear description of what changed and why
- If you're adding a new technique, include an example of a prompt it generates
- Do not commit `.env` files, API keys, `venv/`, or database files

---

## Reporting Issues

Include:
- OS and Python version
- The exact error message (not the full log — just the relevant line)
- Steps to reproduce

Security vulnerabilities: please disclose privately before opening a public issue.

---

## License

By contributing, you agree that your contributions will be licensed under the same [Elastic License 2.0](LICENSE) as the project.
