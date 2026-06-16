# Changelog

All notable changes to ANI (Adversarial Neural Inspector) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-16

First public release of ANI under its current name (formerly "AI Siege"). This release bundles the initial rename plus a major feature drop with security hardening, four new attack families, a pluggable LLM brain, and CI/CD-friendly reporting.

### Added

#### Security hardening
- Jinja2 autoescape enabled in HTML report generator; `Content-Security-Policy` meta tag added to the report template (closes HTML-injection XSS in generated reports).
- Sidebar `addResult()` rebuilt with `createElement` + `textContent`; `innerHTML` interpolation of AI / DeepSeek output removed (closes sidebar XSS in privileged extension context).
- DeepSeek API key persistence in `browser.storage.local` via a new Save button; key is read from a module variable and the DOM input is cleared after each read.
- Fernet encryption for `auth_profiles/*.json` and `sessions/*.json`; key from `ANI_ENCRYPTION_KEY` env var or auto-generated at `~/.ani/encryption.key` (0o600).
- New `src/utils/crypto.py` with `get_fernet`, `encrypt_bytes`/`decrypt_bytes`, and `encrypt_json`/`decrypt_json` helpers.
- `BrowserController` now redacts `Cookie`, `Authorization`, and `Set-Cookie` headers from the in-memory network request log.
- New `--cookie-file` flag and `ANI_AUTH_COOKIE` env var; `--cookie` is deprecated with a one-time warning when used.

#### Attack coverage
- Four new attack families, bringing the total to 10:
  - `gradual_escalation` (multi-turn, 4 turns): benign start escalating to a system-prompt leak.
  - `persona_building` (multi-turn, 3 turns): primes a "truth-telling game" persona.
  - `rag_injection` (OWASP LLM03): indirect prompt injection via documents and retrieval.
  - `tool_use_abuse` (OWASP LLM05/07/08): function call, MCP, agent delegation, browser tool abuse.
- `BaseAttack.execute_conversation()` for multi-turn orchestration with per-turn result aggregation.
- `BaseAttack.get_indicators()` hook for per-payload custom indicator overrides.
- `BaseAttack.get_conversation()` default returns `[]`; multi-turn subclasses override it.
- `src/attacks/payload_loader.py` with `load_payloads(category)` JSON loader, schema validation, and inline fallback.

#### Externalized payloads
- All 6 original attack categories now load payloads from `payloads/<category>.json` at runtime; existing inline Python dicts remain as a fallback when the JSON file is missing.
- `payloads/manifest.json` declares the schema (`id`, `name`, `payload`, `description`, `severity` are required).
- Researchers can add or tune payloads by editing JSON without touching Python.

#### Pluggable LLM brain
- New `src/utils/llm_brain.py` with three adapters behind a `Brain` interface:
  - `RulesOnlyBrain`: fully offline, no network calls, used as the CI default.
  - `DeepSeekBrain`: calls the DeepSeek API with the sidebar's prompt engineering ported to Python.
  - `OpenAICompatibleBrain`: works with any OpenAI-compatible `/v1/chat/completions` endpoint (OpenAI, Together, Groq, OpenRouter, Ollama, LM Studio).
- Factory `get_brain()` selects the backend from `ANI_LLM_BACKEND` (or `--llm-backend`); default is `openai_compatible` pointed at DeepSeek.
- `Config.llm_backend` and `Config.llm_model` added.

#### Adaptive CLI mode
- New `--adaptive` and `--rounds N` options on the `scan` command mirror the sidebar's adaptive loop.
- Per-round `AttackResult`s are emitted with `metadata.adaptive = True`; loop breaks on the first SUCCESS verdict or after `rounds` rounds.
- Works offline via `RulesOnlyBrain` for CI scans.

#### Reporting and CI/CD
- SARIF 2.1.0 output via `--format sarif`; one `result` per vulnerable finding with `ANI-<CATEGORY>-<TEST_ID>` rule IDs.
- SARIF level mapping: `error` for CRITICAL/HIGH, `warning` for MEDIUM, `note` for LOW/INFO.
- SARIF `properties` block carries `regression` and `fixed` metadata when produced with `--baseline`.
- New `--baseline <file>` flag for regression/fixed/unchanged diffing against a prior JSON run.
- HTML report renders `REGRESSION` and `FIXED` badges on each vulnerability card when baseline diffs are present.
- New `--indicators <file>` flag for per-payload custom indicator JSON overrides; supports both exact `test_id` matches and category-wide fallbacks.
- New `_load_indicators_file` and `_apply_baseline_diff` helpers in `cli.py`.

#### Detection and engine
- `ChatDetector` now uses Playwright's `is_visible()` instead of the `offsetHeight > 0` proxy.
- Iframe-aware selector scan via `page.frames`; Shadow DOM pass for open shadow roots.
- `wait_for_response` replaced with a `MutationObserver`-based capture and 500ms text-stability detection (2 consecutive identical 250ms ticks).
- Captured responses are stripped of the user's payload prefix before being returned.

#### Project infrastructure
- New `tests/` directory with 7 test files (46 tests, all passing). See the `Tests` section below.
- `MANIFEST.in` ensures the Jinja2 HTML template ships with `pip install .`.
- `.env.example` documents every environment variable ANI reads.
- `start.bat` option 0: first-time setup (creates venv, installs `requirements.txt`, runs `playwright install chromium`).
- README rewritten with the full new feature surface and an embedded social card image from `assets/`.
- `auth_handler.py` no longer logs plaintext passwords; success logs were removed.
- `Config.load()` no longer silently ignores its `config_path` argument.

### Changed

- All attack files now expose their inline payload list as a module-level `INLINE_PAYLOADS` constant, used as a fallback when the JSON file is missing.
- `list-tests` command now computes payload counts live from each attack class (5/5/5/5/6/4/1/1/5/5) instead of using stale hardcoded numbers.
- `cli.scan` parameter renamed from `format` to `report_format` to stop shadowing the Python builtin.
- Magic log levels (`10` / `20`) replaced with `logging.DEBUG` / `logging.INFO` constants.
- Auth dispatch extracted into `_build_auth_call()` helper to reduce the long if/elif chain.
- Risk score now normalizes against the whole scan (`sum_weight / (total_tests * 10) * 100`) instead of `len(findings) * 10`, so a single critical no longer scores 100% on its own.

### Fixed

- `VulnCategory.JAILbreak` typo (lowercase 'b') in `cwe_mapping` would have raised `AttributeError` at construction; renamed to `JAILBREAK`.
- `Severity` enum duplicated between `attacks/base.py` and `detection/vulnerability.py`; detection now re-imports the canonical version.
- `Controller.type_text()` no longer silently ignores its `delay` parameter (the underlying `page.fill()` issue is documented; the name was preserved for compatibility).
- `_take_screenshot()` no longer re-imports `datetime` inside the method.
- `ani_identifier._send_probe()` no-op removed; callers no longer rely on a dead branch.

### Removed

- Unused `ai_identifier._send_probe` method.
- Orphaned `ani-addon/content.js` and `ani-addon/background.js`; sidebar now communicates directly via `tabs.executeScript`.
- Unused `GOALS` constant in `ani-addon/deepseek.js` (replaced by `CATEGORY_GOALS` in `sidebar.js`).

### Security

- No published CVEs for ANI. The two XSS sinks in the sidebar and the HTML report were found during the security audit that preceded this release; both have fixes included and regression tests to prevent reintroduction.

### Tests

- `tests/test_attacks_base.py` (3): substring matching, case-insensitive matching, no-match path.
- `tests/test_patterns.py` (5): URL/email/API-key extraction and group dispatch.
- `tests/test_vulnerability.py` (5): classifier construction (catches the prior JAILbreak typo), risk score zero/single-critical/cap-at-100, Severity re-export identity.
- `tests/test_report_xss.py` (2): Jinja2 autoescape regression and the `ReportGenerator.env.autoescape` invariant.
- `tests/test_payload_counts.py` (1): every concrete attack class returns at least one payload.
- `tests/test_payloads_external.py` (3): externalized JSON loads with the required keys, returns the loaded list, gracefully returns `[]` for unknown categories.
- `tests/test_multiturn.py` (4): `gradual_escalation` 4-turn chain, `persona_building` 3-turn chain, vulnerability aggregation across turns, empty-aggregation edge case.
- `tests/test_new_attacks.py` (4): `rag_injection` and `tool_use_abuse` payload sets, RAG indicator match, CRITICAL severity for `root:x:` content.
- `tests/test_llm_brain.py` (5): `RulesOnlyBrain` payload generation, success analysis, factory wiring for default / `rules` / `deepseek`.
- `tests/test_adaptive_cli.py` (4): adaptive loop calls the brain once per round, breaks on success, respects max rounds, marks results vulnerable on success.
- `tests/test_sarif_baseline_indicators.py` (10): SARIF schema and level mapping, regression metadata passthrough, baseline regression/fixed/missing-file annotation, custom-indicators file loading and invalid-file tolerance, `BaseAttack.get_indicators` override and static fallback, HTML regression badge render.

Run with `python -m pytest`.

[Unreleased]: https://github.com/fir3storm/ANI/compare/da2608a...HEAD
[1.0.0]: https://github.com/fir3storm/ANI/commit/da2608a
