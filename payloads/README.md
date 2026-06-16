# Payloads Directory

The JSON files in this directory are reserved for future externalization of attack payloads.

Currently, all attack payloads are hardcoded inside the Python modules under `src/attacks/*.py` (for example `PromptInjectionAttack.get_payloads()`). The scanner reads payloads from those classes, not from these JSON files.

When payload externalization is implemented, the loader will read these JSON files instead. Until then, edits to these files have no effect on the scanner.
