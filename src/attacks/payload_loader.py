"""Externalized payload loader for ANI."""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..utils.logger import get_logger

logger = get_logger()


_MANIFEST_PATH = Path(__file__).resolve().parent.parent.parent / "payloads" / "manifest.json"
_PAYLOADS_DIR = Path(__file__).resolve().parent.parent.parent / "payloads"


def _load_schema_required_keys() -> List[str]:
    try:
        with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        return list(manifest.get("schema", {}).get("required", []))
    except Exception as exc:
        logger.warning(f"Could not load manifest.json for schema: {exc}")
        return ["id", "name", "payload", "description", "severity"]


def load_payloads(category: str) -> List[Dict[str, Any]]:
    """Load payloads for a category from JSON, with inline fallback.

    The function first attempts to read ``payloads/<category>.json`` at the
    project root. Each entry is validated against the schema defined in
    ``manifest.json``. Entries missing required keys are dropped with a
    warning. If the JSON file is missing or unreadable, an empty list is
    returned. Callers are expected to wire in their own ``INLINE_PAYLOADS``
    fallback at the call site if desired.
    """
    required = _load_schema_required_keys()
    json_path = _PAYLOADS_DIR / f"{category}.json"

    if not json_path.exists():
        logger.debug(f"No JSON file at {json_path}; returning empty list")
        return []

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logger.warning(f"Failed to read payloads JSON {json_path}: {exc}")
        return []

    if not isinstance(data, list):
        logger.warning(f"Payloads file {json_path} is not a JSON list")
        return []

    validated: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            logger.warning(f"Skipping non-dict entry in {json_path}: {entry!r}")
            continue
        missing = [k for k in required if k not in entry]
        if missing:
            logger.warning(
                f"Skipping payload with missing keys {missing} in {json_path}: "
                f"{entry.get('id', '<no-id>')}"
            )
            continue
        validated.append(entry)

    return validated


def load_payloads_with_fallback(
    category: str,
    inline_payloads: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Load payloads from JSON, falling back to ``inline_payloads`` if empty."""
    loaded = load_payloads(category)
    if loaded:
        return loaded
    if inline_payloads is not None:
        return list(inline_payloads)
    return []
