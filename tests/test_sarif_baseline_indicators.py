import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.attacks.base import AttackResult, Severity
from src.cli import _apply_baseline_diff, _load_indicators_file
from src.reporting.generator import ReportGenerator


def _make_result(test_id, name, vulnerable, severity=Severity.HIGH, category="prompt_injection"):
    return AttackResult(
        test_id=test_id,
        test_name=name,
        category=category,
        payload="test payload",
        response="test response",
        vulnerable=vulnerable,
        severity=severity if vulnerable else Severity.INFO,
    )


def test_sarif_output_is_valid():
    gen = ReportGenerator()
    results = [
        _make_result("PI-001", "Direct Injection", True, Severity.CRITICAL),
        _make_result("PI-002", "Delimiter Injection", True, Severity.HIGH),
        _make_result("PI-003", "Secure", False),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.sarif"
        gen.generate(
            results=results,
            target_url="https://example.com",
            output_format="sarif",
            output_path=out,
        )
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "ANI"
        assert len(run["results"]) == 2
        levels = {r["level"] for r in run["results"]}
        assert levels == {"error"}


def test_sarif_includes_regression_metadata():
    gen = ReportGenerator()
    r = _make_result("PI-001", "Direct Injection", True, Severity.CRITICAL)
    r.metadata["regression"] = True
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.sarif"
        gen.generate(
            results=[r],
            target_url="https://example.com",
            output_format="sarif",
            output_path=out,
        )
        data = json.loads(out.read_text())
        sarif_result = data["runs"][0]["results"][0]
        assert sarif_result["properties"]["regression"] is True


def test_baseline_marks_regression():
    current = [
        _make_result("PI-001", "Direct Injection", True, Severity.CRITICAL),
        _make_result("PI-002", "Delimiter", False),
    ]
    baseline = {
        "results": [
            {"test_id": "PI-001", "vulnerable": False},
            {"test_id": "PI-002", "vulnerable": False},
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(baseline, f)
        baseline_path = Path(f.name)
    try:
        _apply_baseline_diff(current, baseline_path)
    finally:
        baseline_path.unlink()
    assert current[0].metadata.get("regression") is True
    assert current[1].metadata.get("unchanged") is True


def test_baseline_marks_fixed():
    current = [
        _make_result("PI-001", "Direct Injection", False),
    ]
    baseline = {"results": [{"test_id": "PI-001", "vulnerable": True}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(baseline, f)
        baseline_path = Path(f.name)
    try:
        _apply_baseline_diff(current, baseline_path)
    finally:
        baseline_path.unlink()
    assert current[0].metadata.get("fixed") is True


def test_baseline_handles_missing_file_gracefully():
    current = [_make_result("PI-001", "X", True, Severity.HIGH)]
    _apply_baseline_diff(current, Path("/nonexistent/baseline.json"))
    assert current[0].metadata == {}


def test_indicators_file_loaded():
    payload = {"prompt_injection": [{"test_id": "PI-001", "indicators": ["zorgon"]}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        path = f.name
    try:
        data = _load_indicators_file(path)
    finally:
        Path(path).unlink()
    assert "prompt_injection" in data
    assert data["prompt_injection"][0]["indicators"] == ["zorgon"]


def test_indicators_file_invalid_returns_empty():
    data = _load_indicators_file("/nonexistent/file.json")
    assert data == {}


def test_get_indicators_override():
    from src.attacks.prompt_injection import PromptInjectionAttack

    attack = PromptInjectionAttack(MagicMock(), MagicMock(), "https://x")
    attack.custom_indicators = [{"test_id": "PI-001", "indicators": ["zorgon"], "critical_indicators": []}]

    payload = {"id": "PI-001", "name": "X", "payload": "x"}
    reg, crit = attack.get_indicators(payload, ["old_a"], ["old_crit"])
    assert reg == ["zorgon"]
    assert crit == []


def test_get_indicators_falls_back_to_static():
    from src.attacks.prompt_injection import PromptInjectionAttack

    attack = PromptInjectionAttack(MagicMock(), MagicMock(), "https://x")
    attack.custom_indicators = []

    payload = {"id": "PI-001", "name": "X", "payload": "x"}
    reg, crit = attack.get_indicators(payload, ["a", "b"], ["c"])
    assert reg == ["a", "b"]
    assert crit == ["c"]


def test_html_report_with_regression_metadata_renders():
    gen = ReportGenerator()
    r = _make_result("PI-001", "X", True, Severity.CRITICAL)
    r.metadata["regression"] = True
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.html"
        gen.generate(
            results=[r],
            target_url="https://example.com",
            output_format="html",
            output_path=out,
        )
        text = out.read_text(encoding="utf-8")
        assert "regression" in text.lower()
