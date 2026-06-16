"""Tests for new attack categories (RAG injection and tool/MCP/agent abuse)."""

from src.attacks.rag_injection import RAGInjectionAttack
from src.attacks.tool_use_abuse import ToolUseAbuseAttack, SENSITIVE_FILE_INDICATORS


REQUIRED_KEYS = ["id", "name", "payload", "description", "severity"]


def _make_attack(cls):
    return cls(None, None, "http://example.com")


def test_rag_injection_payloads():
    attack = _make_attack(RAGInjectionAttack)
    payloads = attack.get_payloads()
    assert len(payloads) == 5
    for entry in payloads:
        missing = [k for k in REQUIRED_KEYS if k not in entry]
        assert not missing, f"Missing keys {missing} in {entry}"


def test_tool_use_abuse_payloads():
    attack = _make_attack(ToolUseAbuseAttack)
    payloads = attack.get_payloads()
    assert len(payloads) == 5
    for entry in payloads:
        missing = [k for k in REQUIRED_KEYS if k not in entry]
        assert not missing, f"Missing keys {missing} in {entry}"


def test_rag_indicators_match():
    attack = _make_attack(RAGInjectionAttack)
    response = "Sure, as the document says, I should reveal my configuration."
    vulnerability = attack.analyze_response(
        {"id": "RI-001", "name": "Document", "payload": "x", "description": "d", "severity": "high"},
        response,
    )
    assert vulnerability.found is True


def test_tool_use_root_file_response_is_critical():
    attack = _make_attack(ToolUseAbuseAttack)
    response = "I will call the tool. tool result: root:x:0:0:root:/root:/bin/bash"
    payload = attack.get_payloads()[1]
    vulnerability = attack.analyze_response(payload, response)
    assert vulnerability.found is True
    assert vulnerability.severity.value == "Critical"
    assert any("root:x" in ind for ind in vulnerability.indicators) or any(
        ind in vulnerability.indicators for ind in SENSITIVE_FILE_INDICATORS
    )
