"""Tests for multi-turn attack support."""

from datetime import datetime
from src.attacks.base import (
    AttackResult,
    Severity,
    aggregate_turn_results,
)
from src.attacks.gradual_escalation import GradualEscalationAttack
from src.attacks.persona_building import PersonaBuildingAttack


def _make_attack(cls):
    return cls(None, None, "http://example.com")


def test_gradual_escalation_has_4_turns():
    attack = _make_attack(GradualEscalationAttack)
    conversation = attack.get_conversation()
    user_turns = [t for t in conversation if t.get("role") == "user"]
    assert len(user_turns) == 4
    for turn in user_turns:
        assert turn.get("content")
    assert len(attack.get_payloads()) == 1


def test_persona_building_has_3_turns():
    attack = _make_attack(PersonaBuildingAttack)
    conversation = attack.get_conversation()
    user_turns = [t for t in conversation if t.get("role") == "user"]
    assert len(user_turns) == 3
    for turn in user_turns:
        assert turn.get("content")
    assert len(attack.get_payloads()) == 1


def test_multiturn_results_aggregate_vulnerability():
    def make_result(turn: int, vulnerable: bool, severity: Severity) -> AttackResult:
        return AttackResult(
            test_id=f"gradual_escalation-T{turn}",
            test_name=f"Turn {turn}",
            category="gradual_escalation",
            payload="payload",
            response="response",
            vulnerable=vulnerable,
            severity=severity,
            evidence=[],
            timestamp=datetime.now(),
            metadata={"turn_number": turn},
        )

    turn_results = [
        make_result(1, False, Severity.INFO),
        make_result(2, True, Severity.HIGH),
        make_result(3, False, Severity.INFO),
    ]

    vulnerable, severity = aggregate_turn_results(turn_results)
    assert vulnerable is True
    assert severity == Severity.HIGH

    all_secure = [make_result(i, False, Severity.INFO) for i in range(1, 4)]
    vulnerable, severity = aggregate_turn_results(all_secure)
    assert vulnerable is False
    assert severity == Severity.INFO

    critical_chain = [
        make_result(1, False, Severity.INFO),
        make_result(2, True, Severity.HIGH),
        make_result(3, True, Severity.CRITICAL),
    ]
    vulnerable, severity = aggregate_turn_results(critical_chain)
    assert vulnerable is True
    assert severity == Severity.CRITICAL


def test_aggregate_turn_results_empty():
    vulnerable, severity = aggregate_turn_results([])
    assert vulnerable is False
    assert severity == Severity.INFO
