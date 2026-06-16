"""Tests for externalized payload loader."""

from src.attacks.payload_loader import load_payloads
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attacks.jailbreak import JailbreakAttack
from src.attacks.system_prompt import SystemPromptAttack
from src.attacks.data_exfiltration import DataExfiltrationAttack
from src.attacks.encoding_bypass import EncodingBypassAttack
from src.attacks.advanced import AdvancedAttack


REQUIRED_KEYS = ["id", "name", "payload", "description", "severity"]

ATTACK_CLASSES = [
    PromptInjectionAttack,
    JailbreakAttack,
    SystemPromptAttack,
    DataExfiltrationAttack,
    EncodingBypassAttack,
    AdvancedAttack,
]


def _make_attack(cls):
    return cls(None, None, "http://example.com")


def test_each_category_loads_payloads_with_required_keys():
    for cls in ATTACK_CLASSES:
        attack = _make_attack(cls)
        loaded = load_payloads(attack.attack_id)
        assert loaded, f"No payloads loaded for {attack.attack_id}"
        for entry in loaded:
            missing = [k for k in REQUIRED_KEYS if k not in entry]
            assert not missing, f"{attack.attack_id} entry missing keys {missing}: {entry}"


def test_get_payloads_returns_loaded_list():
    for cls in ATTACK_CLASSES:
        attack = _make_attack(cls)
        assert len(attack.get_payloads()) > 0


def test_unknown_category_returns_empty_list():
    assert load_payloads("definitely_not_a_real_category") == []
