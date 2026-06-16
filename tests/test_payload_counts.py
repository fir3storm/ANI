from unittest.mock import MagicMock

from src.attacks.advanced import AdvancedAttack
from src.attacks.data_exfiltration import DataExfiltrationAttack
from src.attacks.encoding_bypass import EncodingBypassAttack
from src.attacks.gradual_escalation import GradualEscalationAttack
from src.attacks.jailbreak import JailbreakAttack
from src.attacks.persona_building import PersonaBuildingAttack
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attacks.system_prompt import SystemPromptAttack


ATTACK_CLASSES = [
    PromptInjectionAttack,
    JailbreakAttack,
    SystemPromptAttack,
    DataExfiltrationAttack,
    EncodingBypassAttack,
    AdvancedAttack,
    GradualEscalationAttack,
    PersonaBuildingAttack,
]


def test_all_attack_classes_have_payloads():
    for cls in ATTACK_CLASSES:
        instance = cls(MagicMock(), MagicMock(), "http://example.com")
        assert len(instance.get_payloads()) > 0, f"{cls.__name__} returned no payloads"
