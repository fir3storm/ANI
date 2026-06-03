"""Attack modules for AI Pentest Tool."""

from .base import BaseAttack, AttackResult
from .prompt_injection import PromptInjectionAttack
from .jailbreak import JailbreakAttack
from .system_prompt import SystemPromptAttack
from .data_exfiltration import DataExfiltrationAttack
from .encoding_bypass import EncodingBypassAttack
from .advanced import AdvancedAttack

__all__ = [
    "BaseAttack",
    "AttackResult",
    "PromptInjectionAttack",
    "JailbreakAttack",
    "SystemPromptAttack",
    "DataExfiltrationAttack",
    "EncodingBypassAttack",
    "AdvancedAttack",
]
