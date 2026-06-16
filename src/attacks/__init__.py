"""Attack modules for ANI."""

from .base import BaseAttack, AttackResult
from .prompt_injection import PromptInjectionAttack
from .jailbreak import JailbreakAttack
from .system_prompt import SystemPromptAttack
from .data_exfiltration import DataExfiltrationAttack
from .encoding_bypass import EncodingBypassAttack
from .advanced import AdvancedAttack
from .gradual_escalation import GradualEscalationAttack
from .persona_building import PersonaBuildingAttack
from .rag_injection import RAGInjectionAttack
from .tool_use_abuse import ToolUseAbuseAttack

__all__ = [
    "BaseAttack",
    "AttackResult",
    "PromptInjectionAttack",
    "JailbreakAttack",
    "SystemPromptAttack",
    "DataExfiltrationAttack",
    "EncodingBypassAttack",
    "AdvancedAttack",
    "GradualEscalationAttack",
    "PersonaBuildingAttack",
    "RAGInjectionAttack",
    "ToolUseAbuseAttack",
]
