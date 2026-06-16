"""Base attack class for ANI."""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..browser.controller import BrowserController
from ..browser.chat_detector import ChatDetector, ChatElement
from ..utils.logger import get_logger

logger = get_logger()


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class AttackResult:
    """Result of an attack test."""
    test_id: str
    test_name: str
    category: str
    payload: str
    response: str
    vulnerable: bool
    severity: Severity
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    screenshot_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "category": self.category,
            "payload": self.payload,
            "response": self.response,
            "vulnerable": self.vulnerable,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "screenshot_path": self.screenshot_path,
        }


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    found: bool
    severity: Severity
    indicators: List[str]
    description: str
    remediation: Optional[str] = None


class BaseAttack(ABC):
    """
    Abstract base class for all attack implementations.

    Subclasses must implement:
    - execute(): Run the attack scenario
    - analyze_response(): Analyze response for vulnerabilities
    - get_payloads(): Return list of test payloads
    """

    def __init__(
        self,
        browser: BrowserController,
        chat_detector: ChatDetector,
        target_url: str,
    ):
        self.browser = browser
        self.chat_detector = chat_detector
        self.target_url = target_url
        self.results: List[AttackResult] = []
        self._chat_element: Optional[ChatElement] = None
        self.custom_indicators: List[Dict[str, Any]] = []

    @property
    @abstractmethod
    def attack_name(self) -> str:
        """Name of the attack category."""
        pass

    @property
    @abstractmethod
    def attack_id(self) -> str:
        """Unique identifier for the attack category."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of the attack."""
        pass

    @abstractmethod
    def get_payloads(self) -> List[Dict[str, Any]]:
        """
        Return list of attack payloads.

        Each payload should be a dict with:
        - id: Unique payload ID
        - name: Payload name
        - payload: The actual attack payload string
        - description: What this payload tests
        """
        pass

    @abstractmethod
    def analyze_response(self, payload: Dict[str, Any], response: str) -> Vulnerability:
        """
        Analyze response for vulnerabilities.

        Args:
            payload: The payload that was sent
            response: AI response text

        Returns:
            Vulnerability with analysis results
        """
        pass

    def get_indicators(
        self,
        payload: Dict[str, Any],
        static_indicators: Optional[List[str]] = None,
        static_critical_indicators: Optional[List[str]] = None,
    ) -> tuple[List[str], List[str]]:
        """Return (regular_indicators, critical_indicators) for a payload.

        Looks up ``self.custom_indicators`` (a list of override dicts loaded
        from the --indicators file) for an entry whose ``test_id`` matches
        the payload, or for a category default (entry with no test_id).
        Returns the static lists unchanged when no override applies.
        """
        static_indicators = list(static_indicators or [])
        static_critical_indicators = list(static_critical_indicators or [])
        if not self.custom_indicators:
            return static_indicators, static_critical_indicators

        test_id = payload.get("id")
        category_match: Optional[Dict[str, Any]] = None
        exact_match: Optional[Dict[str, Any]] = None
        for entry in self.custom_indicators:
            if not isinstance(entry, dict):
                continue
            if entry.get("test_id") == test_id:
                exact_match = entry
                break
            if "test_id" not in entry and entry.get("category") in (None, self.attack_id):
                category_match = entry

        chosen = exact_match or category_match
        if not chosen:
            return static_indicators, static_critical_indicators

        reg = chosen.get("indicators", static_indicators)
        crit = chosen.get("critical_indicators", static_critical_indicators)
        return list(reg), list(crit)

    def get_conversation(self) -> List[Dict[str, str]]:
        """Return the multi-turn conversation script for this attack.

        Format: list of {"role": "user"|"assistant"|"system", "content": "..."}
        Subclasses that do not implement multi-turn conversations should leave
        the default empty list in place; ``execute_conversation`` will then
        fall back to ``execute``.
        """
        return []

    async def execute(self, chat_element: ChatElement) -> List[AttackResult]:
        """
        Execute all payloads in this attack category.

        Args:
            chat_element: Detected chat interface element

        Returns:
            List of attack results
        """
        self._chat_element = chat_element
        payloads = self.get_payloads()

        logger.info(f"Executing {self.attack_name} ({len(payloads)} payloads)")

        for payload in payloads:
            try:
                result = await self._execute_single(payload)
                self.results.append(result)

                if result.vulnerable:
                    logger.warning(
                        f"[VULNERABLE] {payload['name']}: {result.severity.value}"
                    )
                else:
                    logger.info(f"[SECURE] {payload['name']}")

            except Exception as e:
                logger.error(f"Error executing {payload['name']}: {e}")
                self.results.append(AttackResult(
                    test_id=payload["id"],
                    test_name=payload["name"],
                    category=self.attack_id,
                    payload=payload["payload"],
                    response=f"Error: {str(e)}",
                    vulnerable=False,
                    severity=Severity.INFO,
                    evidence=[f"Test failed with error: {str(e)}"],
                ))

        return self.results

    async def execute_conversation(self, chat_element: ChatElement) -> List[AttackResult]:
        """Execute a multi-turn conversation, if one is defined.

        If ``get_conversation()`` returns an empty list this method simply
        delegates to ``execute()`` so single-turn attacks continue to work
        unchanged. Otherwise it walks the conversation, sending each user turn
        in sequence, capturing the AI response, analyzing it, and building a
        list of ``AttackResult`` entries - one per turn - plus a summary
        ``AttackResult`` that aggregates the per-turn outcomes.
        """
        conversation = self.get_conversation()
        if not conversation:
            return await self.execute(chat_element)

        self._chat_element = chat_element
        user_turns = [t for t in conversation if t.get("role") == "user"]
        if not user_turns:
            logger.warning(
                f"{self.attack_name}: conversation defined but contains no user turns"
            )
            return await self.execute(chat_element)

        logger.info(
            f"Executing {self.attack_name} multi-turn ({len(user_turns)} user turns)"
        )

        turn_results: List[AttackResult] = []
        for turn_number, turn in enumerate(user_turns, start=1):
            user_content = turn.get("content", "")
            try:
                await self.chat_detector.send_message(chat_element, user_content)
                response = await self.chat_detector.wait_for_response(timeout=30000)
                if not response:
                    response = "[No response received]"
            except Exception as exc:
                logger.error(f"Error sending turn {turn_number}: {exc}")
                response = f"Error: {exc}"

            synthetic_payload = {
                "id": f"{self.attack_id}-T{turn_number}",
                "name": f"Turn {turn_number}",
                "payload": user_content,
                "description": f"Multi-turn conversation turn {turn_number}",
            }
            vulnerability = self.analyze_response(synthetic_payload, response)

            turn_result = AttackResult(
                test_id=f"{self.attack_id}-T{turn_number}",
                test_name=f"{self.attack_name} - Turn {turn_number}",
                category=self.attack_id,
                payload=user_content,
                response=response,
                vulnerable=vulnerability.found,
                severity=vulnerability.severity,
                evidence=vulnerability.indicators,
                metadata={
                    "turn_number": turn_number,
                    "multi_turn": True,
                    "description": synthetic_payload["description"],
                    "remediation": vulnerability.remediation,
                },
            )
            turn_results.append(turn_result)

            if vulnerability.found:
                logger.warning(
                    f"[VULNERABLE] turn {turn_number}: {vulnerability.severity.value}"
                )

        aggregated_vulnerable, aggregated_severity = aggregate_turn_results(turn_results)

        summary = AttackResult(
            test_id=self.attack_id,
            test_name=f"{self.attack_name} (multi-turn)",
            category=self.attack_id,
            payload="\n---\n".join(t.payload for t in turn_results),
            response="\n---\n".join(t.response for t in turn_results),
            vulnerable=aggregated_vulnerable,
            severity=aggregated_severity,
            evidence=[ev for t in turn_results for ev in t.evidence],
            metadata={
                "multi_turn": True,
                "num_turns": len(turn_results),
                "turn_results": [t.to_dict() for t in turn_results],
            },
        )

        self.results.extend(turn_results)
        self.results.append(summary)
        return self.results

    async def _execute_single(self, payload: Dict[str, Any]) -> AttackResult:
        """
        Execute a single attack payload.

        Args:
            payload: Payload to execute

        Returns:
            Attack result
        """
        logger.debug(f"Executing payload: {payload['name']}")

        await self.chat_detector.send_message(
            self._chat_element,
            payload["payload"],
        )

        response = await self.chat_detector.wait_for_response(timeout=30000)

        if not response:
            response = "[No response received]"

        vulnerability = self.analyze_response(payload, response)

        screenshot_path = None
        if vulnerability.found:
            screenshot_path = await self._take_screenshot(payload["id"])

        return AttackResult(
            test_id=payload["id"],
            test_name=payload["name"],
            category=self.attack_id,
            payload=payload["payload"],
            response=response,
            vulnerable=vulnerability.found,
            severity=vulnerability.severity,
            evidence=vulnerability.indicators,
            screenshot_path=screenshot_path,
            metadata={
                "description": payload.get("description", ""),
                "remediation": vulnerability.remediation,
            },
        )

    async def _take_screenshot(self, payload_id: str) -> Optional[str]:
        """Take screenshot of vulnerable response."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vuln_{payload_id}_{timestamp}.png"
            path = await self.browser.take_screenshot(filename)
            return str(path)
        except Exception as e:
            logger.debug(f"Screenshot failed: {e}")
            return None

    def get_results(self) -> List[AttackResult]:
        """Get all attack results."""
        return self.results.copy()

    def get_vulnerabilities(self) -> List[AttackResult]:
        """Get only vulnerable results."""
        return [r for r in self.results if r.vulnerable]

    def clear_results(self) -> None:
        """Clear stored results."""
        self.results.clear()

    @staticmethod
    def check_indicators(
        response: str,
        indicators: List[str],
        response_lower: bool = True,
    ) -> List[str]:
        """
        Check response for vulnerability indicators.

        Args:
            response: Response text to check
            indicators: List of indicator strings/patterns
            response_lower: Whether to lowercase response for matching

        Returns:
            List of found indicators
        """
        found = []
        text = response.lower() if response_lower else response

        for indicator in indicators:
            if indicator.lower() in text:
                found.append(indicator)

        return found

    @staticmethod
    def check_patterns(
        response: str,
        patterns: List[str],
    ) -> List[str]:
        """
        Check response for regex patterns.

        Args:
            response: Response text to check
            patterns: List of regex patterns

        Returns:
            List of matched patterns
        """
        import re
        found = []

        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                found.append(pattern)

        return found


def aggregate_turn_results(turn_results: List[AttackResult]) -> Tuple[bool, Severity]:
    """Aggregate per-turn results into a single vulnerable flag and severity.

    A multi-turn chain is considered vulnerable if ANY turn was vulnerable.
    The reported severity is the maximum across all turns.
    """
    if not turn_results:
        return False, Severity.INFO

    any_vulnerable = any(r.vulnerable for r in turn_results)
    max_severity = max(
        (r.severity for r in turn_results),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
        default=Severity.INFO,
    )
    return any_vulnerable, max_severity
