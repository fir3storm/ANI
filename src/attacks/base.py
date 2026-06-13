"""Base attack class for ANI."""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
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
                
                # Log result
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
    
    async def _execute_single(self, payload: Dict[str, Any]) -> AttackResult:
        """
        Execute a single attack payload.
        
        Args:
            payload: Payload to execute
        
        Returns:
            Attack result
        """
        logger.debug(f"Executing payload: {payload['name']}")
        
        # Send payload
        await self.chat_detector.send_message(
            self._chat_element,
            payload["payload"],
        )
        
        # Wait for response
        response = await self.chat_detector.wait_for_response(timeout=30000)
        
        if not response:
            response = "[No response received]"
        
        # Analyze response
        vulnerability = self.analyze_response(payload, response)
        
        # Take screenshot if vulnerable
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
            from datetime import datetime
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
