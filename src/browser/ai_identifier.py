"""AI model identification for AI Pentest Tool."""

import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from playwright.async_api import Page

from ..utils.logger import get_logger

logger = get_logger()


@dataclass
class AIModel:
    """Represents an identified AI model."""
    name: str
    provider: str
    confidence: float
    evidence: List[str]
    version: Optional[str] = None


class AIIdentifier:
    """Identifies the backend AI model powering a chat interface."""
    
    # AI model signatures
    AI_SIGNATURES = {
        "gpt": {
            "provider": "OpenAI",
            "phrases": [
                "as an ai",
                "openai",
                "chatgpt",
                "gpt-",
                "language model",
                "i'm an ai",
                "i am an ai assistant",
            ],
            "network_patterns": [
                "api.openai.com",
                "chat.openai.com",
                "openai.azure.com",
            ],
            "js_patterns": [
                "openai",
                "gpt-4",
                "gpt-3.5",
                "chatgpt",
            ],
        },
        "claude": {
            "provider": "Anthropic",
            "phrases": [
                "anthropic",
                "claude",
                "constitutional ai",
                "i'm claude",
                "i am claude",
                "made by anthropic",
            ],
            "network_patterns": [
                "api.anthropic.com",
                "claude.ai",
            ],
            "js_patterns": [
                "anthropic",
                "claude",
            ],
        },
        "gemini": {
            "provider": "Google",
            "phrases": [
                "google",
                "gemini",
                "bard",
                "i'm gemini",
                "google ai",
                "deepmind",
            ],
            "network_patterns": [
                "generativelanguage.googleapis.com",
                "bard.google.com",
                "gemini.google.com",
            ],
            "js_patterns": [
                "gemini",
                "bard",
                "google.ai",
            ],
        },
        "llama": {
            "provider": "Meta",
            "phrases": [
                "llama",
                "meta ai",
                "i'm llama",
                "meta's language model",
            ],
            "network_patterns": [
                "llama.meta.com",
                "meta.ai",
            ],
            "js_patterns": [
                "llama",
                "meta.ai",
            ],
        },
        "mistral": {
            "provider": "Mistral AI",
            "phrases": [
                "mistral",
                "i'm mistral",
                "mistral ai",
            ],
            "network_patterns": [
                "api.mistral.ai",
                "mistral.ai",
            ],
            "js_patterns": [
                "mistral",
            ],
        },
        "cohere": {
            "provider": "Cohere",
            "phrases": [
                "cohere",
                "command",
                "i'm command",
            ],
            "network_patterns": [
                "api.cohere.ai",
                "cohere.ai",
            ],
            "js_patterns": [
                "cohere",
                "command-r",
            ],
        },
    }
    
    # Generic fallback responses that indicate a chatbot
    GENERIC_INDICATORS = [
        "how can i help",
        "how may i help",
        "what can i do for you",
        "i'm here to assist",
        "i am a virtual assistant",
        "chatbot",
        "ai assistant",
    ]
    
    def __init__(self, page: Page):
        self.page = page
        self._network_requests: List[dict] = []
        
        # Set up network monitoring
        self.page.on("request", self._capture_request)
    
    def _capture_request(self, request) -> None:
        """Capture network requests for analysis."""
        self._network_requests.append({
            "url": request.url,
            "method": request.method,
        })
    
    async def identify(self, probe_message: str = None) -> AIModel:
        """
        Identify the AI model powering the chat interface.
        
        Args:
            probe_message: Optional message to send for identification
        
        Returns:
            AIModel with identification results
        """
        logger.info("Identifying AI model...")
        
        evidence = []
        scores: Dict[str, float] = {model: 0.0 for model in self.AI_SIGNATURES}
        
        # Method 1: Analyze probe response
        if probe_message:
            response = await self._send_probe(probe_message)
            if response:
                response_score = self._analyze_response(response)
                for model, score in response_score.items():
                    scores[model] += score
                    if score > 0:
                        evidence.append(f"Response pattern match for {model}")
        
        # Method 2: Check network requests
        network_score = self._analyze_network_requests()
        for model, score in network_score.items():
            scores[model] += score * 2  # Higher weight for network evidence
            if score > 0:
                evidence.append(f"Network request pattern match for {model}")
        
        # Method 3: Scan page JavaScript
        js_score = await self._analyze_page_scripts()
        for model, score in js_score.items():
            scores[model] += score * 1.5  # Medium weight for JS evidence
            if score > 0:
                evidence.append(f"JavaScript pattern match for {model}")
        
        # Method 4: Check page metadata
        metadata_score = await self._analyze_page_metadata()
        for model, score in metadata_score.items():
            scores[model] += score
            if score > 0:
                evidence.append(f"Page metadata match for {model}")
        
        # Find best match
        best_model = max(scores, key=scores.get)
        best_score = scores[best_model]
        
        # Normalize confidence to 0-1
        confidence = min(best_score / 10.0, 1.0)
        
        # Determine version if applicable
        version = await self._detect_version(best_model)
        
        if confidence < 0.2:
            logger.warning("Could not confidently identify AI model")
            return AIModel(
                name="Unknown",
                provider="Unknown",
                confidence=0.0,
                evidence=["Insufficient evidence for identification"],
            )
        
        logger.info(f"AI Model identified: {best_model} (confidence: {confidence:.2%})")
        
        return AIModel(
            name=best_model,
            provider=self.AI_SIGNATURES[best_model]["provider"],
            confidence=confidence,
            evidence=evidence,
            version=version,
        )
    
    async def _send_probe(self, message: str) -> Optional[str]:
        """Send a probe message and get response."""
        try:
            # This would integrate with chat_detector
            # For now, return None to indicate manual integration needed
            return None
        except Exception as e:
            logger.debug(f"Probe failed: {e}")
            return None
    
    def _analyze_response(self, response: str) -> Dict[str, float]:
        """Analyze response text for AI model signatures."""
        scores = {}
        response_lower = response.lower()
        
        for model, signatures in self.AI_SIGNATURES.items():
            score = 0.0
            for phrase in signatures["phrases"]:
                if phrase in response_lower:
                    score += 2.0
            scores[model] = score
        
        return scores
    
    def _analyze_network_requests(self) -> Dict[str, float]:
        """Analyze captured network requests for API endpoints."""
        scores = {}
        
        for model, signatures in self.AI_SIGNATURES.items():
            score = 0.0
            for request in self._network_requests:
                url = request["url"].lower()
                for pattern in signatures["network_patterns"]:
                    if pattern in url:
                        score += 5.0
            scores[model] = score
        
        return scores
    
    async def _analyze_page_scripts(self) -> Dict[str, float]:
        """Analyze page JavaScript for AI-related code."""
        scores = {}
        
        try:
            # Get all script content
            scripts = await self.page.evaluate("""
                () => {
                    const scripts = document.querySelectorAll('script');
                    return Array.from(scripts).map(s => s.textContent).join('\\n');
                }
            """)
            
            scripts_lower = scripts.lower()
            
            for model, signatures in self.AI_SIGNATURES.items():
                score = 0.0
                for pattern in signatures["js_patterns"]:
                    if pattern in scripts_lower:
                        score += 3.0
                scores[model] = score
                
        except Exception as e:
            logger.debug(f"Script analysis failed: {e}")
            scores = {model: 0.0 for model in self.AI_SIGNATURES}
        
        return scores
    
    async def _analyze_page_metadata(self) -> Dict[str, float]:
        """Analyze page metadata for AI-related information."""
        scores = {}
        
        try:
            # Check title
            title = await self.page.title()
            title_lower = title.lower()
            
            # Check meta tags
            meta_description = await self.page.evaluate("""
                () => {
                    const meta = document.querySelector('meta[name="description"]');
                    return meta ? meta.getAttribute('content') : '';
                }
            """)
            meta_lower = (meta_description or "").lower()
            
            combined_text = f"{title_lower} {meta_lower}"
            
            for model, signatures in self.AI_SIGNATURES.items():
                score = 0.0
                for phrase in signatures["phrases"]:
                    if phrase in combined_text:
                        score += 2.0
                scores[model] = score
                
        except Exception as e:
            logger.debug(f"Metadata analysis failed: {e}")
            scores = {model: 0.0 for model in self.AI_SIGNATURES}
        
        return scores
    
    async def _detect_version(self, model: str) -> Optional[str]:
        """Attempt to detect specific model version."""
        try:
            page_content = await self.page.content()
            page_lower = page_content.lower()
            
            # Version patterns
            version_patterns = {
                "gpt": [r"gpt-4", r"gpt-3\.5", r"gpt-4-turbo", r"gpt-4o"],
                "claude": [r"claude-3", r"claude-2", r"claude-instant"],
                "gemini": [r"gemini-pro", r"gemini-ultra", r"gemini-nano"],
                "llama": [r"llama-2", r"llama-3"],
                "mistral": [r"mistral-large", r"mistral-medium", r"mistral-small"],
            }
            
            if model in version_patterns:
                for pattern in version_patterns[model]:
                    match = re.search(pattern, page_lower)
                    if match:
                        return match.group(0).upper()
            
        except Exception:
            pass
        
        return None
    
    def get_network_requests(self) -> List[dict]:
        """Get all captured network requests."""
        return self._network_requests.copy()
    
    def clear_network_requests(self) -> None:
        """Clear captured network requests."""
        self._network_requests.clear()
