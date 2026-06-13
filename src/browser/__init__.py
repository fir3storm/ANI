"""Browser automation module for ANI."""

from .controller import BrowserController
from .chat_detector import ChatDetector
from .ai_identifier import AIIdentifier
from .auth_handler import AuthHandler

__all__ = ["BrowserController", "ChatDetector", "AIIdentifier", "AuthHandler"]
