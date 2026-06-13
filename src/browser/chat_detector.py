"""Chat interface detection for ANI."""

import re
from typing import Optional, List, Tuple
from dataclasses import dataclass
from playwright.async_api import Page, ElementHandle

from ..utils.logger import get_logger

logger = get_logger()


@dataclass
class ChatElement:
    """Represents a detected chat interface element."""
    input_element: ElementHandle
    send_button: Optional[ElementHandle]
    input_type: str  # "textarea", "contenteditable", "input"
    confidence: float
    selector: str


class ChatDetector:
    """Detects and identifies chat input interfaces on web pages."""
    
    # Common selectors for chat inputs
    INPUT_SELECTORS = [
        # Textareas - placeholder based
        'textarea[placeholder*="message" i]',
        'textarea[placeholder*="chat" i]',
        'textarea[placeholder*="ask" i]',
        'textarea[placeholder*="type" i]',
        'textarea[placeholder*="enter" i]',
        'textarea[placeholder*="prompt" i]',
        'textarea[placeholder*="search" i]',
        'textarea[placeholder*="send" i]',
        'textarea[placeholder*="write" i]',
        'textarea[placeholder*="input" i]',
        'textarea[placeholder*="question" i]',
        'textarea[placeholder*="threat" i]',
        'textarea[placeholder*="security" i]',
        
        # Textareas - class/id based
        'textarea[class*="chat" i]',
        'textarea[class*="message" i]',
        'textarea[class*="input" i]',
        'textarea[class*="composer" i]',
        'textarea[class*="prompt" i]',
        'textarea[id*="chat" i]',
        'textarea[id*="message" i]',
        'textarea[id*="input" i]',
        'textarea[id*="composer" i]',
        
        # Contenteditable divs
        '[contenteditable="true"]',
        'div[role="textbox"]',
        'div[role="searchbox"]',
        'div[class*="chat-input" i]',
        'div[class*="message-input" i]',
        'div[class*="editor" i]',
        'div[class*="composer" i]',
        'div[class*="prompt-input" i]',
        
        # Input fields
        'input[type="text"][placeholder*="message" i]',
        'input[type="text"][placeholder*="chat" i]',
        'input[type="text"][placeholder*="ask" i]',
        'input[type="text"][placeholder*="search" i]',
        'input[type="text"][class*="chat" i]',
        'input[type="text"][class*="search" i]',
        
        # Fallback - any textarea on the page
        'textarea',
    ]
    
    # Common selectors for send buttons
    BUTTON_SELECTORS = [
        'button[aria-label*="send" i]',
        'button[aria-label*="submit" i]',
        'button[class*="send" i]',
        'button[class*="submit" i]',
        'button[type="submit"]',
        'button:has-text("Send")',
        'button:has-text("Submit")',
        'button:has-text("Ask")',
        'button:has-text("Chat")',
        'input[type="submit"]',
        '[role="button"][aria-label*="send" i]',
    ]
    
    # Keywords indicating chat interface
    CHAT_KEYWORDS = [
        "message", "chat", "ask", "type", "enter", "send",
        "conversation", "talk", "assistant", "ai", "bot",
    ]
    
    def __init__(self, page: Page):
        self.page = page
    
    async def detect(self, debug: bool = False) -> Optional[ChatElement]:
        """
        Detect chat interface on the current page.
        
        Args:
            debug: If True, dump all detected elements for debugging
        
        Returns:
            ChatElement if found, None otherwise
        """
        logger.info("Scanning page for chat interface...")
        
        # Wait a bit for dynamic content to load
        await self.page.wait_for_timeout(2000)
        
        # Debug mode: dump all textareas and contenteditable elements
        if debug:
            logger.info("[DEBUG MODE] Dumping all potential chat elements...")
            debug_selectors = ['textarea', '[contenteditable="true"]', 'div[role="textbox"]', 'input[type="text"]']
            for sel in debug_selectors:
                try:
                    elements = await self.page.query_selector_all(sel)
                    for i, el in enumerate(elements):
                        placeholder = await el.get_attribute('placeholder') or ''
                        class_attr = await el.get_attribute('class') or ''
                        id_attr = await el.get_attribute('id') or ''
                        visible = await self._is_visible(el)
                        logger.info(f"  [{sel}] #{i}: placeholder='{placeholder[:50]}' class='{class_attr[:30]}' id='{id_attr}' visible={visible}")
                except Exception as e:
                    logger.debug(f"  [{sel}] error: {e}")
        
        # Try each input selector
        candidates = []
        
        for selector in self.INPUT_SELECTORS:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    if await self._is_visible(element):
                        score = await self._score_element(element, selector)
                        candidates.append((element, selector, score))
                        if debug:
                            placeholder = await element.get_attribute('placeholder') or ''
                            logger.info(f"  CANDIDATE [{selector}]: placeholder='{placeholder[:50]}' score={score:.1f}")
            except Exception:
                continue
        
        if not candidates:
            logger.warning("No chat interface detected")
            
            # Fallback: try to find any visible textarea or contenteditable
            logger.info("Trying fallback detection...")
            fallback_selectors = ['textarea', '[contenteditable="true"]']
            for sel in fallback_selectors:
                try:
                    elements = await self.page.query_selector_all(sel)
                    for element in elements:
                        if await self._is_visible(element):
                            bbox = await element.bounding_box()
                            if bbox and bbox['height'] > 20:
                                score = await self._score_element(element, sel)
                                if score > 0:
                                    candidates.append((element, sel, score))
                                    break
                except Exception:
                    continue
            
            if not candidates:
                logger.warning("Fallback detection also failed - no chat interface found")
                return None
        
        # Sort by confidence score
        candidates.sort(key=lambda x: x[2], reverse=True)
        
        best_element, best_selector, best_score = candidates[0]
        
        # Find associated send button
        send_button = await self._find_send_button(best_element)
        
        # Determine input type
        input_type = await self._classify_input(best_element)
        
        logger.info(f"Chat interface detected: {best_selector} (confidence: {best_score:.2f})")
        
        return ChatElement(
            input_element=best_element,
            send_button=send_button,
            input_type=input_type,
            confidence=best_score,
            selector=best_selector,
        )
    
    async def _is_visible(self, element: ElementHandle) -> bool:
        """Check if element is visible on page."""
        try:
            is_visible = await element.is_visible()
            is_enabled = await element.is_enabled()
            return is_visible and is_enabled
        except Exception:
            return False
    
    async def _score_element(self, element: ElementHandle, selector: str) -> float:
        """
        Score element based on likelihood of being a chat input.
        
        Scoring factors:
        - Placeholder text (25 points)
        - Class/ID patterns (20 points)
        - ARIA attributes (15 points)
        - Proximity to send button (25 points)
        - Position on page (15 points)
        """
        score = 0.0
        
        # Check placeholder text
        placeholder = await element.get_attribute("placeholder") or ""
        if any(keyword in placeholder.lower() for keyword in self.CHAT_KEYWORDS):
            score += 25.0
        
        # Check class and ID
        class_attr = await element.get_attribute("class") or ""
        id_attr = await element.get_attribute("id") or ""
        combined_attrs = f"{class_attr} {id_attr}".lower()
        
        if any(keyword in combined_attrs for keyword in self.CHAT_KEYWORDS):
            score += 20.0
        
        # Check ARIA attributes
        role = await element.get_attribute("role") or ""
        aria_label = await element.get_attribute("aria-label") or ""
        
        if role == "textbox" or "textbox" in aria_label.lower():
            score += 15.0
        
        # Check for nearby send button
        send_button = await self._find_send_button(element)
        if send_button:
            score += 25.0
        
        # Check position (prefer elements at bottom of page)
        try:
            bbox = await element.bounding_box()
            if bbox:
                viewport_height = self.page.viewport_size["height"]
                if bbox["y"] > viewport_height * 0.5:
                    score += 15.0
        except Exception:
            pass
        
        return score
    
    async def _find_send_button(self, input_element: ElementHandle) -> Optional[ElementHandle]:
        """Find send button near the input element."""
        for selector in self.BUTTON_SELECTORS:
            try:
                buttons = await self.page.query_selector_all(selector)
                for button in buttons:
                    if await self._is_visible(button):
                        # Check if button is near the input
                        if await self._are_nearby(input_element, button):
                            return button
            except Exception:
                continue
        return None
    
    async def _are_nearby(
        self,
        element1: ElementHandle,
        element2: ElementHandle,
        max_distance: int = 200,
    ) -> bool:
        """Check if two elements are near each other."""
        try:
            bbox1 = await element1.bounding_box()
            bbox2 = await element2.bounding_box()
            
            if bbox1 and bbox2:
                # Calculate distance between centers
                center1 = (bbox1["x"] + bbox1["width"] / 2, bbox1["y"] + bbox1["height"] / 2)
                center2 = (bbox2["x"] + bbox2["width"] / 2, bbox2["y"] + bbox2["height"] / 2)
                
                distance = ((center1[0] - center2[0]) ** 2 + (center1[1] - center2[1]) ** 2) ** 0.5
                return distance < max_distance
        except Exception:
            pass
        
        return False
    
    async def _classify_input(self, element: ElementHandle) -> str:
        """Classify the type of input element."""
        tag_name = await element.evaluate("el => el.tagName.toLowerCase()")
        
        if tag_name == "textarea":
            return "textarea"
        elif tag_name == "input":
            return "input"
        else:
            # Check if contenteditable
            contenteditable = await element.get_attribute("contenteditable")
            role = await element.get_attribute("role")
            
            if contenteditable == "true" or role == "textbox":
                return "contenteditable"
            
            return "unknown"
    
    async def send_message(self, chat_element: ChatElement, message: str) -> None:
        """
        Send a message through the detected chat interface.
        
        Args:
            chat_element: Detected chat element
            message: Message to send
        """
        logger.debug(f"Sending message: {message[:50]}...")
        
        # Click input to focus
        await chat_element.input_element.click()
        
        # Clear existing text
        await chat_element.input_element.fill("")
        
        # Type message
        await chat_element.input_element.fill(message)
        
        # Send message (click button or press Enter)
        if chat_element.send_button:
            await chat_element.send_button.click()
        else:
            await self.page.keyboard.press("Enter")
        
        logger.debug("Message sent")
    
    async def wait_for_response(
        self,
        timeout: int = 30000,
        response_selector: str = None,
    ) -> Optional[str]:
        """
        Wait for AI response to appear.
        
        Args:
            timeout: Maximum wait time in milliseconds
            response_selector: Optional custom selector for response elements
        
        Returns:
            Response text if found, None otherwise
        """
        # Default response selectors
        if not response_selector:
            response_selectors = [
                '[class*="message" i]:last-child',
                '[class*="response" i]:last-child',
                '[class*="assistant" i]:last-child',
                '[class*="bot" i]:last-child',
                '[role="article"]:last-child',
                '[data-role="assistant"]',
                '.message:last-child',
                '.chat-message:last-child',
            ]
        else:
            response_selectors = [response_selector]
        
        # Wait for new content to appear
        try:
            await self.page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass
        
        # Try to find response element
        for selector in response_selectors:
            try:
                element = await self.page.wait_for_selector(selector, timeout=5000)
                if element:
                    text = await element.text_content()
                    if text and len(text.strip()) > 0:
                        return text.strip()
            except Exception:
                continue
        
        # Fallback: get last message-like element
        try:
            all_messages = await self.page.query_selector_all('[class*="message" i]')
            if all_messages:
                last_message = all_messages[-1]
                return await last_message.text_content()
        except Exception:
            pass
        
        return None
    
    async def get_all_messages(self) -> List[str]:
        """Get all visible messages on the page."""
        messages = []
        
        selectors = [
            '[class*="message" i]',
            '[class*="response" i]',
            '[class*="assistant" i]',
            '[role="article"]',
        ]
        
        for selector in selectors:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    text = await element.text_content()
                    if text and len(text.strip()) > 0:
                        messages.append(text.strip())
            except Exception:
                continue
        
        return messages
