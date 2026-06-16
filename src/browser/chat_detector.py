"""Chat interface detection for ANI."""

import asyncio
import json
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

    INPUT_SELECTORS = [
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
        'textarea[class*="chat" i]',
        'textarea[class*="message" i]',
        'textarea[class*="input" i]',
        'textarea[class*="composer" i]',
        'textarea[class*="prompt" i]',
        'textarea[id*="chat" i]',
        'textarea[id*="message" i]',
        'textarea[id*="input" i]',
        'textarea[id*="composer" i]',
        '[contenteditable="true"]',
        'div[role="textbox"]',
        'div[role="searchbox"]',
        'div[class*="chat-input" i]',
        'div[class*="message-input" i]',
        'div[class*="editor" i]',
        'div[class*="composer" i]',
        'div[class*="prompt-input" i]',
        'input[type="text"][placeholder*="message" i]',
        'input[type="text"][placeholder*="chat" i]',
        'input[type="text"][placeholder*="ask" i]',
        'input[type="text"][placeholder*="search" i]',
        'input[type="text"][class*="chat" i]',
        'input[type="text"][class*="search" i]',
        'textarea',
    ]

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

    CHAT_KEYWORDS = [
        "message", "chat", "ask", "type", "enter", "send",
        "conversation", "talk", "assistant", "ai", "bot",
    ]

    _VISIBILITY_JS = r"""
    (el) => {
        try {
            const r = el.getBoundingClientRect();
            const cs = getComputedStyle(el);
            return r.width > 0
                && r.height > 0
                && cs.visibility !== 'hidden'
                && cs.display !== 'none'
                && el.offsetParent !== null;
        } catch (e) {
            return false;
        }
    }
    """

    _STABLE_OBSERVER_JS = r"""
    () => {
        if (window.__aniObserverInstalled) return true;
        window.__aniObserverInstalled = true;
        window.__aniLatestText = '';
        window.__aniLatestAt = 0;
        const target = document.body;
        if (!target) return false;
        const observer = new MutationObserver(() => {
            try {
                const text = (document.body.innerText || '').trim();
                window.__aniLatestText = text;
                window.__aniLatestAt = Date.now();
            } catch (e) {
                // ignore
            }
        });
        observer.observe(target, {
            childList: true,
            subtree: true,
            characterData: true,
        });
        return true;
    }
    """

    def __init__(self, page: Page):
        self.page = page
        self._default_response_timeout = 30000

    async def detect(self, debug: bool = False) -> Optional[ChatElement]:
        """
        Detect chat interface on the current page.

        Args:
            debug: If True, dump all detected elements for debugging

        Returns:
            ChatElement if found, None otherwise
        """
        logger.info("Scanning page for chat interface...")

        await self.page.wait_for_timeout(2000)

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
                        logger.info(
                            f"  [{sel}] #{i}: placeholder='{placeholder[:50]}' "
                            f"class='{class_attr[:30]}' id='{id_attr}' visible={visible}"
                        )
                except Exception as e:
                    logger.debug(f"  [{sel}] error: {e}")

        candidates = await self._collect_candidates(debug=debug)

        if not candidates:
            logger.warning("No chat interface detected")
            candidates = await self._fallback_candidates()
            if not candidates:
                logger.warning("Fallback detection also failed - no chat interface found")
                return None

        candidates.sort(key=lambda x: x[2], reverse=True)

        best_element, best_selector, best_score = candidates[0]

        send_button = await self._find_send_button(best_element)
        input_type = await self._classify_input(best_element)

        logger.info(
            f"Chat interface detected: {best_selector} (confidence: {best_score:.2f})"
        )

        return ChatElement(
            input_element=best_element,
            send_button=send_button,
            input_type=input_type,
            confidence=best_score,
            selector=best_selector,
        )

    async def _collect_candidates(self, debug: bool = False) -> List[Tuple[ElementHandle, str, float]]:
        candidates: List[Tuple[ElementHandle, str, float]] = []
        for selector in self.INPUT_SELECTORS:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    if await self._is_visible(element):
                        score = await self._score_element(element, selector)
                        candidates.append((element, selector, score))
                        if debug:
                            placeholder = await element.get_attribute('placeholder') or ''
                            logger.info(
                                f"  CANDIDATE [{selector}]: placeholder='{placeholder[:50]}' score={score:.1f}"
                            )
            except Exception:
                continue

        for element, selector in await self._collect_frame_candidates():
            try:
                if await self._is_visible(element):
                    score = await self._score_element(element, selector)
                    candidates.append((element, f"frame:{selector}", score))
            except Exception:
                continue

        return candidates

    async def _collect_frame_candidates(self) -> List[Tuple[ElementHandle, str]]:
        """Enumerate iframe frames and run the input selector scan inside each."""
        results: List[Tuple[ElementHandle, str]] = []
        try:
            frames = self.page.frames
        except Exception:
            return results

        for frame in frames:
            if frame == self.page.main_frame:
                continue
            for selector in self.INPUT_SELECTORS[:20]:
                try:
                    elements = await frame.query_selector_all(selector)
                    for element in elements:
                        results.append((element, selector))
                except Exception:
                    continue
        return results

    async def _fallback_candidates(self) -> List[Tuple[ElementHandle, str, float]]:
        """Last-resort scan over textareas and contenteditable elements."""
        candidates: List[Tuple[ElementHandle, str, float]] = []
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
        return candidates

    async def _is_visible(self, element: ElementHandle) -> bool:
        """Native Playwright visibility check with a JS fallback for tricky layouts."""
        try:
            is_visible = await element.is_visible()
            if is_visible:
                return await element.is_enabled()
        except Exception:
            pass

        try:
            fallback = await self.page.evaluate(self._VISIBILITY_JS, element)
            return bool(fallback)
        except Exception:
            return False

    async def _shadow_root_query(self, selector: str) -> Optional[ElementHandle]:
        """Query an input selector inside any open shadow root on the page."""
        try:
            handle = await self.page.evaluate_handle(
                "(sel) => { const all = document.querySelectorAll('*'); for (const el of all) { if (el.shadowRoot) { try { const m = el.shadowRoot.querySelector(sel); if (m) return m; } catch (e) {} } } return null; }",
                selector,
            )
            element = handle.as_element() if handle else None
            return element
        except Exception:
            return None

    async def _score_element(self, element: ElementHandle, selector: str) -> float:
        """
        Score element based on likelihood of being a chat input.
        """
        score = 0.0

        placeholder = await element.get_attribute("placeholder") or ""
        if any(keyword in placeholder.lower() for keyword in self.CHAT_KEYWORDS):
            score += 25.0

        class_attr = await element.get_attribute("class") or ""
        id_attr = await element.get_attribute("id") or ""
        combined_attrs = f"{class_attr} {id_attr}".lower()

        if any(keyword in combined_attrs for keyword in self.CHAT_KEYWORDS):
            score += 20.0

        role = await element.get_attribute("role") or ""
        aria_label = await element.get_attribute("aria-label") or ""

        if role == "textbox" or "textbox" in aria_label.lower():
            score += 15.0

        send_button = await self._find_send_button(element)
        if send_button:
            score += 25.0

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
            contenteditable = await element.get_attribute("contenteditable")
            role = await element.get_attribute("role")

            if contenteditable == "true" or role == "textbox":
                return "contenteditable"

            return "unknown"

    async def send_message(self, chat_element: ChatElement, message: str) -> None:
        """
        Send a message through the detected chat interface.
        """
        logger.debug(f"Sending message: {message[:50]}...")

        await chat_element.input_element.click()
        await chat_element.input_element.fill("")
        await chat_element.input_element.fill(message)

        if chat_element.send_button:
            await chat_element.send_button.click()
        else:
            await self.page.keyboard.press("Enter")

        logger.debug("Message sent")

    async def wait_for_response(
        self,
        timeout: int = None,
        response_selector: str = None,
    ) -> Optional[str]:
        """Wait for AI response to appear, with a MutationObserver-based stable capture."""
        if timeout is None:
            timeout = self._default_response_timeout

        try:
            await self._install_stable_observer()
        except Exception as exc:
            logger.debug(f"Failed to install mutation observer: {exc}")

        deadline = asyncio.get_event_loop().time() + (timeout / 1000.0)
        text = await self._stable_text_poller(deadline)

        if not text:
            text = await self._legacy_response_text(response_selector, timeout)

        if text:
            text = self._strip_user_payload(text)

        return text or None

    async def _install_stable_observer(self) -> bool:
        try:
            return bool(await self.page.evaluate(self._STABLE_OBSERVER_JS))
        except Exception:
            return False

    async def _stable_text_poller(self, deadline: float) -> Optional[str]:
        """Poll the mutation observer's text snapshot until it stops changing."""
        last_text = ""
        stable_ticks = 0
        stable_threshold = 2
        tick_seconds = 0.25

        while True:
            now = asyncio.get_event_loop().time()
            if now >= deadline:
                break
            try:
                current = await self.page.evaluate("() => window.__aniLatestText || ''")
            except Exception:
                current = ""

            if current and current == last_text:
                stable_ticks += 1
                if stable_ticks >= stable_threshold:
                    return current[-2500:]
            else:
                stable_ticks = 0
                last_text = current

            await asyncio.sleep(tick_seconds)

        if last_text:
            return last_text[-2500:]
        return None

    async def _legacy_response_text(
        self,
        response_selector: Optional[str],
        timeout: int,
    ) -> Optional[str]:
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

        try:
            await self.page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass

        for selector in response_selectors:
            try:
                element = await self.page.wait_for_selector(selector, timeout=5000)
                if element:
                    text = await element.text_content()
                    if text and len(text.strip()) > 0:
                        return text.strip()
            except Exception:
                continue

        try:
            all_messages = await self.page.query_selector_all('[class*="message" i]')
            if all_messages:
                last_message = all_messages[-1]
                return await last_message.text_content()
        except Exception:
            pass

        return None

    @staticmethod
    def _strip_user_payload(text: str, payload: Optional[str] = None) -> str:
        """Heuristically drop the user's payload from the captured text.

        Finds the last occurrence of a 20-character prefix of ``payload`` in
        ``text`` and returns the substring that comes after it. If ``payload``
        is missing or no prefix match is found, ``text`` is returned unchanged.
        """
        if not text or not payload or len(payload) < 20:
            return text

        marker = payload[:20]
        idx = text.rfind(marker)
        if idx == -1:
            return text
        return text[idx + len(marker):].lstrip("\n :\t")

    async def get_all_messages(self) -> List[str]:
        """Get all visible messages on the page."""
        messages: List[str] = []
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
