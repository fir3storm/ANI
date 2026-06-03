"""Browser controller using Playwright for AI Pentest Tool."""

import asyncio
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, ElementHandle

from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger()


class BrowserController:
    """Manages Playwright browser instance for AI testing."""
    
    def __init__(self):
        self.config = get_config()
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._network_requests: List[dict] = []
    
    async def launch(self, headless: Optional[bool] = None) -> None:
        """
        Launch browser instance.
        
        Args:
            headless: Override config headless setting
        """
        self.playwright = await async_playwright().start()
        
        is_headless = headless if headless is not None else self.config.browser.headless
        
        self.browser = await self.playwright.chromium.launch(
            headless=is_headless,
            slow_mo=self.config.browser.slow_mo,
        )
        
        self.context = await self.browser.new_context(
            viewport={
                "width": self.config.browser.viewport_width,
                "height": self.config.browser.viewport_height,
            },
            user_agent=self.config.browser.user_agent,
        )
        
        self.page = await self.context.new_page()
        
        # Set up network monitoring
        self.page.on("request", self._on_request)
        self.page.on("response", self._on_response)
        
        logger.info(f"Browser launched (headless={is_headless})")
    
    async def navigate_to(self, url: str) -> None:
        """Navigate to specified URL."""
        if not self.page:
            raise RuntimeError("Browser not launched. Call launch() first.")
        
        logger.info(f"Navigating to: {url}")
        await self.page.goto(url, wait_until="networkidle")
        logger.info(f"Page loaded: {await self.page.title()}")
    
    async def wait_for_element(
        self,
        selector: str,
        timeout: Optional[int] = None,
    ) -> ElementHandle:
        """Wait for element to appear on page."""
        timeout = timeout or self.config.browser.timeout
        element = await self.page.wait_for_selector(selector, timeout=timeout)
        return element
    
    async def click_element(self, selector: str) -> None:
        """Click element by selector."""
        await self.page.click(selector)
    
    async def type_text(self, selector: str, text: str, delay: int = 50) -> None:
        """Type text into element."""
        await self.page.fill(selector, text)
    
    async def press_key(self, key: str) -> None:
        """Press keyboard key."""
        await self.page.keyboard.press(key)
    
    async def get_text(self, selector: str) -> str:
        """Get text content of element."""
        element = await self.page.query_selector(selector)
        if element:
            return await element.text_content()
        return ""
    
    async def get_attribute(self, selector: str, attribute: str) -> Optional[str]:
        """Get attribute value of element."""
        element = await self.page.query_selector(selector)
        if element:
            return await element.get_attribute(attribute)
        return None
    
    async def take_screenshot(self, name: Optional[str] = None) -> Path:
        """Take screenshot and save to reports directory."""
        if not name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"screenshot_{timestamp}.png"
        
        screenshot_path = self.config.reports_dir / name
        await self.page.screenshot(path=str(screenshot_path), full_page=True)
        logger.info(f"Screenshot saved: {screenshot_path}")
        return screenshot_path
    
    async def execute_javascript(self, script: str) -> any:
        """Execute JavaScript on the page."""
        return await self.page.evaluate(script)
    
    async def get_page_content(self) -> str:
        """Get full page HTML content."""
        return await self.page.content()
    
    async def wait_for_navigation(self, timeout: Optional[int] = None) -> None:
        """Wait for page navigation to complete."""
        timeout = timeout or self.config.browser.timeout
        await self.page.wait_for_load_state("networkidle", timeout=timeout)
    
    async def get_current_url(self) -> str:
        """Get current page URL."""
        return self.page.url
    
    async def get_network_requests(self) -> List[dict]:
        """Get captured network requests."""
        return self._network_requests.copy()
    
    def clear_network_requests(self) -> None:
        """Clear captured network requests."""
        self._network_requests.clear()
    
    def _on_request(self, request) -> None:
        """Callback for network requests."""
        self._network_requests.append({
            "type": "request",
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "timestamp": datetime.now().isoformat(),
        })
    
    def _on_response(self, response) -> None:
        """Callback for network responses."""
        self._network_requests.append({
            "type": "response",
            "url": response.url,
            "status": response.status,
            "timestamp": datetime.now().isoformat(),
        })
    
    async def save_session(self, session_path: Path) -> None:
        """Save browser session state."""
        if self.context:
            state = await self.context.storage_state()
            session_path.parent.mkdir(parents=True, exist_ok=True)
            
            import json
            with open(session_path, "w") as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"Session saved: {session_path}")
    
    async def load_session(self, session_path: Path) -> None:
        """Load browser session state."""
        if not self.browser:
            raise RuntimeError("Browser not launched. Call launch() first.")
        
        if session_path.exists():
            self.context = await self.browser.new_context(
                storage_state=str(session_path),
                viewport={
                    "width": self.config.browser.viewport_width,
                    "height": self.config.browser.viewport_height,
                },
            )
            self.page = await self.context.new_page()
            logger.info(f"Session loaded: {session_path}")
        else:
            logger.warning(f"Session file not found: {session_path}")
    
    async def close(self) -> None:
        """Close browser and cleanup."""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        
        logger.info("Browser closed")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.launch()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
