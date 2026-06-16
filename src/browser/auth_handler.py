"""Authentication handler for ANI."""

import json
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
from playwright.async_api import Page, ElementHandle

from ..utils.config import get_config
from ..utils.crypto import encrypt_json, decrypt_json, is_fernet_token
from ..utils.logger import get_logger

logger = get_logger()


class AuthMode(Enum):
    """Authentication modes."""
    MANUAL = "manual"
    CREDENTIALS = "credentials"
    SESSION = "session"
    TOKEN = "token"


@dataclass
class LoginForm:
    """Represents a detected login form."""
    username_field: Optional[ElementHandle]
    password_field: ElementHandle
    submit_button: ElementHandle
    form_type: str  # "form", "oauth", "custom"


@dataclass
class AuthProfile:
    """Authentication profile loaded from config."""
    name: str
    url: str
    auth_type: str
    selectors: Dict[str, str]
    credentials: Dict[str, str]
    post_login: Dict[str, Any]
    instructions: Optional[str] = None

    def save(self, path: Path, encrypt: bool = True) -> None:
        """Persist this profile to disk.

        When ``encrypt`` is True the payload is stored as a Fernet-encrypted
        blob (``.enc`` file). When False the file is written as plain JSON.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "name": self.name,
            "url": self.url,
            "auth_type": self.auth_type,
            "selectors": self.selectors,
            "credentials": self.credentials,
            "post_login": self.post_login,
            "instructions": self.instructions,
        }
        if encrypt:
            target = path if path.suffix == ".enc" else path.with_suffix(".enc")
            target.write_bytes(encrypt_json(data))
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)


@dataclass
class OAuthProvider:
    """Detected OAuth provider."""
    name: str
    button: ElementHandle
    url_pattern: str


_SENSITIVE_HEADERS = {"cookie", "authorization", "set-cookie"}


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for name, value in headers.items():
        if name.lower() in _SENSITIVE_HEADERS:
            redacted[name] = "[REDACTED]"
        else:
            redacted[name] = value
    return redacted


class AuthHandler:
    """Handles various authentication flows for protected chat interfaces."""

    # Common login form selectors
    LOGIN_SELECTORS = {
        "username": [
            'input[name="email"]',
            'input[name="username"]',
            'input[name="user"]',
            'input[id="email"]',
            'input[id="username"]',
            'input[type="email"]',
            'input[type="text"][placeholder*="email" i]',
            'input[type="text"][placeholder*="username" i]',
            'input[type="text"][placeholder*="user" i]',
        ],
        "password": [
            'input[name="password"]',
            'input[name="pass"]',
            'input[id="password"]',
            'input[type="password"]',
        ],
        "submit": [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Login")',
            'button:has-text("Sign in")',
            'button:has-text("Log in")',
            'button:has-text("Submit")',
            'button:has-text("Continue")',
        ],
    }

    # OAuth provider patterns
    OAUTH_PROVIDERS = {
        "google": {
            "patterns": ["accounts.google.com", "googleapis.com"],
            "button_text": ["google", "sign in with google", "continue with google"],
        },
        "microsoft": {
            "patterns": ["login.microsoftonline.com", "microsoft.com"],
            "button_text": ["microsoft", "sign in with microsoft", "continue with microsoft"],
        },
        "github": {
            "patterns": ["github.com/login", "github.com"],
            "button_text": ["github", "sign in with github", "continue with github"],
        },
        "okta": {
            "patterns": ["okta.com"],
            "button_text": ["okta", "sign in with okta"],
        },
    }

    def __init__(self, page: Page):
        self.page = page
        self.config = get_config()
        self.session_dir = self.config.sessions_dir
        self.profile_dir = self.config.auth_profiles_dir

    async def authenticate(
        self,
        mode: AuthMode,
        target_url: str = None,
        auth_profile: Optional[AuthProfile] = None,
        session_id: Optional[str] = None,
        session_file: Optional[str] = None,
        cookies: Optional[str] = None,
    ) -> bool:
        """
        Perform authentication based on specified mode.

        Args:
            mode: Authentication mode
            auth_profile: Profile for credential-based auth
            session_id: Session ID for session reuse
            cookies: Cookie string for token injection

        Returns:
            True if authentication successful
        """
        logger.info(f"Starting authentication (mode: {mode.value})")

        try:
            if mode == AuthMode.MANUAL:
                return await self._auth_manual()
            elif mode == AuthMode.CREDENTIALS:
                if not auth_profile:
                    logger.error("Auth profile required for credential mode")
                    return False
                return await self._auth_credentials(auth_profile)
            elif mode == AuthMode.SESSION:
                if session_file:
                    return await self._auth_session_file(session_file, target_url)
                elif session_id:
                    return await self._auth_session(session_id, target_url)
                else:
                    logger.error("Session ID or Session File required for session mode")
                    return False
            elif mode == AuthMode.TOKEN:
                if not cookies:
                    logger.error("Cookies required for token mode")
                    return False
                return await self._auth_token(cookies)
            else:
                logger.error(f"Unknown auth mode: {mode}")
                return False

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    async def detect_login_form(self) -> Optional[LoginForm]:
        """
        Auto-detect login form on the current page.

        Returns:
            LoginForm if found, None otherwise
        """
        logger.info("Scanning for login form...")

        # Find password field (most reliable indicator)
        password_field = None
        for selector in self.LOGIN_SELECTORS["password"]:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible():
                        password_field = element
                        break
                if password_field:
                    break
            except Exception:
                continue

        if not password_field:
            logger.debug("No login form detected")
            return None

        # Find username field
        username_field = None
        for selector in self.LOGIN_SELECTORS["username"]:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible():
                        username_field = element
                        break
                if username_field:
                    break
            except Exception:
                continue

        # Find submit button
        submit_button = None
        for selector in self.LOGIN_SELECTORS["submit"]:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible():
                        submit_button = element
                        break
                if submit_button:
                    break
            except Exception:
                continue

        if password_field and submit_button:
            logger.info("Login form detected")
            return LoginForm(
                username_field=username_field,
                password_field=password_field,
                submit_button=submit_button,
                form_type="form",
            )

        return None

    async def detect_oauth_providers(self) -> List[OAuthProvider]:
        """
        Detect available OAuth providers.

        Returns:
            List of detected OAuth providers
        """
        providers = []

        # Look for OAuth buttons
        buttons = await self.page.query_selector_all('button, a[role="button"], [class*="social"]')

        for button in buttons:
            try:
                text = (await button.text_content() or "").lower()
                href = await button.get_attribute("href") or ""

                for provider_name, provider_config in self.OAUTH_PROVIDERS.items():
                    # Check button text
                    if any(pattern in text for pattern in provider_config["button_text"]):
                        providers.append(OAuthProvider(
                            name=provider_name,
                            button=button,
                            url_pattern=provider_config["patterns"][0],
                        ))
                        break

                    # Check href
                    if any(pattern in href for pattern in provider_config["patterns"]):
                        providers.append(OAuthProvider(
                            name=provider_name,
                            button=button,
                            url_pattern=provider_config["patterns"][0],
                        ))
                        break
            except Exception:
                continue

        if providers:
            logger.info(f"Detected OAuth providers: {[p.name for p in providers]}")

        return providers

    async def _auth_manual(self, timeout: int = 300) -> bool:
        """
        Manual authentication - user logs in themselves.

        Args:
            timeout: Maximum wait time in seconds
        """
        logger.info("=" * 60)
        logger.info("[bold yellow]MANUAL LOGIN REQUIRED[/bold yellow]")
        logger.info("Please log in manually in the browser window.")
        logger.info("Press ENTER in the terminal when you have logged in.")
        logger.info("=" * 60)

        # Wait for user input in a separate thread to not block event loop
        loop = asyncio.get_event_loop()

        try:
            # Run input() in thread pool
            await asyncio.wait_for(
                loop.run_in_executor(None, input),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.error(f"Manual login timed out after {timeout} seconds")
            return False

        # Verify login success
        return await self._verify_login()

    async def _auth_credentials(self, profile: AuthProfile) -> bool:
        """
        Automatic credential-based authentication.

        Args:
            profile: Authentication profile with credentials
        """
        logger.info(f"Attempting credential-based login for: {profile.name}")

        # Navigate to login URL if specified
        if profile.url and profile.url != self.page.url:
            await self.page.goto(profile.url)
            await self.page.wait_for_load_state("networkidle")

        # Detect login form
        login_form = await self.detect_login_form()

        if not login_form:
            logger.error("Could not detect login form")
            return False

        # Fill username if present
        if login_form.username_field:
            username = profile.credentials.get("username", "")
            masked_user = username[:3] + "***" if username else ""
            await login_form.username_field.fill(username)
            logger.debug(f"Filled username field with value: {masked_user}")

        # Fill password
        password = profile.credentials.get("password", "")
        await login_form.password_field.fill(password)
        logger.debug("Filled password field")

        # Click submit
        await login_form.submit_button.click()

        # Wait for navigation
        await self.page.wait_for_load_state("networkidle")

        # Check for custom selectors if provided
        if profile.selectors.get("mfa_field"):
            logger.info("MFA required - waiting for manual input...")
            mfa_field = await self.page.wait_for_selector(
                profile.selectors["mfa_field"],
                timeout=120000,
            )
            if mfa_field:
                mfa_code = input("Enter MFA code: ")
                await mfa_field.fill(mfa_code)

                mfa_submit = profile.selectors.get("mfa_submit", 'button[type="submit"]')
                await self.page.click(mfa_submit)
                await self.page.wait_for_load_state("networkidle")

        # Verify success
        success_indicator = profile.post_login.get("success_indicator")
        if success_indicator:
            try:
                await self.page.wait_for_selector(success_indicator, timeout=10000)
                logger.info("Login successful")
                return True
            except Exception:
                logger.error("Login failed - success indicator not found")
                return False

        return await self._verify_login()

    async def _auth_session_file(self, session_file: str, target_url: str = None) -> bool:
        """
        Load existing session from a specific file path by injecting cookies.

        Args:
            session_file: Path to the session JSON file
            target_url: URL to navigate to after loading session
        """
        from pathlib import Path
        file_path = Path(session_file)

        if not file_path.exists():
            logger.error(f"Session file not found: {session_file}")
            return False

        logger.info(f"Loading session from file: {session_file}")

        try:
            state = self._read_session_state(file_path)

            cookies = state.get("cookies", [])
            if not cookies:
                logger.error("No cookies found in session file")
                return False

            await self.page.context.add_cookies(cookies)
            logger.info(f"Injected {len(cookies)} cookies into browser")

            if target_url:
                await self.page.goto(target_url)
            else:
                await self.page.reload()

            await self.page.wait_for_load_state("networkidle")

            if await self._verify_login():
                logger.info("Session file loaded successfully")
                return True
            else:
                logger.warning("Session expired or invalid")
                return False

        except Exception as e:
            logger.error(f"Failed to load session file: {e}")
            return False

    async def _auth_session(self, session_id: str, target_url: str = None) -> bool:
        """
        Load existing session by injecting cookies.

        Args:
            session_id: Session identifier
            target_url: URL to navigate to after loading session
        """
        session_path = self.session_dir / f"{session_id}.enc"
        legacy_path = self.session_dir / f"{session_id}.json"

        path = session_path if session_path.exists() else legacy_path
        if not path.exists():
            logger.error(f"Session not found: {session_id}")
            return False

        logger.info(f"Loading session: {session_id}")

        try:
            state = self._read_session_state(path)

            cookies = state.get("cookies", [])
            if not cookies:
                logger.error("No cookies found in session file")
                return False

            await self.page.context.add_cookies(cookies)
            logger.info(f"Injected {len(cookies)} cookies into browser")

            if target_url:
                await self.page.goto(target_url)
            else:
                await self.page.reload()

            await self.page.wait_for_load_state("networkidle")

            if await self._verify_login():
                logger.info("Session loaded successfully")
                return True
            else:
                logger.warning("Session expired")
                return False

        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return False

    async def _auth_token(self, cookies: str) -> bool:
        """
        Inject authentication cookies/tokens.

        Args:
            cookies: Cookie string (name=value; name2=value2)
        """
        logger.info("Injecting authentication cookies...")

        try:
            cookie_list = []
            for cookie in cookies.split(";"):
                cookie = cookie.strip()
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    cookie_list.append({
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": self._extract_domain(self.page.url),
                        "path": "/",
                    })

            await self.page.context.add_cookies(cookie_list)
            await self.page.reload()
            await self.page.wait_for_load_state("networkidle")

            if await self._verify_login():
                logger.info("Cookie injection successful")
                return True
            else:
                logger.warning("Cookie injection failed - session may be invalid")
                return False

        except Exception as e:
            logger.error(f"Cookie injection failed: {e}")
            return False

    def _read_session_state(self, path: Path) -> dict:
        """Read a session file handling encrypted and legacy plaintext formats."""
        raw = path.read_bytes()
        if path.suffix == ".enc" or is_fernet_token(raw):
            return decrypt_json(raw)
        logger.warning(
            f"Session file {path} is unencrypted; please re-save as encrypted."
        )
        return json.loads(raw.decode("utf-8"))

    async def _verify_login(self) -> bool:
        """
        Verify if login was successful.

        Returns:
            True if appears to be logged in
        """
        logged_in_indicators = [
            '[class*="dashboard"]',
            '[class*="chat"]',
            '[class*="user-menu"]',
            '[class*="profile"]',
            '[class*="logout"]',
            '[aria-label*="logout" i]',
            '[aria-label*="sign out" i]',
        ]

        for indicator in logged_in_indicators:
            try:
                element = await self.page.query_selector(indicator)
                if element:
                    return True
            except Exception:
                continue

        login_indicators = [
            'input[type="password"]',
            '[class*="login"]',
            '[class*="signin"]',
            '[id*="login"]',
        ]

        for indicator in login_indicators:
            try:
                element = await self.page.query_selector(indicator)
                if element and await element.is_visible():
                    return False
            except Exception:
                continue

        return True

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc

    async def save_session(self, session_id: str) -> Path:
        """
        Save current browser session for reuse.

        Args:
            session_id: Identifier for the session

        Returns:
            Path to saved session file
        """
        self.session_dir.mkdir(parents=True, exist_ok=True)
        state = await self.page.context.storage_state()

        encrypted_path = self.session_dir / f"{session_id}.enc"
        encrypted_path.write_bytes(encrypt_json(state))

        legacy_path = self.session_dir / f"{session_id}.json"
        if legacy_path.exists():
            try:
                legacy_path.unlink()
            except OSError:
                pass

        logger.info(f"Session saved: {encrypted_path}")
        return encrypted_path

    def load_auth_profile(self, profile_path: str) -> AuthProfile:
        """
        Load authentication profile from JSON or encrypted file.

        Args:
            profile_path: Path to profile file

        Returns:
            AuthProfile instance
        """
        path = Path(profile_path)

        if not path.exists():
            raise FileNotFoundError(f"Auth profile not found: {profile_path}")

        if path.suffix == ".enc" or is_fernet_token(path.read_bytes()[:6]):
            data = decrypt_json(path.read_bytes())
        else:
            with open(path) as f:
                data = json.load(f)

        return AuthProfile(
            name=data.get("name", "Unknown"),
            url=data.get("url", ""),
            auth_type=data.get("auth_type", "credentials"),
            selectors=data.get("selectors", {}),
            credentials=data.get("credentials", {}),
            post_login=data.get("post_login", {}),
            instructions=data.get("instructions"),
        )

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all saved sessions.

        Returns:
            List of session metadata
        """
        sessions = []

        if self.session_dir.exists():
            for session_file in self.session_dir.glob("*.enc"):
                try:
                    stat = session_file.stat()
                    sessions.append({
                        "id": session_file.stem,
                        "path": str(session_file),
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    })
                except Exception:
                    continue
            for session_file in self.session_dir.glob("*.json"):
                try:
                    stat = session_file.stat()
                    sessions.append({
                        "id": session_file.stem,
                        "path": str(session_file),
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    })
                except Exception:
                    continue

        return sessions

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a saved session.

        Args:
            session_id: Session identifier

        Returns:
            True if deleted successfully
        """
        removed = False
        for suffix in (".enc", ".json"):
            candidate = self.session_dir / f"{session_id}{suffix}"
            if candidate.exists():
                try:
                    candidate.unlink()
                    removed = True
                except OSError:
                    pass
        if removed:
            logger.info(f"Session deleted: {session_id}")
            return True
        logger.warning(f"Session not found: {session_id}")
        return False


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Public helper used by other modules to strip credential headers."""
    return _redact_headers(headers)
