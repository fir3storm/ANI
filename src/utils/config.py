"""Configuration management for AI Pentest Tool."""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()


class BrowserConfig(BaseModel):
    """Browser configuration settings."""
    headless: bool = False
    timeout: int = 30000
    viewport_width: int = 1280
    viewport_height: int = 720
    slow_mo: int = 100
    user_agent: Optional[str] = None


class AttackConfig(BaseModel):
    """Attack configuration settings."""
    delay_between_attacks: float = 2.0
    max_retries: int = 3
    screenshot_on_vuln: bool = True
    save_responses: bool = True


class ReportingConfig(BaseModel):
    """Reporting configuration settings."""
    output_dir: str = "./reports"
    format: str = "html"
    include_payloads: bool = True
    include_screenshots: bool = True


class Config(BaseModel):
    """Main configuration for AI Pentest Tool."""
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    
    # Paths
    base_dir: Path = Field(default_factory=lambda: Path.cwd())
    payloads_dir: Path = Field(default_factory=lambda: Path.cwd() / "payloads")
    auth_profiles_dir: Path = Field(default_factory=lambda: Path.cwd() / "auth_profiles")
    sessions_dir: Path = Field(default_factory=lambda: Path.cwd() / "sessions")
    reports_dir: Path = Field(default_factory=lambda: Path.cwd() / "reports")
    
    # Security
    encryption_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("AI_PENTEST_KEY", None)
    )
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        for dir_path in [
            self.payloads_dir,
            self.auth_profiles_dir,
            self.sessions_dir,
            self.reports_dir,
        ]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Load configuration from file or use defaults."""
        config = cls()
        config.ensure_directories()
        return config


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global configuration instance."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config
