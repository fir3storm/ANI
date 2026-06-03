"""CLI interface for AI Prompt Injection Pentest Tool."""

import asyncio
import sys
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console

from .browser.controller import BrowserController
from .browser.chat_detector import ChatDetector
from .browser.ai_identifier import AIIdentifier
from .browser.auth_handler import AuthHandler, AuthMode, AuthProfile
from .attacks.prompt_injection import PromptInjectionAttack
from .attacks.jailbreak import JailbreakAttack
from .attacks.system_prompt import SystemPromptAttack
from .attacks.data_exfiltration import DataExfiltrationAttack
from .attacks.encoding_bypass import EncodingBypassAttack
from .attacks.advanced import AdvancedAttack
from .attacks.base import AttackResult
from .reporting.console import ConsoleReporter
from .reporting.generator import ReportGenerator
from .utils.config import get_config
from .utils.logger import setup_logger, get_logger

app = typer.Typer(
    name="ai-siege",
    help="AI Siege - Autonomous AI Prompt Injection Pentest Tool",
    add_completion=False,
)
console = Console()
reporter = ConsoleReporter()


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output report path"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html or json)"),
    tests: Optional[str] = typer.Option(None, "--tests", "-t", help="Comma-separated test categories to run"),
    headless: bool = typer.Option(False, "--headless", help="Run browser in headless mode"),
    auth: str = typer.Option("manual", "--auth", "-a", help="Authentication mode (manual, credentials, session, token)"),
    auth_profile: Optional[str] = typer.Option(None, "--auth-profile", help="Path to auth profile JSON"),
    session_id: Optional[str] = typer.Option(None, "--session-id", help="Session ID to reuse"),
    session_file: Optional[str] = typer.Option(None, "--session-file", help="Path to exported session JSON file"),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Authentication cookies"),
    timeout: int = typer.Option(30, "--timeout", help="Response timeout in seconds"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    debug_chat: bool = typer.Option(False, "--debug-chat", help="Debug chat interface detection"),
):
    """Run prompt injection tests against target AI application."""
    
    # Setup logging
    log_level = 10 if verbose else 20  # DEBUG or INFO
    setup_logger(level=log_level)
    
    # Parse test categories
    test_categories = None
    if tests:
        test_categories = [t.strip() for t in tests.split(",")]
    
    # Run async scan
    asyncio.run(
        _run_scan(
            url=url,
            output=output,
            format=format,
            test_categories=test_categories,
            headless=headless,
            auth_mode=auth,
            auth_profile=auth_profile,
            session_id=session_id,
            session_file=session_file,
            cookie=cookie,
            timeout=timeout,
        )
    )


async def _run_scan(
    url: str,
    output: Optional[str],
    format: str,
    test_categories: Optional[List[str]],
    headless: bool,
    auth_mode: str,
    auth_profile: Optional[str],
    session_id: Optional[str],
    session_file: Optional[str],
    cookie: Optional[str],
    timeout: int,
    debug_chat: bool = False,
):
    """Execute the scan asynchronously."""
    logger = get_logger()
    
    # Print header
    reporter.print_header(url)
    
    # Initialize browser
    reporter.print_progress("Launching browser...")
    browser = BrowserController()
    await browser.launch(headless=headless)
    
    try:
        # Navigate to target
        reporter.print_progress(f"Navigating to {url}...")
        await browser.navigate_to(url)
        
        # Handle authentication
        auth_handler = AuthHandler(browser.page)
        auth_mode_enum = AuthMode(auth_mode.lower())
        
        if auth_mode_enum == AuthMode.CREDENTIALS and auth_profile:
            profile = auth_handler.load_auth_profile(auth_profile)
            reporter.print_progress(f"Authenticating with profile: {profile.name}...")
            success = await auth_handler.authenticate(auth_mode_enum, target_url=url, auth_profile=profile)
        elif auth_mode_enum == AuthMode.SESSION and session_file:
            reporter.print_progress(f"Loading session from file: {session_file}...")
            success = await auth_handler.authenticate(AuthMode.SESSION, target_url=url, session_file=session_file)
        elif auth_mode_enum == AuthMode.SESSION and session_id:
            reporter.print_progress(f"Loading session: {session_id}...")
            success = await auth_handler.authenticate(auth_mode_enum, target_url=url, session_id=session_id)
        elif auth_mode_enum == AuthMode.TOKEN and cookie:
            reporter.print_progress("Injecting authentication cookies...")
            success = await auth_handler.authenticate(auth_mode_enum, target_url=url, cookies=cookie)
        else:
            reporter.print_progress("Manual login mode - please login in the browser...")
            success = await auth_handler.authenticate(AuthMode.MANUAL, target_url=url)
        
        if not success:
            reporter.print_error("Authentication failed")
            await browser.close()
            return
        
        reporter.print_success("Authenticated successfully")
        
        # Detect chat interface
        reporter.print_progress("Detecting chat interface...")
        chat_detector = ChatDetector(browser.page)
        chat_element = await chat_detector.detect(debug=debug_chat)
        
        if not chat_element:
            reporter.print_error("Could not detect chat interface")
            await browser.close()
            return
        
        reporter.print_success(f"Chat interface detected (confidence: {chat_element.confidence:.0%})")
        
        # Identify AI model
        reporter.print_progress("Identifying AI model...")
        ai_identifier = AIIdentifier(browser.page)
        ai_model = await ai_identifier.identify()
        
        reporter.print_ai_model({
            "name": ai_model.name,
            "provider": ai_model.provider,
            "confidence": ai_model.confidence,
        })
        
        # Initialize attacks
        attack_classes = {
            "prompt_injection": PromptInjectionAttack,
            "jailbreak": JailbreakAttack,
            "system_prompt": SystemPromptAttack,
            "data_exfiltration": DataExfiltrationAttack,
            "encoding_bypass": EncodingBypassAttack,
            "advanced": AdvancedAttack,
        }
        
        # Filter attacks if specified
        if test_categories:
            attack_classes = {
                k: v for k, v in attack_classes.items()
                if k in test_categories
            }
        
        # Execute attacks
        all_results: List[AttackResult] = []
        
        for attack_id, attack_class in attack_classes.items():
            attack = attack_class(browser, chat_detector, url)
            
            reporter.print_attack_header(attack.attack_name, len(attack.get_payloads()))
            
            results = await attack.execute(chat_element)
            all_results.extend(results)
            
            # Print results
            for result in results:
                reporter.print_result(result)
        
        # Print summary
        reporter.print_summary(all_results)
        reporter.print_vulnerabilities(all_results)
        
        # Generate report
        if output:
            report_path = Path(output)
        else:
            report_path = None
        
        report_generator = ReportGenerator()
        report_file = report_generator.generate(
            results=all_results,
            target_url=url,
            ai_model={
                "name": ai_model.name,
                "provider": ai_model.provider,
                "confidence": ai_model.confidence,
            },
            output_format=format,
            output_path=report_path,
        )
        
        reporter.print_success(f"Report generated: {report_file}")
        
        # Offer to save session
        save_session = typer.confirm("Save authenticated session for future use?", default=False)
        if save_session:
            session_name = typer.prompt("Session name")
            session_path = await auth_handler.save_session(session_name)
            reporter.print_success(f"Session saved: {session_path}")
        
    except KeyboardInterrupt:
        reporter.print_warning("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        reporter.print_error(f"Scan failed: {e}")
    finally:
        await browser.close()


@app.command()
def list_tests():
    """List all available test scenarios."""
    
    attacks = [
        ("prompt_injection", "Prompt Injection", "Tests for direct/indirect prompt injection", 8),
        ("jailbreak", "Jailbreak", "Tests for jailbreak and role-playing attacks", 7),
        ("system_prompt", "System Prompt Extraction", "Tests for system prompt leakage", 8),
        ("data_exfiltration", "Data Exfiltration", "Tests for data exfiltration vulnerabilities", 7),
        ("encoding_bypass", "Encoding Bypass", "Tests for encoding-based filter bypasses", 8),
        ("advanced", "Advanced Attacks", "Multi-turn and advanced attack scenarios", 7),
    ]
    
    console.print()
    console.print("[bold cyan]Available Test Categories[/bold cyan]")
    console.print()
    
    from rich.table import Table
    from rich import box
    
    table = Table(box=box.ROUNDED)
    table.add_column("ID", style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Payloads", justify="center")
    
    for attack_id, name, desc, count in attacks:
        table.add_row(attack_id, name, desc, str(count))
    
    console.print(table)
    console.print()
    console.print("[dim]Use --tests to specify categories: --tests prompt_injection,jailbreak[/dim]")
    console.print()


@app.command()
def sessions(
    action: str = typer.Argument(..., help="Action: list, save, delete"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Session name"),
):
    """Manage saved authentication sessions."""
    
    auth_handler = AuthHandler(None)
    
    if action == "list":
        session_list = auth_handler.list_sessions()
        
        if not session_list:
            console.print("[yellow]No saved sessions found[/yellow]")
            return
        
        console.print()
        console.print("[bold cyan]Saved Sessions[/bold cyan]")
        console.print()
        
        from rich.table import Table
        from rich import box
        from datetime import datetime
        
        table = Table(box=box.ROUNDED)
        table.add_column("Session ID", style="bold")
        table.add_column("Size")
        table.add_column("Last Modified")
        
        for session in session_list:
            modified = datetime.fromtimestamp(session["modified"]).strftime("%Y-%m-%d %H:%M:%S")
            size = f"{session['size'] / 1024:.1f} KB"
            table.add_row(session["id"], size, modified)
        
        console.print(table)
        console.print()
    
    elif action == "save":
        if not name:
            name = typer.prompt("Session name")
        console.print(f"[yellow]Session save requires an active scan[/yellow]")
    
    elif action == "delete":
        if not name:
            name = typer.prompt("Session name to delete")
        
        if typer.confirm(f"Delete session '{name}'?"):
            if auth_handler.delete_session(name):
                console.print(f"[green]Session '{name}' deleted[/green]")
            else:
                console.print(f"[red]Session '{name}' not found[/red]")


@app.command()
def auth(
    action: str = typer.Argument(..., help="Action: create-profile, validate-profile, test-profile"),
    profile_path: Optional[str] = typer.Option(None, "--profile", "-p", help="Path to auth profile"),
):
    """Manage authentication profiles."""
    
    if action == "create-profile":
        console.print()
        console.print("[bold cyan]Create Authentication Profile[/bold cyan]")
        console.print()
        
        name = typer.prompt("Profile name")
        url = typer.prompt("Login URL")
        auth_type = typer.prompt("Auth type", default="credentials")
        
        profile = {
            "name": name,
            "url": url,
            "auth_type": auth_type,
            "selectors": {},
            "credentials": {},
            "post_login": {},
        }
        
        if auth_type == "credentials":
            profile["selectors"]["username_field"] = typer.prompt("Username field selector", default="input[name='email']")
            profile["selectors"]["password_field"] = typer.prompt("Password field selector", default="input[name='password']")
            profile["selectors"]["submit_button"] = typer.prompt("Submit button selector", default="button[type='submit']")
            profile["credentials"]["username"] = typer.prompt("Username/Email")
            profile["credentials"]["password"] = typer.prompt("Password", hide_input=True)
            profile["post_login"]["success_indicator"] = typer.prompt("Success indicator selector", default=".chat-container")
        
        # Save profile
        import json
        from pathlib import Path
        
        config = get_config()
        config.auth_profiles_dir.mkdir(parents=True, exist_ok=True)
        
        profile_file = config.auth_profiles_dir / f"{name.lower().replace(' ', '_')}.json"
        with open(profile_file, "w") as f:
            json.dump(profile, f, indent=2)
        
        console.print(f"[green]Profile saved: {profile_file}[/green]")
    
    elif action == "validate-profile":
        if not profile_path:
            profile_path = typer.prompt("Profile path")
        
        try:
            auth_handler = AuthHandler(None)
            profile = auth_handler.load_auth_profile(profile_path)
            console.print(f"[green]Profile '{profile.name}' is valid[/green]")
        except Exception as e:
            console.print(f"[red]Invalid profile: {e}[/red]")
    
    elif action == "test-profile":
        console.print("[yellow]Profile testing requires browser automation[/yellow]")
        console.print("[yellow]Use: python -m ai_pentest scan --url <URL> --auth credentials --auth-profile <PROFILE>[/yellow]")


@app.command()
def version():
    """Show tool version."""
    from . import __version__
    console.print(f"[bold cyan]AI Siege[/bold cyan] v{__version__} [dim]by Abhirup Guha[/dim]")


if __name__ == "__main__":
    app()
