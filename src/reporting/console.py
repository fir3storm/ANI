"""Console reporting for AI Pentest Tool."""

from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.columns import Columns
from rich import box

from ..attacks.base import AttackResult, Severity

console = Console()


class ConsoleReporter:
    """Generates rich console output for test results."""
    
    # Severity colors
    SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "green",
    }
    
    # Severity icons
    SEVERITY_ICONS = {
        Severity.CRITICAL: "[X]",
        Severity.HIGH: "[!]",
        Severity.MEDIUM: "[*]",
        Severity.LOW: "[-]",
        Severity.INFO: "[i]",
    }
    
    def print_header(self, target_url: str, ai_model: str = None) -> None:
        """Print scan header."""
        header_text = Text()
        header_text.append("AI Siege - Autonomous AI Prompt Injection Pentest Tool", style="bold cyan")
        header_text.append("\n")
        header_text.append(f"Target: {target_url}", style="white")
        
        if ai_model:
            header_text.append(f"\nAI Model: {ai_model}", style="yellow")
        
        panel = Panel(
            header_text,
            title="[bold blue]Scan Configuration[/bold blue]",
            border_style="blue",
            padding=(1, 2),
        )
        console.print(panel)
        console.print()
    
    def print_progress(self, message: str) -> None:
        """Print progress message."""
        console.print(f"[cyan]>[/cyan] {message}")
    
    def print_attack_header(self, attack_name: str, num_payloads: int) -> None:
        """Print attack category header."""
        console.print()
        console.rule(f"[bold yellow]{attack_name}[/bold yellow] ({num_payloads} payloads)")
        console.print()
    
    def print_result(self, result: AttackResult) -> None:
        """Print single attack result."""
        severity = result.severity
        color = self.SEVERITY_COLORS.get(severity, "white")
        icon = self.SEVERITY_ICONS.get(severity, "")
        
        # Status line
        if result.vulnerable:
            status = f"[{color}]{icon} VULNERABLE[/{color}]"
        else:
            status = "[green][+] SECURE[/green]"
        
        console.print(f"  {status} {result.test_name}")
        
        # Show evidence if vulnerable
        if result.vulnerable and result.evidence:
            for evidence in result.evidence[:3]:
                console.print(f"    [dim]Evidence: {evidence}[/dim]")
    
    def print_summary(self, results: List[AttackResult]) -> None:
        """Print results summary."""
        console.print()
        console.rule("[bold]Scan Summary[/bold]")
        console.print()
        
        # Count by severity
        counts = {s: 0 for s in Severity}
        vulnerable_count = 0
        
        for result in results:
            if result.vulnerable:
                counts[result.severity] += 1
                vulnerable_count += 1
        
        # Create summary table
        table = Table(
            title="Vulnerability Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="center")
        table.add_column("Visual", no_wrap=True)
        
        # Add rows
        bar_width = 20
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = counts[severity]
            color = self.SEVERITY_COLORS[severity]
            bar_len = min(count * 4, bar_width)
            bar = "█" * bar_len + "░" * (bar_width - bar_len)
            
            table.add_row(
                f"[{color}]{severity.value}[/{color}]",
                str(count),
                f"[{color}]{bar}[/{color}]",
            )
        
        console.print(table)
        
        # Overall stats
        total = len(results)
        secure = total - vulnerable_count
        
        stats_text = Text()
        stats_text.append(f"\nTotal Tests: {total}", style="bold")
        stats_text.append(f"  |  Vulnerable: ", style="white")
        stats_text.append(f"{vulnerable_count}", style="bold red" if vulnerable_count > 0 else "bold green")
        stats_text.append(f"  |  Secure: ", style="white")
        stats_text.append(f"{secure}", style="bold green")
        
        console.print(stats_text)
        console.print()
    
    def print_vulnerabilities(self, results: List[AttackResult]) -> None:
        """Print detailed vulnerability information."""
        vulns = [r for r in results if r.vulnerable]
        
        if not vulns:
            console.print("[green]No vulnerabilities found![/green]")
            return
        
        console.rule("[bold red]Vulnerability Details[/bold red]")
        console.print()
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        vulns.sort(key=lambda x: severity_order.get(x.severity, 5))
        
        for i, vuln in enumerate(vulns, 1):
            color = self.SEVERITY_COLORS[vuln.severity]
            
            # Vulnerability panel
            title = f"[{color}][{vuln.severity.value}] {vuln.test_name}[/{color}]"
            
            content = Text()
            content.append(f"Test ID: {vuln.test_id}\n", style="dim")
            content.append(f"Category: {vuln.category}\n\n", style="dim")
            
            content.append("Payload:\n", style="bold")
            content.append(f"{vuln.payload[:200]}{'...' if len(vuln.payload) > 200 else ''}\n\n", style="red")
            
            content.append("Response:\n", style="bold")
            content.append(f"{vuln.response[:200]}{'...' if len(vuln.response) > 200 else ''}\n\n", style="yellow")
            
            if vuln.evidence:
                content.append("Evidence:\n", style="bold")
                for evidence in vuln.evidence:
                    content.append(f"  - {evidence}\n", style="cyan")
            
            if vuln.metadata.get("remediation"):
                content.append(f"\nRemediation:\n", style="bold")
                content.append(f"  {vuln.metadata['remediation']}\n", style="green")
            
            panel = Panel(
                content,
                title=title,
                border_style=color,
                padding=(1, 2),
            )
            console.print(panel)
            
            if i < len(vulns):
                console.print()
    
    def print_ai_model(self, model_info: Dict[str, Any]) -> None:
        """Print AI model identification results."""
        console.print()
        
        model_text = Text()
        model_text.append("AI Model Detected: ", style="bold")
        model_text.append(f"{model_info.get('name', 'Unknown')}", style="bold cyan")
        
        if model_info.get("provider"):
            model_text.append(f" ({model_info['provider']})", style="dim")
        
        if model_info.get("confidence"):
            confidence = model_info["confidence"]
            conf_color = "green" if confidence > 0.7 else "yellow" if confidence > 0.4 else "red"
            model_text.append(f"\nConfidence: ", style="bold")
            model_text.append(f"{confidence:.0%}", style=f"bold {conf_color}")
        
        panel = Panel(
            model_text,
            title="[bold blue]AI Model Identification[/bold blue]",
            border_style="blue",
        )
        console.print(panel)
        console.print()
    
    def print_error(self, message: str) -> None:
        """Print error message."""
        console.print(f"[bold red]ERROR:[/bold red] {message}")
    
    def print_warning(self, message: str) -> None:
        """Print warning message."""
        console.print(f"[yellow]WARNING:[/yellow] {message}")
    
    def print_success(self, message: str) -> None:
        """Print success message."""
        console.print(f"[green]SUCCESS:[/green] {message}")
    
    def print_info(self, message: str) -> None:
        """Print info message."""
        console.print(f"[cyan]INFO:[/cyan] {message}")
    
    def create_progress(self) -> Progress:
        """Create a progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        )
