"""Report generation for ANI - Adversarial Neural Inspector."""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from ..attacks.base import AttackResult, Severity
from ..detection.vulnerability import VulnerabilityClassifier
from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger()


class ReportGenerator:
    """Generates HTML and JSON reports from scan results."""
    
    def __init__(self):
        self.config = get_config()
        self.classifier = VulnerabilityClassifier()
        self.template_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))
    
    def generate(
        self,
        results: List[AttackResult],
        target_url: str,
        ai_model: Dict[str, Any] = None,
        output_format: str = "html",
        output_path: Path = None,
    ) -> Path:
        """
        Generate report from scan results.
        
        Args:
            results: List of attack results
            target_url: Target URL scanned
            ai_model: AI model information
            output_format: Output format (html or json)
            output_path: Custom output path
        
        Returns:
            Path to generated report
        """
        if output_format == "html":
            return self._generate_html(results, target_url, ai_model, output_path)
        elif output_format == "json":
            return self._generate_json(results, target_url, ai_model, output_path)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def _generate_html(
        self,
        results: List[AttackResult],
        target_url: str,
        ai_model: Dict[str, Any] = None,
        output_path: Path = None,
    ) -> Path:
        """Generate HTML report."""
        template = self.env.get_template("report.html")
        
        # Calculate statistics
        stats = self._calculate_stats(results)
        
        # Prepare data for template
        vulns = [r for r in results if r.vulnerable]
        secure = [r for r in results if not r.vulnerable]
        
        # Sort vulnerabilities by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        vulns.sort(key=lambda x: severity_order.get(x.severity, 5))
        
        # Render template
        html_content = template.render(
            target_url=target_url,
            ai_model=ai_model or {"name": "Unknown", "confidence": 0},
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            stats=stats,
            vulnerabilities=[self._result_to_dict(r) for r in vulns],
            secure_tests=[self._result_to_dict(r) for r in secure],
            all_results=[self._result_to_dict(r) for r in results],
        )
        
        # Determine output path
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.config.reports_dir / f"ani_report_{timestamp}.html"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write report
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _generate_json(
        self,
        results: List[AttackResult],
        target_url: str,
        ai_model: Dict[str, Any] = None,
        output_path: Path = None,
    ) -> Path:
        """Generate JSON report."""
        stats = self._calculate_stats(results)
        
        report_data = {
            "metadata": {
                "tool": "ANI - Adversarial Neural Inspector",
                "version": "1.0.0",
                "target_url": target_url,
                "ai_model": ai_model,
                "scan_date": datetime.now().isoformat(),
            },
            "statistics": stats,
            "results": [self._result_to_dict(r) for r in results],
            "vulnerabilities": [self._result_to_dict(r) for r in results if r.vulnerable],
        }
        
        # Determine output path
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.config.reports_dir / f"ani_report_{timestamp}.json"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write report
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {output_path}")
        return output_path
    
    def _calculate_stats(self, results: List[AttackResult]) -> Dict[str, Any]:
        """Calculate scan statistics."""
        stats = {
            "total_tests": len(results),
            "vulnerable": 0,
            "secure": 0,
            "by_severity": {s.value: 0 for s in Severity},
            "by_category": {},
        }
        
        for result in results:
            if result.vulnerable:
                stats["vulnerable"] += 1
                stats["by_severity"][result.severity.value] += 1
            else:
                stats["secure"] += 1
            
            # Count by category
            category = result.category
            if category not in stats["by_category"]:
                stats["by_category"][category] = {"total": 0, "vulnerable": 0}
            stats["by_category"][category]["total"] += 1
            if result.vulnerable:
                stats["by_category"][category]["vulnerable"] += 1
        
        # Calculate risk score
        if stats["vulnerable"] > 0:
            risk_score = (
                stats["by_severity"].get("Critical", 0) * 10 +
                stats["by_severity"].get("High", 0) * 7 +
                stats["by_severity"].get("Medium", 0) * 4 +
                stats["by_severity"].get("Low", 0) * 2
            ) / stats["total_tests"]
            stats["risk_score"] = min(risk_score * 10, 100)
        else:
            stats["risk_score"] = 0
        
        return stats
    
    def _result_to_dict(self, result: AttackResult) -> Dict[str, Any]:
        """Convert AttackResult to dictionary."""
        return {
            "test_id": result.test_id,
            "test_name": result.test_name,
            "category": result.category,
            "payload": result.payload,
            "response": result.response,
            "vulnerable": result.vulnerable,
            "severity": result.severity.value,
            "evidence": result.evidence,
            "timestamp": result.timestamp.isoformat(),
            "metadata": result.metadata,
            "screenshot_path": result.screenshot_path,
        }
