from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.application.services.risk_engine import RiskWeights
from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.report_generator import ReportGenerator


class HtmlReportGenerator(ReportGenerator):
    """Generate HTML reports from scan results using Jinja2 templates."""

    def __init__(self, template_dir: Path, repository_url: str | None = None) -> None:
        self._environment = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self._repository_url = repository_url.rstrip("/") if repository_url else None
        self._risk_weights = RiskWeights()

    def generate(self, scan_result: ScanResult, output_path: Path) -> Path:
        template = self._environment.get_template("report.html.j2")
        rendered = template.render(
            scan_result=scan_result,
            risk_breakdown=self._risk_breakdown(scan_result),
            methodology_links=self._methodology_links(),
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return output_path

    def _risk_breakdown(self, scan_result: ScanResult) -> dict[str, Any]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total = 0
        for vulnerability in scan_result.vulnerabilities:
            severity = vulnerability.severity.upper()
            if severity not in counts:
                severity = "LOW"
            counts[severity] += 1
            total += self._severity_weight(severity)

        return {
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "total": total,
            "overall": scan_result.risk_score,
        }

    def _severity_weight(self, severity: str) -> int:
        if severity == "CRITICAL":
            return self._risk_weights.critical
        if severity == "HIGH":
            return self._risk_weights.high
        if severity == "MEDIUM":
            return self._risk_weights.medium
        return self._risk_weights.low

    def _methodology_links(self) -> list[dict[str, str | None]]:
        docs = [
            ("Risk scoring methodology", "docs/risk_scoring.md"),
            ("Vulnerability detection methodology", "docs/vulnerability_detection.md"),
            ("SBOM methodology", "docs/sbom.md"),
        ]
        links: list[dict[str, str | None]] = []
        for label, path in docs:
            links.append(
                {
                    "label": label,
                    "path": path,
                    "url": f"{self._repository_url}/{path}" if self._repository_url else None,
                }
            )
        return links
