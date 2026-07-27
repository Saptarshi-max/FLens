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
            inventory=self._inventory(scan_result),
            identity=self._identity(scan_result),
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

    @staticmethod
    def _inventory(scan_result: ScanResult) -> dict[str, Any] | None:
        stats = scan_result.inventory_statistics
        if stats is None:
            return None
        total = stats.merged_components
        return {
            "stats": stats,
            "version_coverage": stats.components_with_known_versions / total if total else 0,
            "cpe_coverage": stats.components_with_cpe_candidates / total if total else 0,
            "diagnostics": scan_result.inventory_diagnostics[:20],
            "busybox": next((c for c in scan_result.components if c.name == "busybox"), None),
        }

    @classmethod
    def _identity(cls, scan_result: ScanResult) -> dict[str, Any] | None:
        stats = scan_result.identity_statistics
        if stats is None:
            return None
        # Surface review-worthy records first, then compatibility fallback and
        # governed mappings, with intentional exclusions last. Name/version
        # tie-breakers make the presentation independent of discovery order.
        status_priority = {
            "ambiguous": 0,
            "unsupported": 1,
            "insufficient_evidence": 2,
            "excluded": 5,
        }
        sortable_records: list[tuple[int, int, str, str, dict[str, Any]]] = []
        for component in scan_result.components:
            resolution = component.identity_resolution
            if resolution is None:
                continue
            priority = status_priority.get(resolution.resolution_status)
            if priority is None:
                priority = 3 if component.cpe_source == "legacy" else 4
            record = {
                "name": component.name,
                "version": component.version,
                "canonical_vendor": resolution.canonical_vendor,
                "canonical_product": resolution.canonical_product,
                "status": resolution.resolution_status,
                "confidence": resolution.confidence,
                "rule_id": resolution.rule_id,
                "cpe_source": component.cpe_source,
                "governed_cpes": resolution.cpe_candidates[: cls.MAX_IDENTITY_CPES],
                "omitted_cpes": max(0, len(resolution.cpe_candidates) - cls.MAX_IDENTITY_CPES),
                "evidence": resolution.evidence[: cls.MAX_IDENTITY_EVIDENCE],
                "omitted_evidence": max(
                    0, len(resolution.evidence) - cls.MAX_IDENTITY_EVIDENCE
                ),
            }
            sortable_records.append(
                (
                    priority,
                    0,
                    component.name,
                    component.version,
                    record,
                )
            )
        sortable_records.sort(key=lambda item: item[:4])
        records = [item[4] for item in sortable_records[: cls.MAX_IDENTITY_ROWS]]
        return {
            "stats": stats,
            "coverage": stats.governed_cpe_components / stats.status_total
            if stats.status_total
            else 0,
            "records": records,
            "omitted": max(0, len(sortable_records) - cls.MAX_IDENTITY_ROWS),
        }

    MAX_IDENTITY_ROWS = 20
    MAX_IDENTITY_EVIDENCE = 3
    MAX_IDENTITY_CPES = 3
