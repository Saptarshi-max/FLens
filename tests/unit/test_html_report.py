from pathlib import Path

from app.domain.entities.component import Component
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.presentation.reports.html_report_generator import HtmlReportGenerator


def test_html_report_contains_component_cve_and_risk(tmp_path: Path) -> None:
    template_dir = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "presentation"
        / "reports"
        / "templates"
    )
    generator = HtmlReportGenerator(template_dir)

    result = ScanResult(
        components=(Component(name="openssl", version="1.1.1d"),),
        vulnerabilities=(
            Vulnerability(
                cve_id="CVE-2022-0778",
                severity="HIGH",
                description="Test CVE",
            ),
        ),
        risk_score="HIGH",
    )

    report_path = generator.generate(result, tmp_path / "report.html")
    html = report_path.read_text(encoding="utf-8")

    assert "openssl" in html
    assert "CVE-2022-0778" in html
    assert "Risk Score: HIGH" in html
