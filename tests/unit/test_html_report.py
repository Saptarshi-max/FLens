from pathlib import Path

from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.presentation.reports.html_report_generator import HtmlReportGenerator


def test_html_report_contains_component_cve_and_risk(tmp_path: Path) -> None:
    template_dir = (
        Path(__file__).resolve().parents[2] / "app" / "presentation" / "reports" / "templates"
    )
    generator = HtmlReportGenerator(template_dir)

    result = ScanResult(
        components=(
            Component(
                name="openssl",
                version="1.1.1d",
                confidence="HIGH",
                evidence=(Evidence("opkg", "/usr/lib/opkg/status", "Package metadata"),),
            ),
        ),
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
    assert "Package metadata" in html
    assert "CVE-2022-0778" in html
    assert "Risk Score: HIGH" in html
    assert "Transparency &amp; Methodology" in html
    assert "Risk Score Breakdown" in html
    assert "Calculated Score: 7" in html
    assert "Disclaimer" in html
    assert "docs/risk_scoring.md" in html


def test_html_report_renders_clickable_methodology_links_with_repository_url(
    tmp_path: Path,
) -> None:
    template_dir = (
        Path(__file__).resolve().parents[2] / "app" / "presentation" / "reports" / "templates"
    )
    generator = HtmlReportGenerator(template_dir, repository_url="https://github.com/acme/flens")

    result = ScanResult(
        components=(Component(name="busybox", version="1.31.1"),),
        vulnerabilities=(),
        risk_score="LOW",
    )

    report_path = generator.generate(result, tmp_path / "report_links.html")
    html = report_path.read_text(encoding="utf-8")

    assert "https://github.com/acme/flens/docs/risk_scoring.md" in html
    assert "https://github.com/acme/flens/docs/vulnerability_detection.md" in html
    assert "https://github.com/acme/flens/docs/sbom.md" in html
