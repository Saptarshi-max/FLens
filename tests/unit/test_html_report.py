from pathlib import Path

from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence
from app.domain.entities.identity_resolution import IdentityResolution
from app.domain.entities.identity_statistics import IdentityStatistics
from app.domain.entities.inventory import InventoryStatistics
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.presentation.reports.html_report_generator import HtmlReportGenerator


def _identity(
    status: str,
    *,
    product: str | None = None,
    vendor: str | None = None,
    cpes: tuple[str, ...] = (),
    evidence: tuple[Evidence, ...] = (),
) -> IdentityResolution:
    return IdentityResolution(
        canonical_product=product,
        canonical_vendor=vendor,
        cpe_candidates=cpes,
        confidence="HIGH",
        rule_id=f"test.{status}",
        evidence=evidence,
        resolution_status=status,
    )


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
    assert "Identity Resolution" not in html


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


def test_html_report_renders_inventory_coverage(tmp_path: Path) -> None:
    template_dir = Path(__file__).resolve().parents[2] / "app/presentation/reports/templates"
    result = ScanResult(
        components=(Component(name="busybox", metadata=(("applet", "ash"),)),),
        vulnerabilities=(), risk_score="LOW",
        inventory_statistics=InventoryStatistics(
            merged_components=1, components_with_known_versions=0,
            components_with_cpe_candidates=0, extraction_placeholder_entries=2,
            open_read_failures=1, elf_discovery_limit_reached=True,
        ),
        inventory_diagnostics=(
            ("/bin/ash", "WindowsReparsePoint", "invalid-path-or-extraction-representation"),
        ),
    )
    report = HtmlReportGenerator(template_dir).generate(result, tmp_path / "coverage.html")
    html = report.read_text(encoding="utf-8")
    assert "Inventory Coverage and Scan Diagnostics" in html
    assert "Version coverage: 0%" in html
    assert "Extraction placeholders: 2" in html
    assert "Open/read failures: 1" in html
    assert "ELF discovery limit reached" in html
    assert "Low version or CPE coverage" in html
    assert "BusyBox applets recognised: 1" in html


def test_html_report_renders_bounded_identity_resolution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = Path(__file__).resolve().parents[2] / "app/presentation/reports/templates"
    evidence = (
        Evidence("package", "/status", "first"),
        Evidence("banner", "/bin/busybox", "second"),
    )
    result = ScanResult(
        components=(
            Component(
                name="observed-busybox",
                version="1.36.0",
                cpe_source="governed",
                identity_resolution=_identity(
                    "resolved",
                    product="busybox",
                    vendor="busybox",
                    cpes=("cpe:one", "cpe:two"),
                    evidence=evidence,
                ),
            ),
            Component(
                name="legacy-observed",
                version="2.0",
                cpe="cpe:legacy",
                cpe_source="legacy",
                identity_resolution=_identity("insufficient_evidence"),
            ),
            Component(
                name="ambiguous-observed",
                cpe_source="none",
                identity_resolution=_identity("ambiguous"),
            ),
        ),
        vulnerabilities=(),
        risk_score="LOW",
        identity_statistics=IdentityStatistics(
            resolved=1,
            ambiguous=1,
            insufficient_evidence=1,
            governed_cpe_components=1,
            legacy_cpe_components=1,
            no_cpe_components=1,
        ),
    )
    monkeypatch.setattr(HtmlReportGenerator, "MAX_IDENTITY_EVIDENCE", 1)
    monkeypatch.setattr(HtmlReportGenerator, "MAX_IDENTITY_CPES", 1)
    generator = HtmlReportGenerator(template_dir)
    report = generator.generate(result, tmp_path / "identity.html")
    html = report.read_text(encoding="utf-8")

    assert "Identity Resolution" in html
    assert "Governed CPE components: 1 (33%)" in html
    assert "observed-busybox 1.36.0" in html
    assert "busybox / busybox" in html
    assert "legacy (legacy fallback)" in html
    assert "governed" in html
    assert "none" in html
    assert "ambiguous-observed" in html
    assert html.index("ambiguous-observed") < html.index("legacy-observed")
    assert "1 CPE candidates omitted." in html
    assert "1 evidence items omitted." in html
    assert "none" in html
    assert "Ambiguous identities require manual review." in html
    assert "Insufficient evidence prevents safe canonical mapping." in html
    assert "Legacy CPE fallback is ungoverned compatibility behaviour." in html
    assert "Low governed-CPE coverage limits vulnerability-assessment confidence." in html
    assert "Excluded components are intentionally omitted" in html


def test_html_report_caps_identity_rows_and_handles_zero_coverage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = Path(__file__).resolve().parents[2] / "app/presentation/reports/templates"
    result = ScanResult(
        components=(
            Component("first", identity_resolution=_identity("unsupported")),
            Component("second", identity_resolution=_identity("excluded")),
        ),
        vulnerabilities=(),
        risk_score="LOW",
        identity_statistics=IdentityStatistics(
            unsupported=1,
            excluded=1,
            no_cpe_components=2,
        ),
    )
    monkeypatch.setattr(HtmlReportGenerator, "MAX_IDENTITY_ROWS", 1)
    generator = HtmlReportGenerator(template_dir)
    report = generator.generate(result, tmp_path / "identity_cap.html")
    html = report.read_text(encoding="utf-8")

    assert "Governed CPE components: 0 (0%)" in html
    assert "first Unknown" in html
    assert "excluded / test.excluded" not in html
    assert "1 identity records omitted by the report limit." in html
    assert "Unsupported identities are outside the current resolver policy." in html
