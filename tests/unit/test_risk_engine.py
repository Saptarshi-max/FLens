from app.application.services.risk_engine import RiskEngine
from app.domain.entities.vulnerability import Vulnerability


def test_risk_engine_low_risk() -> None:
    engine = RiskEngine()
    vulnerabilities = [
        Vulnerability(cve_id="CVE-1", severity="LOW", description="low"),
    ]

    assert engine.score(vulnerabilities).value == "LOW"


def test_risk_engine_medium_risk() -> None:
    engine = RiskEngine()
    vulnerabilities = [
        Vulnerability(cve_id="CVE-1", severity="MEDIUM", description="medium"),
    ]

    assert engine.score(vulnerabilities).value == "MEDIUM"


def test_risk_engine_high_risk() -> None:
    engine = RiskEngine()
    vulnerabilities = [
        Vulnerability(cve_id="CVE-1", severity="HIGH", description="high"),
        Vulnerability(cve_id="CVE-2", severity="LOW", description="low"),
        Vulnerability(cve_id="CVE-3", severity="LOW", description="low"),
        Vulnerability(cve_id="CVE-4", severity="LOW", description="low"),
    ]

    assert engine.score(vulnerabilities).value == "HIGH"


def test_risk_engine_critical_risk() -> None:
    engine = RiskEngine()
    vulnerabilities = [
        Vulnerability(cve_id="CVE-1", severity="CRITICAL", description="critical"),
        Vulnerability(cve_id="CVE-2", severity="CRITICAL", description="critical"),
    ]

    assert engine.score(vulnerabilities).value == "CRITICAL"


def test_risk_engine_empty_vulnerability_list() -> None:
    engine = RiskEngine()

    assert engine.score([]).value == "LOW"
