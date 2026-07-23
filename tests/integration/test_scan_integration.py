from pathlib import Path

from app.config.container import Container


def test_scan_use_case_with_sample_data() -> None:
    rootfs_path = Path("sample_data") / "rootfs"
    container = Container()

    result = container.build_scan_use_case().execute(rootfs_path)

    names = {component.name for component in result.components}
    assert {"busybox", "openssl", "dropbear"}.issubset(names)
    assert len(result.vulnerabilities) >= 1
    assert result.risk_score in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
