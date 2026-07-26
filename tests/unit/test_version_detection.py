from pathlib import Path

from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver


def test_extracts_version_from_opkg_status(tmp_path: Path) -> None:
    status = tmp_path / "usr" / "lib" / "opkg" / "status"
    status.parent.mkdir(parents=True)
    status.write_text("Package: busybox\nVersion: 1.36.1-2\n", encoding="utf-8")

    result = FirmwareVersionResolver().resolve("busybox", tmp_path, ())

    assert result.version == "1.36.1-2"
    assert result.confidence == "HIGH"
    assert result.evidence[0].source == "opkg"


def test_extracts_version_from_binary_banner(tmp_path: Path) -> None:
    binary = tmp_path / "openssl"
    binary.write_text("OpenSSL 3.0.13", encoding="utf-8")

    result = FirmwareVersionResolver().resolve("openssl", tmp_path, (binary,))

    assert result.version == "3.0.13"
    assert result.confidence == "MEDIUM"


def test_unknown_when_no_evidence(tmp_path: Path) -> None:
    result = FirmwareVersionResolver().resolve("dropbear", tmp_path, ())

    assert result.version == "Unknown"


def test_extracts_versions_from_dpkg_and_apk(tmp_path: Path) -> None:
    dpkg = tmp_path / "var" / "lib" / "dpkg" / "status"
    apk = tmp_path / "lib" / "apk" / "db" / "installed"
    dpkg.parent.mkdir(parents=True)
    apk.parent.mkdir(parents=True)
    dpkg.write_text("Package: openssl\nVersion: 3.2.1-1\n", encoding="utf-8")
    apk.write_text("P:dropbear\nV:2024.86-r0\n", encoding="utf-8")
    resolver = FirmwareVersionResolver()

    assert resolver.resolve("openssl", tmp_path, ()).version == "3.2.1-1"
    assert resolver.resolve("dropbear", tmp_path, ()).version == "2024.86-r0"
