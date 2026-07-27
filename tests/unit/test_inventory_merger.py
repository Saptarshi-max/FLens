from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence
from app.infrastructure.inventory.inventory_merger import InventoryMerger


def _component(
    name: str,
    version: str = "Unknown",
    *,
    component_type: str = "application",
    evidence_path: str = "/rootfs/bin/example",
    dependencies: tuple[str, ...] = (),
    architecture: str = "Unknown",
    metadata: tuple[tuple[str, str], ...] = (),
) -> Component:
    return Component(
        name=name,
        version=version,
        component_type=component_type,
        confidence="HIGH" if component_type == "package" else "MEDIUM",
        evidence=(Evidence(component_type, evidence_path, name),),
        dependencies=dependencies,
        architecture=architecture,
        metadata=metadata,
    )


def test_identical_package_and_elf_components_merge_with_package_version() -> None:
    result = InventoryMerger().merge(
        [
            _component("busybox", "1.01", component_type="package"),
            _component(
                "busybox", "1.35.0", component_type="executable", evidence_path="/bin/busybox"
            ),
        ]
    )

    assert len(result) == 1
    assert result[0].version == "1.01"
    assert result[0].confidence == "HIGH"
    assert set(result[0].metadata) >= {
        ("observed_version", "1.01"),
        ("observed_version", "1.35.0"),
    }


def test_known_version_replaces_unknown_and_retains_evidence_paths_and_dependencies() -> None:
    result = InventoryMerger().merge(
        [
            _component(
                "busybox",
                evidence_path="/bin/busybox",
                dependencies=("libc.so.0",),
            ),
            _component(
                "busybox",
                "1.35.0",
                evidence_path="/usr/bin/busybox",
                dependencies=("libgcc_s.so.1", "libc.so.0"),
            ),
        ]
    )

    component = result[0]
    assert component.version == "1.35.0"
    assert {evidence.path for evidence in component.evidence} == {
        "/bin/busybox",
        "/usr/bin/busybox",
    }
    assert component.dependencies == ("libc.so.0", "libgcc_s.so.1")


def test_duplicate_evidence_is_retained_once() -> None:
    discovery = _component("busybox", "1.35.0")

    result = InventoryMerger().merge([discovery, discovery])

    assert len(result[0].evidence) == 1


def test_library_identity_is_stable_but_abi_specific() -> None:
    merger = InventoryMerger()
    first = _component(
        "/usr/lib/libssl.so.1.1",
        component_type="library",
        metadata=(("soname", "libssl.so.1.1"),),
    )
    same = _component("LIBSSL.SO.1.1", component_type="library")
    newer = _component("libssl.so.3", component_type="library")

    assert merger.identity(first) == "library:libssl.so.1.1"
    assert merger.identity(first) == merger.identity(same)
    result = merger.merge([first, same, newer])

    assert [component.name.lower() for component in result] == [
        "/usr/lib/libssl.so.1.1",
        "libssl.so.3",
    ]
    assert ("soname", "libssl.so.1.1") in result[0].metadata


def test_unrelated_prefixes_are_not_merged() -> None:
    result = InventoryMerger().merge(
        [
            _component("openssl"),
            _component("libssl.so.1.1", component_type="library"),
            _component("dropbear"),
            _component("dropbearmulti"),
        ]
    )

    assert {component.name for component in result} == {
        "openssl",
        "libssl.so.1.1",
        "dropbear",
        "dropbearmulti",
    }


def test_merge_is_deterministic_regardless_of_input_order() -> None:
    components = [
        _component(
            "busybox",
            "1.35.0",
            evidence_path="/bin/busybox",
            architecture="EM_MIPS",
            metadata=(("soname", "busybox"),),
        ),
        _component(
            "busybox",
            "1.01",
            component_type="package",
            evidence_path="/usr/lib/opkg/status",
            architecture="mipsel",
        ),
    ]

    assert InventoryMerger().merge(components) == InventoryMerger().merge(
        list(reversed(components))
    )
