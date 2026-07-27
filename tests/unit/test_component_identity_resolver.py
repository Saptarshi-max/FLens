from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence
from app.infrastructure.cpe.component_identity_resolver import ComponentIdentityResolver


def test_exact_mapping_retains_evidence() -> None:
    evidence = Evidence("opkg", "/status", "Package: busybox")
    result = ComponentIdentityResolver().resolve(Component("busybox", evidence=(evidence,)))
    assert result.resolution_status == "resolved"
    assert result.cpe_candidates == ("cpe:2.3:a:busybox:busybox",)
    assert result.evidence == (evidence,)


def test_conservative_rejections_and_no_prefix_matching() -> None:
    resolver = ComponentIdentityResolver()
    assert resolver.resolve(Component("hostapd-common")).resolution_status == "ambiguous"
    assert resolver.resolve(Component("uclient-fetch")).resolution_status == "unsupported"
    assert resolver.resolve(Component("dropbearmulti")).resolution_status == "insufficient_evidence"
    assert resolver.resolve(Component("openssl")).resolution_status == "insufficient_evidence"
    assert resolver.resolve(Component("firewall")).resolution_status == "excluded"


def test_resolution_is_deterministic_and_preserves_existing_cpe() -> None:
    resolver = ComponentIdentityResolver()
    component = Component("custom", cpe_candidates=("cpe:2.3:a:vendor:custom",))
    assert resolver.resolve(component) == resolver.resolve(component)
    assert resolver.resolve(component).cpe_candidates == component.cpe_candidates
