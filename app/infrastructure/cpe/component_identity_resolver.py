"""Governed, exact-match upstream identity resolution."""

from app.domain.entities.component import Component
from app.domain.entities.identity_resolution import IdentityResolution


class ComponentIdentityResolver:
    _EXCLUDED = {"firewall", "fw3", "luci-app-firewall", "base-files"}
    _EXACT = {
        "busybox": ("busybox", "busybox", "cpe:2.3:a:busybox:busybox"),
        "dnsmasq": ("dnsmasq", "thekelleys", "cpe:2.3:a:thekelleys:dnsmasq"),
        "dropbear": (
            "dropbear_ssh",
            "dropbear_ssh_project",
            "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh",
        ),
    }

    def resolve(self, component: Component) -> IdentityResolution:
        name = component.name.lower()
        evidence = component.evidence
        if name in self._EXCLUDED or name.startswith("kmod-"):
            return IdentityResolution(
                None, None, (), "LOW", "exclude.framework", evidence, "excluded"
            )
        if name == "hostapd-common":
            return IdentityResolution(
                None, None, (), "LOW", "ambiguous.hostapd_split", evidence, "ambiguous"
            )
        if name == "wpad-basic":
            return IdentityResolution(
                None, None, (), "LOW", "ambiguous.bundled_wpad", evidence, "ambiguous"
            )
        if name == "kernel":
            return IdentityResolution(
                None, None, (), "LOW", "unsupported.kernel_context", evidence, "unsupported"
            )
        if name == "libc":
            return IdentityResolution(
                None,
                None,
                (),
                "LOW",
                "insufficient.libc_implementation",
                evidence,
                "insufficient_evidence",
            )
        if name == "uclient-fetch":
            return IdentityResolution(
                None, None, (), "LOW", "unsupported.uclient_fetch", evidence, "unsupported"
            )
        mapping = self._EXACT.get(name)
        if mapping:
            product, vendor, cpe = mapping
            return IdentityResolution(
                product, vendor, (cpe,), "HIGH", "exact.package_or_binary", evidence, "resolved"
            )
        if component.cpe_candidates:
            return IdentityResolution(
                None, None, component.cpe_candidates, "MEDIUM", "existing.cpe", evidence, "resolved"
            )
        return IdentityResolution(
            None, None, (), "LOW", "insufficient.no_exact_rule", evidence, "insufficient_evidence"
        )
