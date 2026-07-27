from app.domain.entities.component import Component


class CpeResolver:
    """Deterministic CPE mappings; unmapped software is intentionally left unresolved."""

    _mappings = {
        "busybox": ("cpe:2.3:a:busybox:busybox",),
        "openssl": ("cpe:2.3:a:openssl:openssl",),
        "dropbear": ("cpe:2.3:a:dropbear_ssh_project:dropbear_ssh",),
        "curl": ("cpe:2.3:a:haxx:curl",),
        "dnsmasq": ("cpe:2.3:a:thekelleys:dnsmasq",),
        "nginx": ("cpe:2.3:a:f5:nginx",),
        "lighttpd": ("cpe:2.3:a:lighttpd:lighttpd",),
        "hostapd": ("cpe:2.3:a:w1.fi:hostapd",),
        "musl": ("cpe:2.3:a:musl-libc:musl",),
        "glibc": ("cpe:2.3:a:gnu:glibc",),
    }

    def resolve(self, component: Component) -> Component:
        candidates = self._mappings.get(component.name.lower(), ())
        return Component(
            name=component.name,
            version=component.version,
            evidence=component.evidence,
            confidence=component.confidence,
            component_type=component.component_type,
            architecture=component.architecture,
            dependencies=component.dependencies,
            metadata=component.metadata,
            cpe=candidates[0] if candidates else None,
            cpe_candidates=candidates,
            cpe_confidence="HIGH" if len(candidates) == 1 else "LOW",
        )
