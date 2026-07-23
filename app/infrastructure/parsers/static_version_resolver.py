from app.domain.interfaces.version_resolver import VersionResolver


class StaticVersionResolver(VersionResolver):
    """Phase 1 version resolver backed by static mapping."""

    def __init__(self, versions: dict[str, str] | None = None) -> None:
        self._versions = versions or {
            "openssl": "1.1.1d",
            "busybox": "1.31.1",
            "dropbear": "2020.81",
        }

    def resolve(self, component_name: str) -> str:
        return self._versions.get(component_name.lower(), "unknown")
