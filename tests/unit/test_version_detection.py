from app.infrastructure.parsers.static_version_resolver import StaticVersionResolver


def test_known_version() -> None:
    resolver = StaticVersionResolver({"openssl": "1.1.1d"})

    assert resolver.resolve("openssl") == "1.1.1d"


def test_unknown_component() -> None:
    resolver = StaticVersionResolver({"openssl": "1.1.1d"})

    assert resolver.resolve("not-real") == "unknown"
