from types import SimpleNamespace
from typing import cast

from elftools.elf.dynamic import DynamicSection, DynamicTag

from app.infrastructure.elf.inventory_scanner import (
    ElfInventoryScanner,
    _get_dynamic_string_table,
)


class _Strings:
    def get_string(self, offset: int) -> str:
        return {7: "libssl.so.1.1"}[offset]


def _section(value: object) -> DynamicSection:
    return cast(DynamicSection, SimpleNamespace(stringtable=value))


def _tag(value: object) -> DynamicTag:
    return cast(DynamicTag, SimpleNamespace(entry={"d_val": value}))


def test_dynamic_string_table_resolves_valid_lookup() -> None:
    section = _section(_Strings())

    assert _get_dynamic_string_table(section) is not None
    assert ElfInventoryScanner._dynamic_string(section, _tag(7)) == "libssl.so.1.1"


def test_dynamic_string_table_missing_or_not_callable() -> None:
    missing = cast(DynamicSection, SimpleNamespace())
    invalid = _section(SimpleNamespace(get_string="not-callable"))

    assert _get_dynamic_string_table(missing) is None
    assert _get_dynamic_string_table(invalid) is None


def test_dynamic_string_rejects_invalid_offset_and_values() -> None:
    section = _section(_Strings())

    assert ElfInventoryScanner._dynamic_string(section, _tag("7")) is None
    non_string_table = _section(SimpleNamespace(get_string=lambda _: 3))
    assert ElfInventoryScanner._dynamic_string(non_string_table, _tag(7)) is None


def test_dynamic_string_swallows_lookup_error() -> None:
    class _Broken:
        def get_string(self, offset: int) -> str:
            raise ValueError(f"bad offset {offset}")

    assert ElfInventoryScanner._dynamic_string(_section(_Broken()), _tag(7)) is None
