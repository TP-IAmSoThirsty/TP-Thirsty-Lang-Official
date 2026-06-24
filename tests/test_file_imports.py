"""Tests for `.thirsty` file imports via module_system.resolve_import."""
import pytest

from utf.thirsty_lang import module_system
from utf.thirsty_lang.module_system import resolve_import

LIB = """module lib: core

glass double(x) {
    return x * 2
}

drink answer = 42
"""


@pytest.fixture(autouse=True)
def clear_cache():
    module_system.ModuleCache.clear()
    yield
    module_system.ModuleCache.clear()


def test_file_import_exposes_functions_and_values(tmp_path):
    lib = tmp_path / "lib.thirsty"
    lib.write_text(LIB)
    module = resolve_import(str(lib))
    assert callable(module["double"])
    assert module["double"](21) == 42
    assert module["answer"] == 42
    # Builtins must not leak into the module namespace.
    assert "length" not in module
    assert "pour" not in module


def test_file_import_is_cached(tmp_path):
    lib = tmp_path / "lib.thirsty"
    lib.write_text(LIB)
    first = resolve_import(str(lib))
    second = resolve_import(str(lib))
    assert first is second
    assert str(lib) in module_system.ModuleCache


def test_file_import_missing_file():
    with pytest.raises(ImportError, match="File not found"):
        resolve_import("does_not_exist.thirsty")


def test_file_import_parse_error(tmp_path):
    bad = tmp_path / "bad.thirsty"
    bad.write_text("module bad: core\nglass f( {\n")  # malformed params
    with pytest.raises(ImportError, match="Failed to import"):
        resolve_import(str(bad))


def test_non_thirsty_unknown_module():
    with pytest.raises(ImportError, match="Module not found"):
        resolve_import("some_random_thing")
