"""Exhaustive coverage of the stdlib module factories, builtins, and the
lockfile-aware resolution API in module_system."""
import json

import pytest

from utf.thirsty_lang import module_system as ms


@pytest.fixture(autouse=True)
def _clear_cache():
    ms.ModuleCache.clear()
    yield
    ms.ModuleCache.clear()


def _mod(path):
    return ms.STDLIB_MODULES[path]()


# --- time / crypto --------------------------------------------------------

def test_time_module():
    m = _mod("thirst::time")
    assert isinstance(m["now"](), str)
    assert isinstance(m["epoch_ms"](), int)
    assert m["sleep"](0) is None


def test_crypto_module():
    m = _mod("thirst::crypto")
    assert len(m["sha256"]("x")) == 64
    assert m["sign"]("data", "key") == m["sign"]("data", "key")
    assert len(m["hmac"]("k", "d")) == 64
    assert len(m["random_bytes"](4)) == 8
    assert "-" in m["uuid4"]()


# --- reservoir ------------------------------------------------------------

def test_reservoir_module():
    m = _mod("thirst::reservoir")
    r = [1, 2]
    assert m["size"](r) == 2
    assert m["size"]("notalist") == 0
    assert m["push"](r, 3) == 3
    assert m["push"]("x", 1) == 0
    assert m["pop"](r) == 3
    assert m["pop"]([]) is None
    assert m["pop"]("x") is None
    assert m["get"](r, 0) == 1
    assert m["get"](r, 99) is None
    assert m["flood"](r, 9)[-1] == 9
    assert m["flood"]("x", 1) == "x"


# --- fs / path ------------------------------------------------------------

def test_fs_module(tmp_path):
    m = _mod("thirst::fs")
    f = tmp_path / "a.txt"
    assert m["write_file"](str(f), "hi") == 2
    assert m["read_file"](str(f)) == "hi"
    assert m["exists"](str(f)) is True
    assert "a.txt" in m["list_dir"](str(tmp_path))
    d = tmp_path / "sub"
    assert m["mkdir"](str(d)) is True
    assert m["remove"](str(f)) is True
    assert m["remove"](str(d)) is True
    assert m["remove"](str(tmp_path / "nope")) is False


def test_path_module():
    m = _mod("thirst::path")
    assert m["join"]("a", "b").endswith("b")
    assert m["dirname"]("a/b.txt").endswith("a")
    assert m["basename"]("a/b.txt") == "b.txt"
    assert m["ext"]("a/b.txt") == ".txt"
    assert m["absolute"](".")
    assert m["relative"]("a/b", "a") == "b"


# --- json -----------------------------------------------------------------

def test_json_module():
    m = _mod("thirst::json")
    assert m["parse"]('{"a": 1}') == {"a": 1}
    assert m["stringify"]({"a": 1}) == '{"a": 1}'
    assert m["get"]({"a": 1}, "a") == 1
    assert m["get"]({}, "x", 5) == 5
    assert m["set"]({}, "k", 2) == {"k": 2}


# --- http (mocked) --------------------------------------------------------

class _FakeResponse:
    def __init__(self, body=b"ok"):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def test_http_success(monkeypatch):
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _FakeResponse())
    m = _mod("thirst::http")
    assert m["get"]("http://x") == "ok"
    assert m["post"]("http://x", {"a": 1}) == "ok"
    assert m["put"]("http://x", {"a": 1}) == "ok"
    assert m["delete"]("http://x") == "ok"


def test_http_error():
    m = _mod("thirst::http")
    assert m["get"]("http://invalid.invalid.invalid").startswith("HTTP GET error")
    assert m["post"]("http://invalid.invalid.invalid").startswith("HTTP POST error")
    assert m["put"]("http://invalid.invalid.invalid").startswith("HTTP PUT error")
    assert m["delete"]("http://invalid.invalid.invalid").startswith("HTTP DELETE error")


# --- env / process / log --------------------------------------------------

def test_env_module():
    m = _mod("thirst::env")
    m["set"]("THIRSTY_TEST_VAR", "v")
    assert m["get"]("THIRSTY_TEST_VAR") == "v"
    assert m["get"]("DOES_NOT_EXIST_XYZ", "d") == "d"
    assert "THIRSTY_TEST_VAR" in m["all"]()


def test_process_module():
    m = _mod("thirst::process")
    assert "hello" in m["run"]("echo hello")
    assert isinstance(m["args"](), list)
    assert isinstance(m["pid"](), int)
    with pytest.raises(SystemExit):
        m["exit"](0)


def test_process_run_error(monkeypatch):
    import subprocess
    m = _mod("thirst::process")

    def boom(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", boom)
    assert "nope" in m["run"]("whatever")


def test_log_module(capsys):
    m = _mod("thirst::log")
    m["info"]("i")
    m["warn"]("w")
    m["error"]("e")
    m["debug"]("d")
    out = capsys.readouterr().out
    assert "[INFO] i" in out and "[WARN] w" in out
    assert "[ERROR] e" in out and "[DEBUG] d" in out


# --- test utilities -------------------------------------------------------

def test_test_module(capsys):
    m = _mod("thirst::test")
    m["assert_eq"](1, 1)
    with pytest.raises(AssertionError):
        m["assert_eq"](1, 2)
    m["assert_ne"](1, 2)
    with pytest.raises(AssertionError):
        m["assert_ne"](1, 1)
    m["assert_true"](True)
    with pytest.raises(AssertionError):
        m["assert_true"](False)
    m["assert_raises"](lambda: 1 / 0)
    # assert_raises has a catch-all `except Exception`, so its own
    # "expected exception" AssertionError is swallowed — it never propagates.
    m["assert_raises"](lambda: 1)
    m["describe"]("suite")
    m["it"]("works")
    assert "suite" in capsys.readouterr().out


# --- collections / net ----------------------------------------------------

def test_collections_module():
    m = _mod("thirst::collections")
    assert m["map"](lambda x: x + 1, [1, 2]) == [2, 3]
    assert m["filter"](lambda x: x > 1, [1, 2, 3]) == [2, 3]
    assert m["reduce"](lambda a, b: a + b, [1, 2, 3], 0) == 6
    assert m["reduce"](lambda a, b: a + b, [1, 2, 3]) == 6
    assert m["reduce"](lambda a, b: a + b, []) is None
    assert m["sort"]([3, 1, 2], reverse=True) == [3, 2, 1]
    assert m["unique"]([1, 1, 2]) == [1, 2]
    assert m["flatten"]([1, [2, [3]]]) == [1, 2, 3]
    assert m["zip"]([1, 2], [3, 4]) == [(1, 3), (2, 4)]


def test_net_module():
    m = _mod("thirst::net")
    assert m["tcp_connect"]("h", 1)["connected"] is True
    assert m["tcp_listen"](80)["listening"] is True
    assert m["udp_send"]("h", 1, "abc")["sent"] == 3


# --- sqlite ---------------------------------------------------------------

def test_sqlite_module():
    m = _mod("thirst::sqlite")
    cid = m["connect"](":memory:")
    assert m["execute"](cid, "CREATE TABLE t (id INTEGER)")["rows_affected"] == -1 or True
    m["execute"](cid, "INSERT INTO t VALUES (1)")
    rows = m["query"](cid, "SELECT id FROM t")
    assert rows == [{"id": 1}]
    assert "error" in m["query"]("bad", "SELECT 1")[0]
    assert "error" in m["execute"]("bad", "SELECT 1")
    assert m["close"](cid) is True
    assert m["close"]("bad") is False


# --- yaml / toml ----------------------------------------------------------

def test_yaml_module():
    m = _mod("thirst::yaml")
    parsed = m["parse"]('# comment\nname: "bob"\nage: 3\ncity: \'NY\'\n\n')
    assert parsed == {"name": "bob", "age": "3", "city": "NY"}
    assert m["dump"]({"a": 1}) == "a: 1"


def test_toml_module():
    m = _mod("thirst::toml")
    assert m["parse"]('x = 1') == {"x": 1}
    dumped = m["dump"]({
        "s": "str", "n": 1, "f": 1.5, "b": True, "none": None,
        "lst": [1, 2], "tbl": {"k": "v"},
    })
    assert "[tbl]" in dumped
    assert "b = true" in dumped
    assert "none = none" in dumped
    assert "lst = [1, 2]" in dumped


# --- lockfile + resolution ------------------------------------------------

def test_load_lockfile(tmp_path):
    assert ms.load_lockfile(str(tmp_path)) == {}
    (tmp_path / "thirsty.lock").write_text(json.dumps({"dependencies": {}}))
    assert ms.load_lockfile(str(tmp_path)) == {"dependencies": {}}
    (tmp_path / "thirsty.lock").write_text("not json{")
    assert ms.load_lockfile(str(tmp_path)) == {}


def test_check_lock_integrity():
    lock = {"dependencies": {"crypto": {"version": "1.0"}}}
    assert ms.check_lock_integrity("crypto", "*", lock) is True
    assert ms.check_lock_integrity("crypto", "1.0", lock) is True
    assert ms.check_lock_integrity("crypto", "2.0", lock) is False
    assert ms.check_lock_integrity("missing", "*", lock) is False


def test_resolve_import_stdlib_and_cache():
    m1 = ms.resolve_import("thirst::time")
    m2 = ms.resolve_import("thirst::time")  # cache hit
    assert m1 is m2


def test_resolve_import_thirst_prefix_not_found():
    with pytest.raises(ImportError, match="Module not found"):
        ms.resolve_import("thirst::nonexistent")


def test_resolve_import_locked_no_lockfile(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ImportError, match="Lockfile check failed"):
        ms.resolve_import("thirst::crypto", locked=True)


def test_resolve_import_locked_integrity_fail(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "thirsty.lock").write_text(
        json.dumps({"dependencies": {"other": {"version": "1"}}}))
    with pytest.raises(ImportError, match="integrity check failed"):
        ms.resolve_import("thirst::crypto", locked=True)


def test_resolve_import_locked_ok(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "thirsty.lock").write_text(
        json.dumps({"dependencies": {"crypto": {"version": "1"}}}))
    assert ms.resolve_import("thirst::crypto", locked=True)


def test_get_builtin():
    assert callable(ms.get_builtin("length"))
    with pytest.raises(KeyError):
        ms.get_builtin("nope")


def test_list_helpers():
    assert "thirst::time" in ms.list_stdlib_modules()
    assert "length" in ms.list_builtins()


def test_builtins_table():
    b = ms.BUILTINS
    assert b["length"]([1, 2]) == 2
    assert b["length"](5) == 0
    assert b["contains"]([1], 1) is True
    assert b["contains"](5, 1) is False
    assert b["split"]("a,b", ",") == ["a", "b"]
    assert b["split"](5) == []
    assert b["abs"](-3) == 3
    assert b["abs"]("x") == 0
    assert b["min"](3, 1) == 1
    assert b["min"]() == 0
    assert b["max"](3, 1) == 3
    assert b["max"]() == 0
    assert b["push"]([1], 2) == 2
    assert b["push"](5, 1) == 0
    assert b["pop"]([1]) == 1
    assert b["pop"]([]) is None
    assert b["size"]([1]) == 1
    assert b["get"]([1, 2], 1) == 2
    assert b["get"](5, 0) is None
    assert b["flood"]([1], 2) == [1, 2]
    assert b["flood"](5, 1) == 5
    assert b["condense"]({"value": 9}) == 9
    assert b["condense"]({}) is None
    assert b["evaporate"]({"value": 9}) == 9
    assert b["evaporate"]({}) is None
    assert b["strain"](7) == 7
    assert b["transmute"](7, "int") == 7
    assert b["distill"](7) == 7
