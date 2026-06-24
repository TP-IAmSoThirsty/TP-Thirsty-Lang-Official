"""Full coverage for the package manager (manifest/lockfile/deps)."""
import json
import os

from utf.thirsty_lang.package_manager import (
    PackageManager,
    create_thirsty_lock,
    create_thirsty_toml,
)

MANIFEST = """# comment
[package]
name = "demo"
version = "1.0"

[tool.sub]
flag = true

[dependencies]
crypto = "1.0"
"""


def test_parse_manifest_missing(tmp_path):
    pm = PackageManager(str(tmp_path))
    assert pm.parse_manifest() == {}


def test_parse_manifest(tmp_path):
    (tmp_path / "thirsty.toml").write_text(MANIFEST)
    pm = PackageManager(str(tmp_path))
    m = pm.parse_manifest()
    assert m["package"]["name"] == "demo"
    assert m["tool"]["sub"]["flag"] is True
    assert m["dependencies"]["crypto"] == "1.0"


def test_parse_manifest_explicit_path(tmp_path):
    p = tmp_path / "custom.toml"
    p.write_text(MANIFEST)
    pm = PackageManager(str(tmp_path))
    assert pm.parse_manifest(str(p))["package"]["version"] == "1.0"


def test_parse_toml_value_variants():
    pm = PackageManager()
    f = pm._parse_toml_value
    assert f('"s"') == "s"
    assert f("'s'") == "s"
    assert f("true") is True
    assert f("false") is False
    assert f("none") is None
    assert f("null") is None
    assert f("[]") == []
    assert f("[1, 2]") == [1, 2]
    assert f('{a = 1, b = "x"}') == {"a": 1, "b": "x"}
    assert f("3.14") == 3.14
    assert f("42") == 42
    assert f("bareword") == "bareword"


def test_parse_lock(tmp_path):
    pm = PackageManager(str(tmp_path))
    assert pm.parse_lock() == {}
    (tmp_path / "thirsty.lock").write_text("")
    assert pm.parse_lock() == {}
    (tmp_path / "thirsty.lock").write_text(json.dumps({"x": 1}))
    assert pm.parse_lock() == {"x": 1}


def test_parse_lock_explicit_path(tmp_path):
    p = tmp_path / "c.lock"
    p.write_text(json.dumps({"a": 2}))
    pm = PackageManager(str(tmp_path))
    assert pm.parse_lock(str(p)) == {"a": 2}


def test_generate_lock_explicit_deps():
    pm = PackageManager()
    lock = pm.generate_lock({"a": "1.0", "b": 2})
    assert lock["lockfile_version"] == 1
    assert lock["dependencies"]["a"]["version"] == "1.0"
    assert lock["dependencies"]["b"]["version"] == "2"
    assert lock["dependencies"]["a"]["integrity"].startswith("sha256-")


def test_generate_lock_from_manifest():
    pm = PackageManager()
    pm.manifest = {"dependencies": {"crypto": "1.0"}}
    lock = pm.generate_lock()
    assert "crypto" in lock["dependencies"]


def test_write_lock(tmp_path):
    pm = PackageManager(str(tmp_path))
    pm.generate_lock({"a": "1"})
    assert pm.write_lock() is True
    assert os.path.exists(tmp_path / "thirsty.lock")


def test_write_lock_failure(tmp_path):
    pm = PackageManager(str(tmp_path))
    pm.generate_lock({"a": "1"})
    assert pm.write_lock(str(tmp_path / "missing_dir" / "x.lock")) is False


def test_verify_integrity():
    pm = PackageManager()
    pm.generate_lock({"a": "1"})
    assert pm.verify_integrity() == []
    pm.lock["dependencies"]["a"]["integrity"] = "sha256-tampered"
    violations = pm.verify_integrity()
    assert violations[0]["name"] == "a"


def test_add_remove_dependency(tmp_path):
    pm = PackageManager(str(tmp_path))
    pm.manifest = {"package": {"name": "x"}}
    assert pm.add_dependency("crypto", "2.0") is True
    assert pm.manifest["dependencies"]["crypto"] == "2.0"
    assert pm.remove_dependency("crypto") is True
    assert pm.remove_dependency("missing") is False


def test_write_manifest_failure(tmp_path):
    pm = PackageManager(str(tmp_path))
    pm.manifest_path = str(tmp_path / "missing_dir" / "thirsty.toml")
    pm.manifest = {"package": {"name": "x"}}
    assert pm.add_dependency("crypto", "1") is False


def test_format_toml():
    pm = PackageManager()
    out = pm._format_toml({
        "package": {"name": "x", "version": "1"},
        "scalar": 5,
        "dependencies": {"a": "1"},
    })
    assert "[package]" in out
    assert "[dependencies]" in out
    assert "scalar = 5" in out


def test_audit_dependencies(tmp_path):
    (tmp_path / "thirsty.toml").write_text(
        "[dependencies]\nfoo = \"1\"\nbar = \"1\"\n")
    pm = PackageManager(str(tmp_path))
    pm.parse_manifest()
    # lockfile: bar has wrong integrity, baz is orphan, foo missing entirely
    lock = {
        "dependencies": {
            "bar": {"version": "1", "integrity": "sha256-wrong"},
            "baz": {"version": "1", "integrity": "x"},
        }
    }
    (tmp_path / "thirsty.lock").write_text(json.dumps(lock))
    issues = pm.audit_dependencies()
    types = {i["type"] for i in issues}
    assert "missing_lock" in types       # foo
    assert "integrity_mismatch" in types  # bar
    assert "orphan_lock" in types         # baz


def test_create_helpers(tmp_path):
    toml_path = create_thirsty_toml(str(tmp_path), "myproj")
    assert os.path.exists(toml_path)
    assert "myproj" in open(toml_path).read()
    lock_path = create_thirsty_lock(str(tmp_path))
    assert json.loads(open(lock_path).read())["lockfile_version"] == 1
