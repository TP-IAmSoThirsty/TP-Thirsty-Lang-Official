"""Coverage for the main `thirsty` CLI dispatch and every subcommand."""
import builtins
import os

import pytest

from utf.thirsty_lang import cli

PROG = """module demo: core

glass greet(name) {
    return "hello"
}

drink main = greet("x")
pour main
"""

GODS_EXAMPLE = os.path.join("src", "utf", "examples", "gods.thirstofgods")


def run_cli(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["thirsty", *args])
    cli.main()


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


# === main dispatch ========================================================

def test_main_no_command(monkeypatch, capsys):
    run_cli(monkeypatch)
    assert "usage" in capsys.readouterr().out.lower()


def test_main_version(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "--version")
    assert "Thirsty-Lang" in capsys.readouterr().out


def test_main_exception_handler(monkeypatch):
    monkeypatch.setattr(cli, "cmd_fmt",
                        lambda _a: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "fmt", "x.thirsty")


def test_main_exception_with_debug(monkeypatch):
    monkeypatch.setenv("THIRSTY_DEBUG", "1")
    monkeypatch.setattr(cli, "cmd_lock",
                        lambda _a: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "lock")


# === run ==================================================================

def test_run_demo(monkeypatch, capsys):
    run_cli(monkeypatch, "run", "--demo")
    assert "hello" in capsys.readouterr().out


def test_run_file(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, "run", write(tmp_path, "p.thirsty", PROG))
    assert "hello" in capsys.readouterr().out


def test_run_prints_result(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, "run", write(tmp_path, "p.thirsty",
                                       "module m: core\ndrink x = 5\nx"))
    assert "5" in capsys.readouterr().out


def test_run_gods_delegation(monkeypatch, tmp_path, capsys):
    src = write(tmp_path, "g.thirstofgods", open(GODS_EXAMPLE).read())
    run_cli(monkeypatch, "run", src)
    capsys.readouterr()


def test_run_file_not_found(monkeypatch):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run", "missing.thirsty")


def test_run_parse_errors(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run", write(tmp_path, "bad.thirsty", "glass f( {"))


RUNTIME_ERR = "module m: core\ndrink x = 1 / 0"


def test_run_runtime_error(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run",
                write(tmp_path, "e.thirsty", RUNTIME_ERR))


def test_run_runtime_error_release(monkeypatch, tmp_path, capsys):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run", "--release",
                write(tmp_path, "e.thirsty", RUNTIME_ERR))
    assert "Error:" in capsys.readouterr().err


def test_run_runtime_error_trace(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run", "--trace",
                write(tmp_path, "e.thirsty", RUNTIME_ERR))


def test_run_locked_no_lockfile(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run", "--locked",
                write(tmp_path, "p.thirsty", PROG))


def test_run_locked_ok(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "thirsty.lock").write_text(
        '{"dependencies": {"a": {"version": "1"}}}')
    run_cli(monkeypatch, "run", "--locked",
            write(tmp_path, "p.thirsty", PROG))
    assert "Lockfile verified" in capsys.readouterr().out


def test_run_policy_not_found(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "run", "--policy", "missing.tarl",
                write(tmp_path, "p.thirsty", PROG))


def test_run_with_authority_and_policy(monkeypatch, tmp_path, capsys):
    policy = write(tmp_path, "p.tarl", "when true => ALLOW\n")
    run_cli(monkeypatch, "run", "--authority", "admin", "--policy", policy,
            write(tmp_path, "p.thirsty", PROG))
    assert "hello" in capsys.readouterr().out


def test_run_governance_violation(monkeypatch, tmp_path):
    from utf.thirsty_lang import interpreter as itp

    proof = type("P", (), {"verdict": "DENY", "policy_hash": "abc"})()

    def deny(self, ast, mode="core"):
        raise itp.GovernanceViolation("fn", "denied", proof)

    monkeypatch.setattr(itp.Interpreter, "interpret", deny)
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "run", write(tmp_path, "p.thirsty", PROG))
    assert exc.value.code == 2


# === fmt ==================================================================

def test_fmt_write(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, "fmt", write(tmp_path, "p.thirsty", PROG))
    assert "Formatted" in capsys.readouterr().out


def test_fmt_check_would_reformat(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "fmt", "--check",
                write(tmp_path, "p.thirsty", "module m: core\ndrink   x=1"))


def test_fmt_file_not_found(monkeypatch, capsys):
    run_cli(monkeypatch, "fmt", "missing.thirsty")
    assert "not found" in capsys.readouterr().err


# === new ==================================================================

def test_new_project(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run_cli(monkeypatch, "new", "myproj")
    assert (tmp_path / "myproj" / "src" / "main.thirsty").exists()
    assert "Created" in capsys.readouterr().out


def test_new_existing_dir(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "exists").mkdir()
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "new", "exists")


# === govern ===============================================================

def test_govern_report(monkeypatch, tmp_path, capsys):
    run_cli(monkeypatch, "govern", "--report",
            write(tmp_path, "p.thirsty", PROG))
    assert "Governance Report" in capsys.readouterr().out


def test_govern_no_file_scans(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    write(tmp_path, "p.thirsty", PROG)
    run_cli(monkeypatch, "govern", "--report")
    capsys.readouterr()


def test_govern_no_file_none_found(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "govern", "--report")


def test_govern_auto_tarl(monkeypatch, tmp_path, capsys):
    src = write(tmp_path, "p.thirsty", PROG)
    run_cli(monkeypatch, "govern", "--auto-tarl", src)
    assert os.path.exists(os.path.splitext(src)[0] + ".tarl")


# === add / audit / lock ===================================================

def test_add(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run_cli(monkeypatch, "add", "crypto@1.0")
    assert "Added" in capsys.readouterr().out


def test_add_no_version(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run_cli(monkeypatch, "add", "crypto")
    assert "crypto@*" in capsys.readouterr().out


def test_audit_clean(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run_cli(monkeypatch, "audit")
    assert "No dependency issues" in capsys.readouterr().out


def test_audit_with_issues_fix(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "thirsty.toml").write_text('[dependencies]\nfoo = "1"\n')
    run_cli(monkeypatch, "audit", "--fix")
    assert "regenerated" in capsys.readouterr().out


def test_lock(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run_cli(monkeypatch, "lock")
    assert "Lockfile generated" in capsys.readouterr().out


# === doctor ===============================================================

def test_doctor_failing(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "doctor")


def test_doctor_fix(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "doctor", "--fix")
    out = capsys.readouterr().out
    assert "Created thirsty.toml" in out


def test_doctor_passing(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "thirsty.toml").write_text("[package]\n")
    (tmp_path / "thirsty.lock").write_text("{}")
    srcdir = tmp_path / "src"
    srcdir.mkdir()
    (srcdir / "main.thirsty").write_text(PROG)
    run_cli(monkeypatch, "doctor")
    assert "Passed: 4" in capsys.readouterr().out


# === docs =================================================================

def test_docs(monkeypatch, tmp_path, capsys):
    outdir = tmp_path / "docs"
    run_cli(monkeypatch, "docs", "--output-dir", str(outdir))
    assert (outdir / "index.html").exists()


# === repl =================================================================

def _feed_input(monkeypatch, lines):
    it = iter(lines)

    def fake_input(_prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(builtins, "input", fake_input)


def test_repl_session(monkeypatch, capsys):
    _feed_input(monkeypatch, [
        "help",
        "",
        "drink x = 5",
        "x",
        ".clear",
        "exit",
    ])
    run_cli(monkeypatch, "repl")
    out = capsys.readouterr().out
    assert "REPL" in out
    assert "State cleared." in out


def test_repl_eof(monkeypatch, capsys):
    _feed_input(monkeypatch, [])
    run_cli(monkeypatch, "repl")
    capsys.readouterr()


def test_repl_runtime_error(monkeypatch, capsys):
    _feed_input(monkeypatch, ["1 / 0", "exit"])
    run_cli(monkeypatch, "repl")
    assert "Error" in capsys.readouterr().out
