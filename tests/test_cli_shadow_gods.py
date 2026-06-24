"""CLI coverage for shadow-thirst and thirst-of-gods."""
import os

import pytest

from utf.shadow_thirst import cli as shadow_cli
from utf.thirst_of_gods import cli as gods_cli

MUTATION = """
mutation m {
    validated_canonical {
        shadow {
            let x = compute(input)
        }
        invariant {
            count > 0 && count < 100
        }
        canonical {
            let result = compute(input)
            return result
        }
    }
}
"""

GODS_EXAMPLE = os.path.join("src", "utf", "examples", "gods.thirstofgods")


def _argv(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", list(args))


# === shadow-thirst ========================================================

def _write_mutation(tmp_path):
    p = tmp_path / "m.shadow"
    p.write_text(MUTATION)
    return str(p)


def test_shadow_check_text(monkeypatch, capsys, tmp_path):
    _argv(monkeypatch, "shadow-thirst", "check", _write_mutation(tmp_path))
    shadow_cli.main()
    assert "VERDICT" in capsys.readouterr().out


def test_shadow_check_json(monkeypatch, capsys, tmp_path):
    _argv(monkeypatch, "shadow-thirst", "check", _write_mutation(tmp_path), "--json")
    shadow_cli.main()
    assert '"verdict"' in capsys.readouterr().out


def test_shadow_visualize_stdout(monkeypatch, capsys, tmp_path):
    _argv(monkeypatch, "shadow-thirst", "visualize", _write_mutation(tmp_path))
    shadow_cli.main()
    assert capsys.readouterr().out.strip()


def test_shadow_visualize_output_file(monkeypatch, tmp_path, capsys):
    out = tmp_path / "flow.mmd"
    _argv(monkeypatch, "shadow-thirst", "visualize",
          _write_mutation(tmp_path), "--output", str(out))
    shadow_cli.main()
    assert out.exists()
    assert "written to" in capsys.readouterr().out


def test_shadow_no_command(monkeypatch):
    _argv(monkeypatch, "shadow-thirst")
    with pytest.raises(SystemExit):
        shadow_cli.main()


def test_shadow_file_not_found(monkeypatch):
    _argv(monkeypatch, "shadow-thirst", "check", "nope.shadow")
    with pytest.raises(SystemExit):
        shadow_cli.main()


def test_shadow_parse_error(monkeypatch, tmp_path):
    bad = tmp_path / "bad.shadow"
    bad.write_text("this is not a mutation")
    _argv(monkeypatch, "shadow-thirst", "check", str(bad))
    with pytest.raises(SystemExit):
        shadow_cli.main()


# === thirst-of-gods =======================================================

def test_gods_run(monkeypatch, capsys):
    _argv(monkeypatch, "thirst-of-gods", "run", GODS_EXAMPLE)
    gods_cli.main()
    # Either prints a result or nothing; must not error.
    capsys.readouterr()


def test_gods_check_pass(monkeypatch, capsys):
    _argv(monkeypatch, "thirst-of-gods", "check", GODS_EXAMPLE)
    gods_cli.main()
    assert "Deity Contract" in capsys.readouterr().out


def test_gods_transpile_thirsty(monkeypatch, tmp_path, capsys):
    src = tmp_path / "g.thirstofgods"
    src.write_text(open(GODS_EXAMPLE).read())
    _argv(monkeypatch, "thirst-of-gods", "transpile", str(src))
    gods_cli.main()
    assert (tmp_path / "g.thirsty").exists()
    assert "Thirsty-Lang" in capsys.readouterr().out


def test_gods_transpile_js(monkeypatch, tmp_path, capsys):
    src = tmp_path / "g.thirstofgods"
    src.write_text(open(GODS_EXAMPLE).read())
    _argv(monkeypatch, "thirst-of-gods", "transpile", str(src), "--target", "js")
    gods_cli.main()
    assert (tmp_path / "g.js").exists()


def test_gods_no_command(monkeypatch, capsys):
    _argv(monkeypatch, "thirst-of-gods")
    gods_cli.main()
    assert "usage" in capsys.readouterr().out.lower()


def test_gods_run_file_not_found(monkeypatch):
    _argv(monkeypatch, "thirst-of-gods", "run", "missing.thirstofgods")
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_run_parse_errors(monkeypatch, tmp_path):
    bad = tmp_path / "bad.thirstofgods"
    bad.write_text("glass f( {")  # malformed
    _argv(monkeypatch, "thirst-of-gods", "run", str(bad))
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_run_deity_error(monkeypatch, tmp_path):
    from utf.thirst_of_gods import core
    good = tmp_path / "g.thirstofgods"
    good.write_text(open(GODS_EXAMPLE).read())

    def boom(_ast):
        raise core.ThirstOfGodsError("bad deity")

    monkeypatch.setattr(core, "interpret_gods", boom)
    _argv(monkeypatch, "thirst-of-gods", "run", str(good))
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_run_runtime_error(monkeypatch, tmp_path):
    from utf.thirst_of_gods import core
    good = tmp_path / "g.thirstofgods"
    good.write_text(open(GODS_EXAMPLE).read())

    def boom(_ast):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(core, "interpret_gods", boom)
    _argv(monkeypatch, "thirst-of-gods", "run", str(good))
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_check_file_not_found(monkeypatch):
    _argv(monkeypatch, "thirst-of-gods", "check", "missing.thirstofgods")
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_check_parse_errors(monkeypatch, tmp_path):
    bad = tmp_path / "bad.thirstofgods"
    bad.write_text("glass f( {")
    _argv(monkeypatch, "thirst-of-gods", "check", str(bad))
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_check_fail(monkeypatch, tmp_path):
    from utf.thirst_of_gods import core
    good = tmp_path / "g.thirstofgods"
    good.write_text(open(GODS_EXAMPLE).read())

    diag = type("D", (), {"code": "G001", "severity": "ERROR", "message": "boom"})()
    monkeypatch.setattr(core, "validate_deity_contract", lambda _ast: [diag])
    contract = type("C", (), {"violations": ["v1"]})()
    monkeypatch.setattr(core, "to_gods", lambda _ast: contract)
    _argv(monkeypatch, "thirst-of-gods", "check", str(good))
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_transpile_file_not_found(monkeypatch):
    _argv(monkeypatch, "thirst-of-gods", "transpile", "missing.thirstofgods")
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_transpile_parse_errors(monkeypatch, tmp_path):
    bad = tmp_path / "bad.thirstofgods"
    bad.write_text("glass f( {")
    _argv(monkeypatch, "thirst-of-gods", "transpile", str(bad))
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_transpile_unknown_target(monkeypatch, tmp_path):
    good = tmp_path / "g.thirstofgods"
    good.write_text(open(GODS_EXAMPLE).read())
    # Call transpile_file directly to bypass argparse's choices validation.
    with pytest.raises(SystemExit):
        gods_cli.transpile_file(str(good), target="cobol")


def test_gods_run_prints_result(monkeypatch, capsys, tmp_path):
    from utf.thirst_of_gods import core
    good = tmp_path / "g.thirstofgods"
    good.write_text(open(GODS_EXAMPLE).read())
    monkeypatch.setattr(core, "interpret_gods", lambda _ast: "RESULT_VALUE")
    _argv(monkeypatch, "thirst-of-gods", "run", str(good))
    gods_cli.main()
    assert "RESULT_VALUE" in capsys.readouterr().out


def test_gods_main_exception_handler(monkeypatch):
    monkeypatch.setattr(gods_cli, "run_file",
                        lambda _f: (_ for _ in ()).throw(RuntimeError("x")))
    _argv(monkeypatch, "thirst-of-gods", "run", "whatever")
    with pytest.raises(SystemExit):
        gods_cli.main()


def test_gods_run_delegate(monkeypatch, capsys):
    # The `run` delegation entry point used by the main Thirsty CLI.
    gods_cli.run(GODS_EXAMPLE)
    capsys.readouterr()
