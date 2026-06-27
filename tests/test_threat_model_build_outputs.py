"""Generated-output governance-loss tests mapped to THREAT_MODEL C034."""
import json
import os

import pytest

from utf.thirsty_lang import cli

GOVERNED_SOURCE = """module demo: governed

drink main = 1
"""


def _write(tmp_path, source=GOVERNED_SOURCE):
    p = tmp_path / "governed.thirsty"
    p.write_text(source)
    return str(p)


@pytest.mark.parametrize("target", ["js", "llvm-ir", "wasm-pyodide"])
def test_governed_build_refuses_governance_loss_by_default(
    tmp_path, monkeypatch, target,
):
    import sys

    source_path = _write(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["thirsty", "build", "--target", target, source_path]
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    base = os.path.splitext(source_path)[0]
    assert not os.path.exists(base + ".js")
    assert not os.path.exists(base + ".ll")
    assert not os.path.exists(base + ".pyodide.html")


def test_governance_loss_escape_hatch_emits_manifest_disclosure(
    tmp_path, monkeypatch, capsys,
):
    import sys

    source_path = _write(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "thirsty", "build", "--target", "js", "--allow-governance-loss",
            "--emit-manifest", source_path,
        ],
    )
    cli.main()
    base = os.path.splitext(source_path)[0]
    assert os.path.exists(base + ".js")
    manifest = json.loads(open(base + ".manifest.json").read())
    assert manifest["mode"] == "governed"
    assert manifest["build"]["target"] == "js"
    assert manifest["build"]["governance_loss"] is True
    assert "governance loss" in capsys.readouterr().err.lower()
