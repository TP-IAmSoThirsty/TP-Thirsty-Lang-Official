"""CLI coverage for tscg and tscg-b."""
import io

import pytest

from utf.tscg import cli as tscg_cli
from utf.tscg_b import cli as tscgb_cli
from utf.tscg_b.core import pack_text

EXPR = "$COG -> $DNT"


def _argv(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", list(args))


# --- tscg -----------------------------------------------------------------

def test_tscg_parse_text(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "parse", EXPR)
    tscg_cli.main()
    assert "COG" in capsys.readouterr().out


def test_tscg_parse_json(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "parse", EXPR, "--json")
    tscg_cli.main()
    assert '"type"' in capsys.readouterr().out


def test_tscg_parse_combine_text(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "parse", "$COG ^ $DNT")
    tscg_cli.main()
    assert "Combine" in capsys.readouterr().out


def test_tscg_parse_combine_json(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "parse", "$COG || $DNT", "--json")
    tscg_cli.main()
    assert '"combine"' in capsys.readouterr().out


def test_tscg_canonical(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "canonical", EXPR)
    tscg_cli.main()
    assert capsys.readouterr().out.strip()


def test_tscg_checksum(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "checksum", EXPR)
    tscg_cli.main()
    assert len(capsys.readouterr().out.strip()) >= 16


def test_tscg_validate_ok(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "validate", EXPR)
    tscg_cli.main()
    assert "recognized" in capsys.readouterr().out


def test_tscg_validate_errors(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "validate", "$ZZZ -> $COG")
    tscg_cli.main()
    assert "error" in capsys.readouterr().out.lower()


def test_tscg_list_text(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "list")
    tscg_cli.main()
    assert "COG" in capsys.readouterr().out


def test_tscg_list_json(monkeypatch, capsys):
    _argv(monkeypatch, "tscg", "list", "--json")
    tscg_cli.main()
    assert "COG" in capsys.readouterr().out


def test_tscg_no_command(monkeypatch):
    _argv(monkeypatch, "tscg")
    with pytest.raises(SystemExit):
        tscg_cli.main()


def test_tscg_parse_error(monkeypatch):
    _argv(monkeypatch, "tscg", "parse", "@@@")
    with pytest.raises(SystemExit):
        tscg_cli.main()


def test_tscg_node_helpers_fallback():
    # Unknown node types hit the fallback returns.
    assert tscg_cli._node_to_dict(object()) == {}
    assert isinstance(tscg_cli._node_to_str(object()), str)


# --- tscg-b ---------------------------------------------------------------

class _FakeStdout:
    def __init__(self):
        self.buffer = io.BytesIO()


def test_tscgb_encode(monkeypatch):
    out = _FakeStdout()
    monkeypatch.setattr("sys.stdout", out)
    _argv(monkeypatch, "tscg-b", "encode", "hi")
    tscgb_cli.main()
    assert out.buffer.getvalue()  # wrote a frame


def test_tscgb_decode_hex(monkeypatch, capsys):
    frame_hex = pack_text("hi").hex()
    _argv(monkeypatch, "tscg-b", "decode", frame_hex)
    tscgb_cli.main()
    assert '"text"' in capsys.readouterr().out


def test_tscgb_stream_hex(monkeypatch, capsys):
    frame_hex = pack_text("hi").hex()
    _argv(monkeypatch, "tscg-b", "stream", frame_hex)
    tscgb_cli.main()
    assert "text" in capsys.readouterr().out


class _FakeStdin:
    def __init__(self, data=b""):
        self.buffer = io.BytesIO(data)


def test_tscgb_decode_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _FakeStdin(pack_text("hi")))
    _argv(monkeypatch, "tscg-b", "decode")
    tscgb_cli.main()
    assert '"text"' in capsys.readouterr().out


def test_tscgb_stream_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _FakeStdin(pack_text("hi")))
    _argv(monkeypatch, "tscg-b", "stream")
    tscgb_cli.main()
    assert "text" in capsys.readouterr().out


def test_tscgb_no_args(monkeypatch):
    _argv(monkeypatch, "tscg-b")
    with pytest.raises(SystemExit):
        tscgb_cli.main()


def test_tscgb_help(monkeypatch, capsys):
    _argv(monkeypatch, "tscg-b", "--help")
    with pytest.raises(SystemExit) as exc:
        tscgb_cli.main()
    assert exc.value.code == 0
    assert "encode" in capsys.readouterr().out


def test_tscgb_unknown(monkeypatch):
    _argv(monkeypatch, "tscg-b", "bogus")
    with pytest.raises(SystemExit):
        tscgb_cli.main()


def test_tscgb_error(monkeypatch):
    _argv(monkeypatch, "tscg-b", "decode", "nothex!")
    with pytest.raises(SystemExit):
        tscgb_cli.main()


def test_tscgb_encode_stdin(monkeypatch):
    out = _FakeStdout()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stdin", io.StringIO("piped"))
    _argv(monkeypatch, "tscg-b", "encode")
    tscgb_cli.main()
    assert out.buffer.getvalue()
