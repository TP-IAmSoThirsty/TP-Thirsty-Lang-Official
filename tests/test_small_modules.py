"""Coverage for small leaf modules: console, package __init__, token,
diagnostics."""
import importlib
import sys

from utf.thirsty_lang.diagnostics import (
    Diagnostic,
    DiagnosticBundle,
    DiagnosticSeverity,
    format_diagnostic,
    make_error,
    make_warning,
)
from utf.thirsty_lang.token import Token, TokenType

# --- console --------------------------------------------------------------

def test_enable_utf8_handles_reconfigure_failure(monkeypatch):
    class Bad:
        def reconfigure(self, encoding):
            raise ValueError("nope")

    monkeypatch.setattr(sys, "stdout", Bad())
    monkeypatch.setattr(sys, "stderr", Bad())
    from utf.console import enable_utf8
    enable_utf8()  # must swallow the error


# --- package __init__ -----------------------------------------------------

def test_package_main(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["thirsty"])
    import utf.thirsty_lang as tl
    tl.main()
    assert "usage" in capsys.readouterr().out.lower()


def test_version_fallback(monkeypatch):
    import importlib.metadata as md

    import utf.thirsty_lang as tl

    def boom(_name):
        raise RuntimeError("not installed")

    monkeypatch.setattr(md, "version", boom)
    importlib.reload(tl)
    assert tl.__version__ == "0.8.3"
    monkeypatch.undo()
    importlib.reload(tl)  # restore real metadata version


# --- token ----------------------------------------------------------------

def test_token_repr():
    assert "Token(" in repr(Token(TokenType.INT, "5", 1, 2))


# --- diagnostics ----------------------------------------------------------

def test_severity_str():
    assert str(DiagnosticSeverity.ERROR) == "error"


def test_diagnostic_format_with_source():
    d = Diagnostic(code="E001", message="bad", span=(1, 3, 1, 4))
    out = d.format(["abc def"])
    assert "[E001]" in out
    assert "^" in out


def test_diagnostic_format_col_zero():
    d = Diagnostic(code="E001", message="bad", span=(1, 0, 1, 0))
    out = d.format(["abc"])
    assert "^" in out


def test_diagnostic_format_no_source():
    d = Diagnostic(code="E001", message="bad", span=(1, 1, 1, 2))
    assert d.format() == "[E001] error: bad"


def test_bundle():
    b = DiagnosticBundle()
    assert b.format_all() == "No diagnostics."
    assert bool(b) is False
    b.add(Diagnostic(code="E001", message="m", span=(1, 1, 1, 1)))
    assert b.has_errors() is True
    assert len(b) == 1
    assert bool(b) is True
    assert "diagnostic(s)" in b.format_all()


def test_format_diagnostic_helper():
    d = make_error("E011", name="x")
    assert "x" in format_diagnostic(d)


def test_make_warning():
    w = make_warning("E060")
    assert w.severity == "warning"
    assert "empty" in w.message.lower()
