"""Coverage for the TARL language server (tarl.lsp)."""
import io
import json

from utf.tarl import lsp
from utf.tarl.lsp import TarlLanguageServer

DOC = '''\
policy base:
  when x == 1 => ALLOW
policy child EXTENDS base:
  when y == 2 => DENY
'''

INCLUDE_DOC = 'INCLUDE "other.tarl"\npolicy p:\n  when x == 1 => ALLOW\n'


def _frame(msg):
    body = json.dumps(msg).encode()
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _server(data=b""):
    return TarlLanguageServer(stdin=io.BytesIO(data), stdout=io.BytesIO())


def test_full_session():
    uri = "file:///x.tarl"
    session = (
        _frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _frame({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        + _frame({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                  "params": {"textDocument": {"uri": uri, "text": DOC}}})
        + _frame({"jsonrpc": "2.0", "method": "textDocument/didChange",
                  "params": {"textDocument": {"uri": uri},
                             "contentChanges": [{"text": DOC}]}})
        + _frame({"jsonrpc": "2.0", "id": 2, "method": "textDocument/hover",
                  "params": {"textDocument": {"uri": uri},
                             "position": {"line": 1}}})
        + _frame({"jsonrpc": "2.0", "id": 3, "method": "textDocument/definition",
                  "params": {"textDocument": {"uri": uri},
                             "position": {"line": 2}}})
        + _frame({"jsonrpc": "2.0", "id": 4, "method": "unknown/method",
                  "params": {}})
        + _frame({"jsonrpc": "2.0", "method": "textDocument/didClose",
                  "params": {"textDocument": {"uri": uri}}})
        + _frame({"jsonrpc": "2.0", "id": 5, "method": "shutdown", "params": {}})
    )
    srv = TarlLanguageServer(stdin=io.BytesIO(session), stdout=io.BytesIO())
    srv.run()
    out = srv._out.getvalue()
    assert b"capabilities" in out


def test_run_eof_immediately():
    _server(b"").run()  # empty stream → loop exits at once


def test_validate_and_hover_direct():
    srv = _server()
    assert isinstance(srv.validate(DOC), list)
    # hover on a rule line and on a policy header line
    assert srv.hover_at(DOC, 1) is not None
    assert srv.hover_at(DOC, 2) is not None
    # hover on a blank/non-matching line → None
    assert srv.hover_at(DOC, 99) is None


def test_definition_extends_and_include():
    srv = _server()
    uri = "file:///x.tarl"
    # EXTENDS parent on the "policy child EXTENDS base" line
    loc = srv.definition_at(DOC, uri, 2)
    assert loc is not None and "range" in loc
    # INCLUDE directive resolves to a file uri
    inc = srv.definition_at(INCLUDE_DOC, uri, 0)
    assert inc is not None and inc["uri"].startswith("file://")
    # out-of-range line → None
    assert srv.definition_at(DOC, uri, 999) is None


def test_hover_missing_doc_returns_none():
    srv = _server()
    result = srv._on_hover({"textDocument": {"uri": "file:///none"},
                            "position": {"line": 0}})
    assert result is None
    assert srv._on_definition({"textDocument": {"uri": "file:///none"},
                               "position": {"line": 0}}) is None


def test_main_entrypoint(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"")))
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(io.BytesIO()))
    # main() builds a server on the real stdio buffers and runs to EOF.
    lsp.main()
