"""Tests for `thirsty lsp` stdio and socket modes (JSON-RPC over the TARL LSP)."""
import io
import json

from utf.thirsty_lang import cli


def _frame(msg: dict) -> bytes:
    body = json.dumps(msg).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _session_bytes() -> bytes:
    # initialize then shutdown — shutdown stops the run loop without sys.exit.
    return _frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + \
        _frame({"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}})


class _FakeStd:
    def __init__(self, data=b""):
        self.buffer = io.BytesIO(data)


def test_lsp_stdio(monkeypatch):
    fake_in = _FakeStd(_session_bytes())
    fake_out = _FakeStd()
    monkeypatch.setattr("sys.stdin", fake_in)
    monkeypatch.setattr("sys.stdout", fake_out)

    args = type("A", (), {"stdio": True, "port": 9898})()
    cli.cmd_lsp(args)

    out = fake_out.buffer.getvalue()
    assert b"Content-Length:" in out
    assert b'"id":1' in out  # initialize reply


class _FakeConn:
    def __init__(self, data):
        self._r = io.BytesIO(data)
        self._w = io.BytesIO()
        self.closed = False

    def makefile(self, mode):
        return self._r if "r" in mode else self._w

    def close(self):
        self.closed = True


class _FakeServerSocket:
    def __init__(self, conn):
        self._conn = conn
        self.closed = False

    def setsockopt(self, *a):
        pass

    def bind(self, addr):
        self.bound = addr

    def listen(self, n):
        self.backlog = n

    def accept(self):
        return self._conn, ("127.0.0.1", 54321)

    def close(self):
        self.closed = True


def test_lsp_socket(monkeypatch, capsys):
    conn = _FakeConn(_session_bytes())
    sock = _FakeServerSocket(conn)
    import socket
    monkeypatch.setattr(socket, "socket", lambda *a, **k: sock)

    cli._serve_lsp_socket(9999)

    captured = capsys.readouterr().out
    assert "listening on 127.0.0.1:9999" in captured
    assert "Connection from" in captured
    assert conn.closed and sock.closed
    assert b"Content-Length:" in conn._w.getvalue()


def test_lsp_socket_via_cmd(monkeypatch):
    conn = _FakeConn(_session_bytes())
    sock = _FakeServerSocket(conn)
    import socket
    monkeypatch.setattr(socket, "socket", lambda *a, **k: sock)

    args = type("A", (), {"stdio": False, "port": 8080})()
    cli.cmd_lsp(args)
    assert conn.closed
