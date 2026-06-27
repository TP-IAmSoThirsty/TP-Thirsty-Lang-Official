"""
T.A.R.L. Language Server — Phase 6

Implements the Language Server Protocol (LSP) for .tarl files over stdio.

Run as:
    python -m utf.tarl.lsp
or via the console_scripts entry point:
    tarl-lsp

Capabilities:
  - Full text-document sync
  - Syntax diagnostics (parse/tokenizer errors per rule)
  - Dead-rule warnings (requires z3-solver; falls back silently)
  - Coverage-gap hints (requires z3-solver)
  - Hover: rule verdict + condition at cursor position
  - Definition: jump to EXTENDS/RESTRICTS parent or INCLUDE file target
"""
from __future__ import annotations

import json
import logging
import sys
import threading

log = logging.getLogger(__name__)


# ── JSON-RPC framing ──────────────────────────────────────────────────────────

def _read_message(stream) -> dict | None:
    """Read one Length-prefixed JSON-RPC message. Returns None on EOF."""
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        decoded = line.decode("utf-8", errors="replace").strip()
        if not decoded:
            break
        if ":" in decoded:
            k, _, v = decoded.partition(":")
            headers[k.strip().lower()] = v.strip()

    length = int(headers.get("content-length", 0))
    if not length:
        return None
    body = stream.read(length).decode("utf-8")
    message = json.loads(body)
    return message if isinstance(message, dict) else None


def _write_message(stream, msg: dict) -> None:
    """Write one Length-prefixed JSON-RPC message to stream."""
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    stream.write(header + body)
    stream.flush()


# ── Diagnostic construction ───────────────────────────────────────────────────

def _diagnostic(
    start_line: int,
    start_char: int,
    end_line: int,
    end_char: int,
    message: str,
    severity: int = 1,   # 1=Error 2=Warning 3=Info 4=Hint
) -> dict:
    return {
        "range": {
            "start": {"line": start_line, "character": start_char},
            "end":   {"line": end_line,   "character": end_char},
        },
        "severity": severity,
        "source": "tarl",
        "message": message,
    }


# ── Language server ───────────────────────────────────────────────────────────

class TarlLanguageServer:
    """
    T.A.R.L. Language Server over JSON-RPC / stdio.

    Designed to be injected with mock streams for testing::

        server = TarlLanguageServer(stdin=mock_in, stdout=mock_out)
        server.run()
    """

    def __init__(self, stdin=None, stdout=None):
        self._in = stdin or sys.stdin.buffer
        self._out = stdout or sys.stdout.buffer
        self._docs: dict[str, str] = {}
        self._running = True
        # Protects stdout writes from main + Z3 background threads
        self._write_lock = threading.Lock()
        # Version counter per URI — lets Z3 threads discard stale results
        self._doc_versions: dict[str, int] = {}

    def run(self) -> None:
        """Main read-dispatch loop."""
        while self._running:
            msg = _read_message(self._in)
            if msg is None:
                break
            self._dispatch(msg)

    def _dispatch(self, msg: dict) -> None:
        method = msg.get("method", "")
        msg_id = msg.get("id")

        handler = {
            "initialize":              self._on_initialize,
            "initialized":             self._on_initialized,
            "shutdown":                self._on_shutdown,
            "exit":                    self._on_exit,
            "textDocument/didOpen":    self._on_did_open,
            "textDocument/didChange":  self._on_did_change,
            "textDocument/didClose":   self._on_did_close,
            "textDocument/hover":      self._on_hover,
            "textDocument/definition": self._on_definition,
        }.get(method)

        if handler is None:
            if msg_id is not None:
                self._reply(msg_id, result=None)
            return

        try:
            result = handler(msg.get("params", {}))
            if msg_id is not None:
                self._reply(msg_id, result=result)
        except Exception as exc:
            log.error("Error in %s: %s", method, exc, exc_info=True)
            if msg_id is not None:
                self._error(msg_id, -32603, str(exc))

    def _reply(self, msg_id, result) -> None:
        with self._write_lock:
            _write_message(self._out, {
                "jsonrpc": "2.0", "id": msg_id, "result": result,
            })

    def _error(self, msg_id, code: int, message: str) -> None:
        with self._write_lock:
            _write_message(self._out, {
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": code, "message": message},
            })

    def _notify(self, method: str, params: dict) -> None:
        with self._write_lock:
            _write_message(self._out, {
                "jsonrpc": "2.0", "method": method, "params": params,
            })

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _on_initialize(self, params: dict) -> dict:
        return {
            "capabilities": {
                "textDocumentSync": 1,    # Full sync
                "hoverProvider": True,
                "definitionProvider": True,
            },
            "serverInfo": {"name": "tarl-lsp", "version": "0.1.0"},
        }

    def _on_initialized(self, params: dict):
        return None

    def _on_shutdown(self, params: dict):
        self._running = False
        return None

    def _on_exit(self, params: dict):
        sys.exit(0)

    # ── Document sync ─────────────────────────────────────────────────────────

    def _on_did_open(self, params: dict):
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        text = doc.get("text", "")
        self._docs[uri] = text
        self._publish_diagnostics(uri, text)
        return None

    def _on_did_change(self, params: dict):
        uri = params.get("textDocument", {}).get("uri", "")
        changes = params.get("contentChanges", [])
        if changes:
            text = changes[-1].get("text", "")
            self._docs[uri] = text
            self._publish_diagnostics(uri, text)
        return None

    def _on_did_close(self, params: dict):
        uri = params.get("textDocument", {}).get("uri", "")
        self._docs.pop(uri, None)
        self._notify("textDocument/publishDiagnostics", {
            "uri": uri, "diagnostics": [],
        })
        return None

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def _publish_diagnostics(self, uri: str, text: str) -> None:
        """
        Publish diagnostics in two passes:
          1. Syntax errors — synchronous, fast, published immediately so the
             editor has feedback before the user finishes typing.
          2. Z3 static analysis — run in a daemon thread.  A version counter
             guards against stale results: if the document changed while Z3
             was running the notification is silently discarded.
        """
        # Bump version so any in-flight Z3 thread for this URI self-cancels.
        version = self._doc_versions.get(uri, 0) + 1
        self._doc_versions[uri] = version

        syntax = self._syntax_diags(text)
        self._notify("textDocument/publishDiagnostics", {
            "uri": uri, "diagnostics": syntax,
        })

        def _z3_task():
            z3 = self._z3_diags(text)
            if self._doc_versions.get(uri) != version:
                return   # document changed; result is stale
            self._notify("textDocument/publishDiagnostics", {
                "uri": uri, "diagnostics": syntax + z3,
            })

        threading.Thread(target=_z3_task, daemon=True).start()

    def validate(self, text: str) -> list[dict]:
        """
        Synchronous combined validation — syntax + Z3 (if available).

        Used by tests and callers that need a single blocking result.
        The LSP server itself uses the split async path in
        _publish_diagnostics instead.
        """
        return self._syntax_diags(text) + self._z3_diags(text)

    def _syntax_diags(self, text: str) -> list[dict]:
        """Fast synchronous pass: tokenizer/parser errors only."""
        from utf.tarl.core import PolicyParser
        from utf.tarl.spec import TarlPolicy

        diags: list[dict] = []
        doc_lines = text.split("\n")

        try:
            items = PolicyParser.parse_all(text)
        except Exception as exc:
            diags.append(_diagnostic(0, 0, 0, 0, f"Parse error: {exc}"))
            return diags

        for item in items:
            if not isinstance(item, TarlPolicy):
                continue
            for rule in item.rules:
                li = max(0, rule.source_line - 1)
                raw = doc_lines[li] if li < len(doc_lines) else ""
                try:
                    PolicyParser._tokenize(rule.condition)
                except ValueError as exc:
                    col = raw.find("when") if "when" in raw else 0
                    diags.append(_diagnostic(
                        li, col, li, len(raw),
                        f"Condition syntax error: {exc}",
                        severity=1,
                    ))

        return diags

    def _z3_diags(self, text: str) -> list[dict]:
        """Slow optional pass: Z3-backed dead-rule and coverage analysis."""
        from utf.tarl.core import PolicyParser
        from utf.tarl.spec import TarlPolicy

        diags: list[dict] = []
        doc_lines = text.split("\n")

        try:
            items = PolicyParser.parse_all(text)
        except Exception:
            return diags

        for item in items:
            if not isinstance(item, TarlPolicy):
                continue
            try:
                from utf.tarl.analyzer import PolicyAnalyzer

                shadows = PolicyAnalyzer(item).check_shadows()
                for sh in shadows.shadows:
                    rule = item.rules[sh.shadowed_index]
                    li = max(0, rule.source_line - 1)
                    raw = doc_lines[li] if li < len(doc_lines) else ""
                    diags.append(_diagnostic(
                        li, 0, li, len(raw),
                        (
                            f"Dead rule: shadowed by rule"
                            f" #{sh.shadowing_index} and can never match"
                        ),
                        severity=2,
                    ))

                cov = PolicyAnalyzer(item).check_coverage()
                if not cov.passed:
                    diags.append(_diagnostic(
                        0, 0, 0, 0,
                        (
                            f"Coverage gap: {len(cov.gaps)} context region(s)"
                            f" fall through to DEFAULT_DENY"
                        ),
                        severity=4,
                    ))
            except (ImportError, Exception):
                pass

        return diags

    # ── Hover ─────────────────────────────────────────────────────────────────

    def _on_hover(self, params: dict) -> dict | None:
        uri = params.get("textDocument", {}).get("uri", "")
        pos = params.get("position", {})
        line = pos.get("line", 0)

        text = self._docs.get(uri)
        if text is None:
            return None

        contents = self.hover_at(text, line)
        if contents is None:
            return None
        return {"contents": {"kind": "markdown", "value": contents}}

    def hover_at(self, text: str, line: int) -> str | None:
        """
        Return markdown hover string for the given (0-based) line, or None.

        Public for testability.
        """
        from utf.tarl.core import PolicyParser
        from utf.tarl.spec import TarlPolicy

        doc_lines = text.split("\n")
        try:
            items = PolicyParser.parse_all(text)
        except Exception:
            return None

        for item in items:
            if not isinstance(item, TarlPolicy):
                continue

            # Rule hover
            for rule in item.rules:
                if rule.source_line - 1 == line:
                    dur = ""
                    if rule.duration_seconds:
                        ds = rule.duration_seconds
                        label = (
                            f"{ds // 3600}h" if ds % 3600 == 0
                            else f"{ds // 60}m" if ds % 60 == 0
                            else f"{ds}s"
                        )
                        dur = f"\n\n_Time-bound: `{label}`_"
                    return (
                        f"**T.A.R.L. Rule**\n\n"
                        f"```\nwhen {rule.condition} => {rule.verdict.value}\n```"
                        f"\n\nVerdict: **{rule.verdict.value}**{dur}"
                    )

            # Policy header hover
            if item.name == "unnamed":
                continue
            for idx, raw in enumerate(doc_lines):
                stripped = raw.strip()
                if (
                    stripped.startswith(f"policy {item.name}")
                    or stripped.startswith(f"policy_set {item.name}")
                ):
                    if idx == line:
                        parts = [f"**Policy** `{item.name}`"]
                        if item.composition and item.parent:
                            parts.append(
                                f"\n\n{item.composition.value} `{item.parent}`"
                            )
                        if item.valid_from:
                            parts.append(f"\n\n_Valid from: {item.valid_from}_")
                        if item.valid_until:
                            parts.append(f"\n\n_Valid until: {item.valid_until}_")
                        return "".join(parts)
                    break

        return None

    # ── Definition ────────────────────────────────────────────────────────────

    def _on_definition(self, params: dict) -> dict | None:
        uri = params.get("textDocument", {}).get("uri", "")
        pos = params.get("position", {})
        line_idx = pos.get("line", 0)

        text = self._docs.get(uri)
        if text is None:
            return None

        return self.definition_at(text, uri, line_idx)

    def definition_at(
        self, text: str, uri: str, line_idx: int
    ) -> dict | None:
        """
        Return an LSP Location dict for the definition at line_idx, or None.

        Resolves:
          - EXTENDS/RESTRICTS → parent policy in the same document
          - INCLUDE "file.tarl" → file URI
        Public for testability.
        """
        from utf.tarl.core import PolicyParser

        doc_lines = text.split("\n")
        if line_idx >= len(doc_lines):
            return None
        raw_line = doc_lines[line_idx]

        # Policy header: EXTENDS/RESTRICTS <parent>
        m = PolicyParser.POLICY_HEADER_RE.match(raw_line.strip())
        if m and m.group(3):
            parent_name = m.group(3)
            for idx, ln in enumerate(doc_lines):
                if ln.strip().startswith(f"policy {parent_name}"):
                    return {
                        "uri": uri,
                        "range": {
                            "start": {"line": idx, "character": 0},
                            "end":   {"line": idx, "character": len(ln)},
                        },
                    }
            return None

        # INCLUDE "file.tarl" directive
        m_inc = PolicyParser.INCLUDE_RE.match(raw_line.strip())
        if m_inc and m_inc.group(1):
            import os
            from urllib.parse import quote, urlparse
            parsed = urlparse(uri)
            base_dir = os.path.dirname(parsed.path)
            target = os.path.normpath(
                os.path.join(base_dir, m_inc.group(1))
            )
            target_uri = "file://" + quote(target, safe="/:\\")
            return {
                "uri": target_uri,
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end":   {"line": 0, "character": 0},
                },
            }

        return None


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.ERROR,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    TarlLanguageServer().run()


if __name__ == "__main__":
    main()
