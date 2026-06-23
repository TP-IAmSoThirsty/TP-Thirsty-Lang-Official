"""
Phase 6 tests — Governance IDE Surface

Covers:
  - TarlExplainer (explainer.py)
  - TarlTestRunner + .tarl_test format (tester.py)
  - TarlLanguageServer — validate, hover_at, definition_at (lsp.py)
  - CLI: tarl explain, tarl test
  - Public API exports
"""
import io
import json
import os
import tempfile
import unittest

# ── helpers ───────────────────────────────────────────────────────────────────

SIMPLE_POLICY = """\
policy access:
    when user.role == "admin" => ALLOW
    when user.role == "user"  => ALLOW
"""

DENY_POLICY = """\
policy locked:
    when flag == true => DENY
"""

MULTI_RULE_POLICY = """\
policy ranked:
    when score >= 90 => ALLOW
    when score >= 60 => ESCALATE
    when score >= 0  => DENY
"""


# ══════════════════════════════════════════════════════════════════════════════
# TarlExplainer
# ══════════════════════════════════════════════════════════════════════════════

class TestTarlExplainer(unittest.TestCase):

    def setUp(self):
        from utf.tarl.explainer import TarlExplainer
        self.ex = TarlExplainer()

    # ── basic verdict paths ───────────────────────────────────────────────────

    def test_explain_allow_first_rule(self):
        from utf.tarl.spec import TarlVerdict
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        self.assertEqual(exp.verdict, TarlVerdict.ALLOW)
        self.assertEqual(exp.matched_rule_index, 0)

    def test_explain_allow_second_rule(self):
        from utf.tarl.spec import TarlVerdict
        exp = self.ex.explain({"user": {"role": "user"}},
                              policy_text=SIMPLE_POLICY)
        self.assertEqual(exp.verdict, TarlVerdict.ALLOW)
        self.assertEqual(exp.matched_rule_index, 1)

    def test_explain_default_deny(self):
        from utf.tarl.spec import TarlVerdict
        exp = self.ex.explain({"user": {"role": "ghost"}},
                              policy_text=SIMPLE_POLICY)
        self.assertEqual(exp.verdict, TarlVerdict.DENY)
        self.assertEqual(exp.matched_rule_index, -1)

    def test_explain_deny_rule_match(self):
        from utf.tarl.spec import TarlVerdict
        exp = self.ex.explain({"flag": True}, policy_text=DENY_POLICY)
        self.assertEqual(exp.verdict, TarlVerdict.DENY)
        self.assertEqual(exp.matched_rule_index, 0)

    def test_explain_escalate_verdict(self):
        from utf.tarl.spec import TarlVerdict
        exp = self.ex.explain({"score": 75}, policy_text=MULTI_RULE_POLICY)
        self.assertEqual(exp.verdict, TarlVerdict.ESCALATE)
        self.assertEqual(exp.matched_rule_index, 1)

    # ── trace structure ───────────────────────────────────────────────────────

    def test_rule_traces_count_equals_policy_rules(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        self.assertEqual(len(exp.rule_traces), 2)

    def test_matched_rule_trace_is_evaluated_and_matched(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        self.assertTrue(exp.rule_traces[0].evaluated)
        self.assertTrue(exp.rule_traces[0].matched)

    def test_subsequent_rule_marked_unevaluated(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        self.assertFalse(exp.rule_traces[1].evaluated)
        self.assertFalse(exp.rule_traces[1].matched)

    def test_no_match_all_rules_evaluated(self):
        exp = self.ex.explain({"user": {"role": "nobody"}},
                              policy_text=SIMPLE_POLICY)
        for trace in exp.rule_traces:
            self.assertTrue(trace.evaluated)
        self.assertFalse(any(t.matched for t in exp.rule_traces))

    def test_condition_error_captured_in_trace(self):
        # source: reference causes an attribute error — captured, not raised
        policy = "policy p:\n    when source:broken_source IN [1] => ALLOW\n"
        # source:broken_source evaluates to [] (missing), so IN returns False
        exp = self.ex.explain({}, policy_text=policy)
        # No exception should bubble out; the rule simply doesn't match
        self.assertEqual(exp.matched_rule_index, -1)

    # ── temporal skip ─────────────────────────────────────────────────────────

    def test_temporal_not_yet_active_sets_temporal_reason(self):
        policy = (
            "policy future:\n"
            "    valid_from: 2099-01-01\n"
            "    when x == 1 => ALLOW\n"
        )
        exp = self.ex.explain({"x": 1}, policy_text=policy)
        self.assertIsNotNone(exp.temporal_reason)
        self.assertEqual(len(exp.rule_traces), 0)

    def test_temporal_expired_sets_temporal_reason(self):
        policy = (
            "policy past:\n"
            "    valid_until: 2000-01-01\n"
            "    when x == 1 => ALLOW\n"
        )
        exp = self.ex.explain({"x": 1}, policy_text=policy)
        self.assertIsNotNone(exp.temporal_reason)

    # ── expires_at ────────────────────────────────────────────────────────────

    def test_time_bound_rule_sets_expires_at(self):
        policy = "policy tb:\n    when x == 1 => ALLOW for: 1h\n"
        exp = self.ex.explain({"x": 1}, policy_text=policy)
        self.assertIsNotNone(exp.expires_at)

    def test_no_duration_rule_has_no_expires_at(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        self.assertIsNone(exp.expires_at)

    # ── pass TarlPolicy directly ──────────────────────────────────────────────

    def test_explain_with_policy_object(self):
        from utf.tarl.core import PolicyParser
        from utf.tarl.spec import TarlVerdict
        policy = PolicyParser.parse(SIMPLE_POLICY)
        exp = self.ex.explain({"user": {"role": "admin"}}, policy=policy)
        self.assertEqual(exp.verdict, TarlVerdict.ALLOW)

    # ── format ────────────────────────────────────────────────────────────────

    def test_format_contains_verdict(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        text = exp.format()
        self.assertIn("ALLOW", text)

    def test_format_shows_matched_rule_index(self):
        exp = self.ex.explain({"user": {"role": "user"}},
                              policy_text=SIMPLE_POLICY)
        text = exp.format()
        self.assertIn("Rule #1", text)

    def test_format_verbose_shows_skipped_rules(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        text = exp.format(verbose=True)
        self.assertIn("skipped", text)

    def test_format_non_verbose_hides_skipped_rules(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        text = exp.format(verbose=False)
        self.assertNotIn("skipped", text)

    def test_format_temporal_shows_reason(self):
        policy = (
            "policy future:\n"
            "    valid_from: 2099-01-01\n"
            "    when x == 1 => ALLOW\n"
        )
        exp = self.ex.explain({"x": 1}, policy_text=policy)
        text = exp.format()
        self.assertIn("Temporal", text)

    # ── to_dict ───────────────────────────────────────────────────────────────

    def test_to_dict_structure(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        d = exp.to_dict()
        self.assertIn("policy_name", d)
        self.assertIn("verdict", d)
        self.assertIn("matched_rule_index", d)
        self.assertIn("rule_traces", d)
        self.assertIsInstance(d["rule_traces"], list)

    def test_to_dict_rule_traces_have_expected_keys(self):
        exp = self.ex.explain({"user": {"role": "admin"}},
                              policy_text=SIMPLE_POLICY)
        d = exp.to_dict()
        trace = d["rule_traces"][0]
        for key in ("rule_index", "condition", "verdict", "matched",
                    "evaluated", "error"):
            self.assertIn(key, trace)

    # ── empty policy ──────────────────────────────────────────────────────────

    def test_explain_empty_policy_text_returns_deny(self):
        from utf.tarl.spec import TarlVerdict
        exp = self.ex.explain({"x": 1})
        self.assertEqual(exp.verdict, TarlVerdict.DENY)


# ══════════════════════════════════════════════════════════════════════════════
# TarlTestRunner / .tarl_test format
# ══════════════════════════════════════════════════════════════════════════════

_INLINE_SUITE = '''\
policy:
    when user.role == "admin" => ALLOW
    when user.role == "user"  => ALLOW

test "admin allowed":
    context: {"user": {"role": "admin"}}
    expect: ALLOW

test "user allowed":
    context: {"user": {"role": "user"}}
    expect: ALLOW

test "ghost denied":
    context: {"user": {"role": "ghost"}}
    expect: DENY
'''

_FAILING_SUITE = '''\
policy:
    when x == 1 => ALLOW

test "wrong expectation":
    context: {"x": 1}
    expect: DENY
'''

_EXPECT_RULE_SUITE = '''\
policy:
    when x >= 10 => ALLOW
    when x >= 5  => ESCALATE
    when x >= 0  => DENY

test "high score":
    context: {"x": 10}
    expect: ALLOW
    expect_rule: 0

test "mid score":
    context: {"x": 7}
    expect: ESCALATE
    expect_rule: 1
'''


class TestTarlTestRunner(unittest.TestCase):

    def setUp(self):
        from utf.tarl.tester import TarlTestRunner
        self.runner = TarlTestRunner()

    def _run(self, text, **kw):
        return self.runner.run_text(text, **kw)

    # ── parsing ───────────────────────────────────────────────────────────────

    def test_parse_inline_policy(self):
        result = self._run(_INLINE_SUITE)
        self.assertIsNone(result.load_error)
        self.assertEqual(result.total, 3)

    def test_all_passing(self):
        result = self._run(_INLINE_SUITE)
        self.assertEqual(result.passed, 3)
        self.assertEqual(result.failed, 0)

    def test_failing_verdict(self):
        result = self._run(_FAILING_SUITE)
        self.assertEqual(result.failed, 1)
        self.assertFalse(result.results[0].passed)

    def test_expect_rule_passes_when_correct(self):
        result = self._run(_EXPECT_RULE_SUITE)
        self.assertEqual(result.failed, 0, [str(r) for r in result.results])

    def test_expect_rule_fails_when_wrong_rule(self):
        suite = '''\
policy:
    when x >= 10 => ALLOW
    when x >= 5  => ALLOW

test "wrong rule":
    context: {"x": 15}
    expect: ALLOW
    expect_rule: 1
'''
        result = self._run(suite)
        self.assertEqual(result.failed, 1)
        r = result.results[0]
        self.assertEqual(r.actual_rule, 0)
        self.assertEqual(r.expected_rule, 1)

    def test_mixed_pass_fail(self):
        suite = '''\
policy:
    when x == 1 => ALLOW

test "pass":
    context: {"x": 1}
    expect: ALLOW

test "fail":
    context: {"x": 2}
    expect: ALLOW
'''
        result = self._run(suite)
        self.assertEqual(result.passed, 1)
        self.assertEqual(result.failed, 1)

    # ── policy_file directive ─────────────────────────────────────────────────

    def test_policy_file_directive_resolves_relative(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pol = os.path.join(tmpdir, "pol.tarl")
            with open(pol, "w") as f:
                f.write('when role == "admin" => ALLOW\n')
            suite_text = (
                'policy_file: pol.tarl\n\n'
                'test "admin":\n'
                '    context: {"role": "admin"}\n'
                '    expect: ALLOW\n'
            )
            result = self.runner.run_text(suite_text, base_dir=tmpdir)
            self.assertIsNone(result.load_error)
            self.assertEqual(result.passed, 1)

    def test_policy_file_not_found_returns_load_error(self):
        suite_text = (
            "policy_file: nonexistent.tarl\n\n"
            'test "x":\n'
            "    context: {}\n"
            "    expect: DENY\n"
        )
        result = self._run(suite_text)
        self.assertIsNotNone(result.load_error)
        self.assertEqual(result.total, 0)

    # ── error cases ───────────────────────────────────────────────────────────

    def test_no_policy_returns_load_error(self):
        suite = 'test "x":\n    context: {}\n    expect: DENY\n'
        result = self._run(suite)
        self.assertIsNotNone(result.load_error)

    def test_invalid_json_context_raises_load_error(self):
        suite = (
            "policy:\n    when x == 1 => ALLOW\n\n"
            "test \"bad\":\n    context: {bad json}\n    expect: ALLOW\n"
        )
        result = self._run(suite)
        self.assertIsNotNone(result.load_error)

    def test_invalid_expect_verdict_raises_load_error(self):
        suite = (
            "policy:\n    when x == 1 => ALLOW\n\n"
            'test "bad":\n    context: {}\n    expect: MAYBE\n'
        )
        result = self._run(suite)
        self.assertIsNotNone(result.load_error)

    # ── run_file ──────────────────────────────────────────────────────────────

    def test_run_file_not_found(self):
        result = self.runner.run_file("/nonexistent/path/suite.tarl_test")
        self.assertIsNotNone(result.load_error)

    def test_run_file_reads_and_passes(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl_test", delete=False
        ) as f:
            f.write(_INLINE_SUITE)
            f.flush()
            path = f.name
        try:
            result = self.runner.run_file(path)
            self.assertEqual(result.passed, 3)
        finally:
            os.unlink(path)

    # ── run_directory ─────────────────────────────────────────────────────────

    def test_run_directory_finds_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ("a.tarl_test", "b.tarl_test"):
                with open(os.path.join(tmpdir, name), "w") as f:
                    f.write(_INLINE_SUITE)
            results = self.runner.run_directory(tmpdir)
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r.passed == 3 for r in results))

    def test_run_directory_empty_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = self.runner.run_directory(tmpdir)
            self.assertEqual(results, [])

    # ── __str__ ───────────────────────────────────────────────────────────────

    def test_suite_result_str_pass(self):
        result = self._run(_INLINE_SUITE, file_path="suite.tarl_test")
        text = str(result)
        self.assertIn("3/3 passed", text)
        self.assertIn("PASS", text)

    def test_suite_result_str_fail(self):
        result = self._run(_FAILING_SUITE, file_path="suite.tarl_test")
        text = str(result)
        self.assertIn("FAIL", text)

    def test_suite_result_str_load_error(self):
        result = self.runner.run_file("/no/such/file.tarl_test")
        self.assertIn("ERROR", str(result))

    def test_test_result_str_pass(self):
        result = self._run(_INLINE_SUITE)
        self.assertIn("PASS", str(result.results[0]))

    def test_test_result_str_fail_shows_detail(self):
        result = self._run(_FAILING_SUITE)
        text = str(result.results[0])
        self.assertIn("FAIL", text)
        self.assertIn("ALLOW", text)   # actual
        self.assertIn("DENY", text)    # expected

    # ── ok property ───────────────────────────────────────────────────────────

    def test_ok_true_when_all_pass(self):
        result = self._run(_INLINE_SUITE)
        self.assertTrue(result.ok)

    def test_ok_false_when_any_fail(self):
        result = self._run(_FAILING_SUITE)
        self.assertFalse(result.ok)


# ══════════════════════════════════════════════════════════════════════════════
# TarlLanguageServer
# ══════════════════════════════════════════════════════════════════════════════

class TestTarlLanguageServer(unittest.TestCase):

    def _server(self):
        from utf.tarl.lsp import TarlLanguageServer
        return TarlLanguageServer(
            stdin=io.BytesIO(b""),
            stdout=io.BytesIO(),
        )

    # ── validate ──────────────────────────────────────────────────────────────

    def test_validate_clean_document_no_diags(self):
        srv = self._server()
        diags = srv.validate(SIMPLE_POLICY)
        # Only check for Error (severity=1) diagnostics; hints/warnings ok
        errors = [d for d in diags if d["severity"] == 1]
        self.assertEqual(errors, [])

    def test_validate_empty_document_no_diags(self):
        srv = self._server()
        self.assertEqual(srv.validate(""), [])

    def test_validate_bad_token_produces_error(self):
        srv = self._server()
        bad_policy = "policy p:\n    when @@@invalid => ALLOW\n"
        diags = srv.validate(bad_policy)
        errors = [d for d in diags if d["severity"] == 1]
        self.assertGreater(len(errors), 0)
        self.assertIn("syntax error", errors[0]["message"].lower())

    def test_validate_diagnostic_has_required_keys(self):
        srv = self._server()
        diags = srv.validate(SIMPLE_POLICY)
        # Even with no errors, coverage hint may appear — check structure
        for d in diags:
            self.assertIn("range", d)
            self.assertIn("severity", d)
            self.assertIn("message", d)
            self.assertIn("source", d)

    # ── hover_at ─────────────────────────────────────────────────────────────

    def test_hover_on_rule_line_returns_markdown(self):
        srv = self._server()
        # SIMPLE_POLICY line 1 (0-based) is "    when user.role == "admin" => ALLOW"
        result = srv.hover_at(SIMPLE_POLICY, line=1)
        self.assertIsNotNone(result)
        self.assertIn("ALLOW", result)
        self.assertIn("T.A.R.L. Rule", result)

    def test_hover_on_second_rule_line(self):
        srv = self._server()
        result = srv.hover_at(SIMPLE_POLICY, line=2)
        self.assertIsNotNone(result)
        self.assertIn("ALLOW", result)

    def test_hover_on_policy_header(self):
        srv = self._server()
        result = srv.hover_at(SIMPLE_POLICY, line=0)
        self.assertIsNotNone(result)
        self.assertIn("access", result)

    def test_hover_out_of_range_returns_none(self):
        srv = self._server()
        result = srv.hover_at(SIMPLE_POLICY, line=999)
        self.assertIsNone(result)

    def test_hover_time_bound_rule_shows_duration(self):
        srv = self._server()
        policy = "policy tb:\n    when x == 1 => ALLOW for: 2h\n"
        result = srv.hover_at(policy, line=1)
        self.assertIsNotNone(result)
        self.assertIn("2h", result)

    # ── definition_at ─────────────────────────────────────────────────────────

    def test_definition_extends_jumps_to_parent(self):
        srv = self._server()
        text = (
            "policy base:\n"
            "    when x == 1 => ALLOW\n"
            "\n"
            "policy child EXTENDS base:\n"
            "    when y == 2 => DENY\n"
        )
        result = srv.definition_at(text, "file:///doc.tarl", line_idx=3)
        self.assertIsNotNone(result)
        self.assertEqual(result["uri"], "file:///doc.tarl")
        self.assertEqual(result["range"]["start"]["line"], 0)

    def test_definition_no_parent_returns_none(self):
        srv = self._server()
        result = srv.definition_at(SIMPLE_POLICY, "file:///doc.tarl", 0)
        self.assertIsNone(result)

    def test_definition_out_of_range_returns_none(self):
        srv = self._server()
        result = srv.definition_at(SIMPLE_POLICY, "file:///doc.tarl", 999)
        self.assertIsNone(result)

    # ── on_initialize ─────────────────────────────────────────────────────────

    def test_initialize_returns_capabilities(self):
        srv = self._server()
        result = srv._on_initialize({})
        self.assertIn("capabilities", result)
        caps = result["capabilities"]
        self.assertIn("textDocumentSync", caps)
        self.assertIn("hoverProvider", caps)
        self.assertIn("definitionProvider", caps)
        self.assertIn("serverInfo", result)

    # ── on_shutdown ───────────────────────────────────────────────────────────

    def test_shutdown_sets_running_false(self):
        srv = self._server()
        self.assertTrue(srv._running)
        srv._on_shutdown({})
        self.assertFalse(srv._running)

    # ── document sync ─────────────────────────────────────────────────────────

    def test_did_open_stores_document(self):
        srv = self._server()
        srv._on_did_open({
            "textDocument": {"uri": "file:///a.tarl", "text": SIMPLE_POLICY}
        })
        self.assertIn("file:///a.tarl", srv._docs)

    def test_did_change_updates_document(self):
        srv = self._server()
        srv._docs["file:///a.tarl"] = "old"
        srv._on_did_change({
            "textDocument": {"uri": "file:///a.tarl"},
            "contentChanges": [{"text": SIMPLE_POLICY}],
        })
        self.assertEqual(srv._docs["file:///a.tarl"], SIMPLE_POLICY)

    def test_did_close_removes_document(self):
        srv = self._server()
        srv._docs["file:///a.tarl"] = SIMPLE_POLICY
        srv._on_did_close({"textDocument": {"uri": "file:///a.tarl"}})
        self.assertNotIn("file:///a.tarl", srv._docs)

    # ── JSON-RPC framing ──────────────────────────────────────────────────────

    def test_message_roundtrip(self):
        from utf.tarl.lsp import _read_message, _write_message

        buf = io.BytesIO()
        msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        _write_message(buf, msg)

        buf.seek(0)
        recovered = _read_message(buf)
        self.assertEqual(recovered["id"], 1)
        self.assertEqual(recovered["method"], "initialize")

    def test_dispatch_unknown_method_with_id_replies_null(self):
        from utf.tarl.lsp import _read_message

        req = json.dumps({
            "jsonrpc": "2.0", "id": 99, "method": "$/unknown", "params": {}
        }).encode()
        header = f"Content-Length: {len(req)}\r\n\r\n".encode()
        stdin = io.BytesIO(header + req)
        stdout = io.BytesIO()

        from utf.tarl.lsp import TarlLanguageServer
        srv = TarlLanguageServer(stdin=stdin, stdout=stdout)
        # Read one message and dispatch
        _read_message(stdin)
        stdin.seek(0)  # reset for run() to consume
        srv._dispatch({"jsonrpc": "2.0", "id": 99, "method": "$/unknown",
                        "params": {}})

        stdout.seek(0)
        response = _read_message(stdout)
        self.assertIsNotNone(response)
        self.assertEqual(response["id"], 99)
        self.assertIsNone(response["result"])


# ══════════════════════════════════════════════════════════════════════════════
# CLI integration — tarl explain
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIExplain(unittest.TestCase):

    def _run_cli(self, args, stdin_text=None):
        """Run utf.tarl.cli.main with the given sys.argv and capture stdout."""
        import io as _io
        from unittest.mock import patch

        buf = _io.StringIO()
        with patch("sys.argv", args), \
             patch("sys.stdout", buf):
            try:
                from utf.tarl.cli import main
                main()
            except SystemExit:
                pass
        return buf.getvalue()

    def test_explain_basic(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl", delete=False
        ) as f:
            f.write(SIMPLE_POLICY)
            path = f.name
        try:
            out = self._run_cli([
                "tarl", "explain", path,
                "--context", '{"user": {"role": "admin"}}',
            ])
            self.assertIn("ALLOW", out)
        finally:
            os.unlink(path)

    def test_explain_json_output(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl", delete=False
        ) as f:
            f.write(SIMPLE_POLICY)
            path = f.name
        try:
            out = self._run_cli([
                "tarl", "explain", path,
                "--context", '{"user": {"role": "admin"}}',
                "--json",
            ])
            data = json.loads(out)
            self.assertEqual(data["verdict"], "ALLOW")
            self.assertIn("rule_traces", data)
        finally:
            os.unlink(path)

    def test_explain_default_deny(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl", delete=False
        ) as f:
            f.write(SIMPLE_POLICY)
            path = f.name
        try:
            out = self._run_cli([
                "tarl", "explain", path,
                "--context", '{"user": {"role": "nobody"}}',
            ])
            self.assertIn("DENY", out)
            self.assertIn("DEFAULT_DENY", out)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# CLI integration — tarl test
# ══════════════════════════════════════════════════════════════════════════════

class TestCLITest(unittest.TestCase):

    def _run_cli(self, args):
        import io as _io
        from unittest.mock import patch

        buf = _io.StringIO()
        exit_code = 0
        with patch("sys.argv", args), \
             patch("sys.stdout", buf):
            try:
                from utf.tarl.cli import main
                main()
            except SystemExit as exc:
                exit_code = int(exc.code) if exc.code is not None else 0
        return buf.getvalue(), exit_code

    def test_test_all_pass_exit_0(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl_test", delete=False
        ) as f:
            f.write(_INLINE_SUITE)
            path = f.name
        try:
            out, code = self._run_cli(["tarl", "test", path])
            self.assertEqual(code, 0)
            self.assertIn("3/3", out)
        finally:
            os.unlink(path)

    def test_test_fail_exit_1(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl_test", delete=False
        ) as f:
            f.write(_FAILING_SUITE)
            path = f.name
        try:
            _, code = self._run_cli(["tarl", "test", path])
            self.assertEqual(code, 1)
        finally:
            os.unlink(path)

    def test_test_json_output(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tarl_test", delete=False
        ) as f:
            f.write(_INLINE_SUITE)
            path = f.name
        try:
            out, _ = self._run_cli(["tarl", "test", path, "--json"])
            data = json.loads(out)
            self.assertIsInstance(data, list)
            self.assertEqual(data[0]["passed"], 3)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Public API exports
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase6APIExports(unittest.TestCase):

    def test_all_phase6_symbols_in_all(self):
        import utf.tarl as tarl
        expected = [
            "TarlExplainer",
            "PolicyExplanation",
            "RuleTrace",
            "TarlTestRunner",
            "TarlTestSuiteResult",
            "TarlTestResult",
            "TarlTestCase",
        ]
        for name in expected:
            with self.subTest(name=name):
                self.assertIn(name, tarl.__all__)
                self.assertTrue(hasattr(tarl, name))

    def test_explainer_importable_directly(self):
        from utf.tarl.explainer import TarlExplainer
        self.assertTrue(callable(TarlExplainer))

    def test_tester_importable_directly(self):
        from utf.tarl.tester import (
            TarlTestRunner,
        )
        self.assertTrue(callable(TarlTestRunner))

    def test_lsp_importable(self):
        from utf.tarl.lsp import TarlLanguageServer, main
        self.assertTrue(callable(TarlLanguageServer))
        self.assertTrue(callable(main))


if __name__ == "__main__":
    unittest.main()
