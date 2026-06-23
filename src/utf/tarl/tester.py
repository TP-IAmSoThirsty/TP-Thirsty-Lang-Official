"""
T.A.R.L. Test Runner — Phase 6

Parses and runs .tarl_test files, reporting pass/fail for each case.

File format::

    # Optional comment
    policy_file: path/to/policy.tarl

    # Or an inline policy (alternative to policy_file):
    policy:
        when user.role == "admin" => ALLOW
        when user.role == "user"  => ALLOW

    test "admin is always allowed":
        context: {"user": {"role": "admin"}}
        expect: ALLOW

    test "unknown defaults deny":
        context: {"user": {"role": "ghost"}}
        expect: DENY
        expect_rule: -1

Directives:
  policy_file: <path>          — path to .tarl file (relative to the test file)
  policy:                      — inline policy block (indented lines)
  test "<name>":               — opens a test case
    context: <json-object>     — evaluation context as JSON
    expect: ALLOW|DENY|ESCALATE
    expect_rule: <int>         — optional; asserts which rule index matched
"""
from __future__ import annotations

import glob as _glob
import json
import os
from dataclasses import dataclass, field

from utf.tarl.core import PolicyParser, evaluate_policy
from utf.tarl.spec import TarlVerdict


@dataclass
class TarlTestCase:
    """A single test case parsed from a .tarl_test file."""
    name: str
    context: dict
    expect: TarlVerdict
    expect_rule: int | None = None
    source_line: int = 0


@dataclass
class TarlTestFile:
    """Parsed representation of a complete .tarl_test file."""
    policy_file: str | None = None
    policy_text: str | None = None
    tests: list[TarlTestCase] = field(default_factory=list)


@dataclass
class TarlTestResult:
    """Result of running a single test case."""
    name: str
    passed: bool
    expected: TarlVerdict
    actual: TarlVerdict
    expected_rule: int | None = None
    actual_rule: int = -1
    error: str | None = None

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        if self.passed:
            return f"  {status}  {self.name}"
        if self.error:
            return f"  {status}  {self.name}  [{self.error}]"
        detail = f"expected {self.expected.value}, got {self.actual.value}"
        if self.expected_rule is not None:
            detail += (
                f"; rule expected {self.expected_rule},"
                f" got {self.actual_rule}"
            )
        return f"  {status}  {self.name}  [{detail}]"


@dataclass
class TarlTestSuiteResult:
    """Aggregated results for a single .tarl_test file."""
    file_path: str
    total: int
    passed: int
    failed: int
    results: list[TarlTestResult]
    load_error: str | None = None

    def __str__(self) -> str:
        if self.load_error:
            return f"ERROR  {self.file_path}: {self.load_error}"
        header = f"{self.file_path}: {self.passed}/{self.total} passed"
        lines = [header]
        for r in self.results:
            lines.append(str(r))
        return "\n".join(lines)

    @property
    def ok(self) -> bool:
        return self.load_error is None and self.failed == 0


class TarlTestRunner:
    """
    Parses and executes .tarl_test suites.

    Usage::

        runner = TarlTestRunner()

        # Single file
        result = runner.run_file("tests/access.tarl_test")
        print(result)

        # All .tarl_test files under a directory (recursive)
        for result in runner.run_directory("tests/policies/"):
            print(result)
    """

    def run_file(self, path: str) -> TarlTestSuiteResult:
        """Run a single .tarl_test file."""
        base_dir = os.path.dirname(os.path.abspath(path))
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            return TarlTestSuiteResult(
                file_path=path, total=0, passed=0, failed=0,
                results=[], load_error=str(exc),
            )
        return self._run_text(text, base_dir=base_dir, file_path=path)

    def run_directory(self, path: str) -> list[TarlTestSuiteResult]:
        """
        Recursively find and run all .tarl_test files under path.
        Returns results in sorted order by file path.
        """
        pattern = os.path.join(path, "**", "*.tarl_test")
        paths = sorted(_glob.glob(pattern, recursive=True))
        return [self.run_file(p) for p in paths]

    def run_text(
        self,
        text: str,
        base_dir: str = ".",
        file_path: str = "<inline>",
    ) -> TarlTestSuiteResult:
        """Parse and run test cases from a text string."""
        return self._run_text(text, base_dir=base_dir, file_path=file_path)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run_text(
        self,
        text: str,
        base_dir: str,
        file_path: str,
    ) -> TarlTestSuiteResult:
        try:
            suite = self._parse(text)
        except ValueError as exc:
            return TarlTestSuiteResult(
                file_path=file_path, total=0, passed=0, failed=0,
                results=[], load_error=str(exc),
            )

        policy_text: str | None = suite.policy_text
        if policy_text is None and suite.policy_file:
            ppath = (
                suite.policy_file if os.path.isabs(suite.policy_file)
                else os.path.join(base_dir, suite.policy_file)
            )
            try:
                with open(ppath, encoding="utf-8") as fh:
                    policy_text = fh.read()
            except OSError as exc:
                return TarlTestSuiteResult(
                    file_path=file_path, total=0, passed=0, failed=0,
                    results=[],
                    load_error=f"Cannot open policy_file {ppath!r}: {exc}",
                )

        if policy_text is None:
            return TarlTestSuiteResult(
                file_path=file_path, total=0, passed=0, failed=0,
                results=[],
                load_error="No policy_file or inline policy defined",
            )

        policy = PolicyParser.parse(policy_text)
        results: list[TarlTestResult] = []
        for tc in suite.tests:
            results.append(self._run_case(tc, policy))

        passed = sum(1 for r in results if r.passed)
        return TarlTestSuiteResult(
            file_path=file_path,
            total=len(results),
            passed=passed,
            failed=len(results) - passed,
            results=results,
        )

    def _run_case(self, tc: TarlTestCase, policy) -> TarlTestResult:
        try:
            decision = evaluate_policy(tc.context, policy=policy)
        except Exception as exc:
            return TarlTestResult(
                name=tc.name,
                passed=False,
                expected=tc.expect,
                actual=TarlVerdict.DENY,
                expected_rule=tc.expect_rule,
                actual_rule=-1,
                error=f"Evaluation error: {exc}",
            )

        verdict_ok = decision.verdict == tc.expect
        rule_ok = (
            tc.expect_rule is None
            or decision.rule_index == tc.expect_rule
        )
        return TarlTestResult(
            name=tc.name,
            passed=verdict_ok and rule_ok,
            expected=tc.expect,
            actual=decision.verdict,
            expected_rule=tc.expect_rule,
            actual_rule=decision.rule_index,
        )

    def _parse(self, text: str) -> TarlTestFile:
        """
        Parse .tarl_test text into a TarlTestFile.

        Raises ValueError on malformed directives.
        """
        suite = TarlTestFile()
        lines = text.split("\n")
        n = len(lines)
        i = 0
        current_test: dict | None = None
        inline_mode = False   # True when collecting indented policy lines

        def _flush() -> None:
            if current_test is None:
                return
            name = current_test.get("name", "unnamed")
            raw_ctx = current_test.get("context", "{}")
            try:
                ctx = json.loads(raw_ctx)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON context in test {name!r}: {exc}"
                ) from exc
            raw_expect = current_test.get("expect", "")
            try:
                expect = TarlVerdict(raw_expect.upper())
            except ValueError as exc:
                raise ValueError(
                    f"Invalid expect verdict {raw_expect!r} in test {name!r}."
                    f" Must be ALLOW, DENY, or ESCALATE."
                ) from exc
            raw_rule = current_test.get("expect_rule")
            expect_rule = int(raw_rule) if raw_rule is not None else None
            suite.tests.append(TarlTestCase(
                name=name,
                context=ctx,
                expect=expect,
                expect_rule=expect_rule,
                source_line=current_test.get("line", 0),
            ))

        inline_policy_lines: list[str] = []

        while i < n:
            raw = lines[i]
            stripped = raw.strip()
            i += 1

            if not stripped or stripped.startswith("#"):
                if inline_mode:
                    inline_policy_lines.append("")
                continue

            # Collecting inline policy block
            if inline_mode:
                if raw.startswith(("  ", "\t")):
                    inline_policy_lines.append(stripped)
                    continue
                else:
                    # Non-indented line ends the inline policy block
                    inline_mode = False
                    while inline_policy_lines and not inline_policy_lines[-1]:
                        inline_policy_lines.pop()
                    suite.policy_text = "\n".join(inline_policy_lines)

            if stripped.startswith("policy_file:"):
                suite.policy_file = stripped[len("policy_file:"):].strip()
                continue

            if stripped == "policy:" or stripped.startswith("policy: |"):
                inline_mode = True
                inline_policy_lines = []
                continue

            if stripped.startswith("test ") and stripped.endswith(":"):
                _flush()
                current_test = {"line": i}
                rest = stripped[5:-1].strip()
                if (rest.startswith('"') and rest.endswith('"')) or \
                   (rest.startswith("'") and rest.endswith("'")):
                    rest = rest[1:-1]
                current_test["name"] = rest
                continue

            if current_test is not None:
                if stripped.startswith("context:"):
                    current_test["context"] = stripped[len("context:"):].strip()
                elif stripped.startswith("expect_rule:"):
                    current_test["expect_rule"] = stripped[len("expect_rule:"):].strip()
                elif stripped.startswith("expect:"):
                    current_test["expect"] = stripped[len("expect:"):].strip()

        # End of file: close any open inline policy block
        if inline_mode:
            while inline_policy_lines and not inline_policy_lines[-1]:
                inline_policy_lines.pop()
            suite.policy_text = "\n".join(inline_policy_lines)

        _flush()
        return suite
