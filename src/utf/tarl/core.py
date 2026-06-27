"""
T.A.R.L. Core — Phase 1+2: Condition Algebra and Policy Parser

Phase 1 — SafeExpr supports:
  - Nested attribute access: user.role.clearance
  - Full arithmetic: +, -, *, /, %
  - Set membership: value IN [...] / NOT IN [...]
  - Dynamic sources: source:name (resolved by TarlRuntime)
  - Temporal builtins: CURRENT_HOUR, CURRENT_DAY, CURRENT_WEEKDAY, etc.
  - String predicates: MATCHES, STARTS_WITH, ENDS_WITH, CONTAINS
  - Utility functions: LEN, LOWER, UPPER, ELAPSED_SINCE
  - Universal/existential quantifiers: ALL(col, v -> cond), ANY(...)

Phase 2 — PolicyParser supports:
  - EXTENDS / RESTRICTS composition
  - INCLUDE <name>|"<file>" [AS <alias>]
  - STOP keyword (blocks parent fallthrough in EXTENDS)
  - policy_set with combine UNION|INTERSECT|MAJORITY [...]
  - Temporal versioning stubs: valid_from, valid_until, supersedes, on_expiry
  - parse_all() for multi-policy files
"""
import datetime
import re
from typing import Any, Optional

from utf.tarl.spec import (
    DEFAULT_DENY,
    CompositionOp,
    SetOp,
    TarlDecision,
    TarlPolicy,
    TarlPolicyRef,
    TarlPolicySet,
    TarlRule,
    TarlVerdict,
)

# ── Token types ──────────────────────────────────────────────────────────────
INT = "INT"
FLOAT = "FLOAT"
STRING = "STRING"
BOOL_TRUE = "BOOL_TRUE"
BOOL_FALSE = "BOOL_FALSE"
IDENT = "IDENT"
SOURCE = "SOURCE"       # source:name — resolved by runtime
# Arithmetic
PLUS = "PLUS"
MINUS = "MINUS"
STAR = "STAR"
SLASH = "SLASH"
PERCENT = "PERCENT"
# Comparisons
EQEQ = "EQEQ"
NE = "NE"
LT = "LT"
GT = "GT"
LE = "LE"
GE = "GE"
# Logic
AND = "AND"
OR = "OR"
NOT = "NOT"
IN = "IN"
# Structure
DOT = "DOT"
COMMA = "COMMA"
ARROW = "ARROW"         # ->
LBRACKET = "LBRACKET"
RBRACKET = "RBRACKET"
LPAREN = "LPAREN"
RPAREN = "RPAREN"
EOF = "EOF"

_KEYWORDS = {
    "and": AND, "or": OR, "not": NOT, "in": IN,
    "true": BOOL_TRUE, "false": BOOL_FALSE,
}

_TEMPORAL_BUILTINS = frozenset({
    "CURRENT_HOUR", "CURRENT_DAY", "CURRENT_WEEKDAY",
    "CURRENT_MONTH", "CURRENT_YEAR", "CURRENT_TIMESTAMP",
})

_SAFE_FUNCTIONS = frozenset({
    "MATCHES", "STARTS_WITH", "ENDS_WITH", "CONTAINS",
    "ELAPSED_SINCE", "LEN", "LOWER", "UPPER",
})

_QUANTIFIERS = frozenset({"ALL", "ANY"})


class ExprToken:
    __slots__ = ("type", "value", "pos")

    def __init__(self, type: str, value, pos: int = 0):
        self.type = type
        self.value = value
        self.pos = pos

    def __repr__(self) -> str:
        return f"ExprToken({self.type}, {self.value!r})"


class PolicyParser:
    """Parses TARL policy text into TarlPolicy / TarlPolicySet objects."""

    RULE_RE = re.compile(
        r"when\s+(.+?)\s*=>\s*(ALLOW|DENY|ESCALATE)"
        r"(?:\s+for:\s*(\S+))?\s*$"
    )
    # policy <name> [EXTENDS|RESTRICTS <parent>] [v<ver>] [:]
    POLICY_HEADER_RE = re.compile(
        r"policy\s+(\w+)"
        r"(?:\s+(EXTENDS|RESTRICTS)\s+(\w+))?"
        r"(?:\s+v([\w.]+))?"
        r"\s*:?"
    )
    POLICY_SET_HEADER_RE = re.compile(r"policy_set\s+(\w+)\s*:")
    # INCLUDE "path/to/file.tarl" AS alias
    # INCLUDE policy_name AS alias
    INCLUDE_RE = re.compile(
        r'INCLUDE\s+(?:"([^"]+)"|(\w+))'
        r'(?:\s+AS\s+(\w+))?'
    )
    # combine UNION|INTERSECT|MAJORITY [p1, p2, ...]
    COMBINE_RE = re.compile(
        r"combine\s+(UNION|INTERSECT|MAJORITY)\s+\[([^\]]+)\]"
    )
    # default: ALLOW|DENY|ESCALATE
    DEFAULT_RE = re.compile(
        r"default\s*:\s*(ALLOW|DENY|ESCALATE)"
    )
    # valid_from|valid_until|supersedes|on_expiry: <value>
    METADATA_RE = re.compile(
        r"(valid_from|valid_until|supersedes|on_expiry)\s*:\s*(.+)"
    )
    # if_unresolved_after: <duration> => revert_to: <policy_name>
    IF_UNRESOLVED_RE = re.compile(
        r"if_unresolved_after:\s*(\S+)\s*=>\s*revert_to:\s*(\w+)"
    )

    @classmethod
    def parse_all(cls, text: str) -> list:
        """
        Parse text containing one or more policy/policy_set blocks.
        Returns a list of TarlPolicy and TarlPolicySet objects.
        Bare rules (no policy header) accumulate into an 'unnamed' policy.
        """
        results: list[Any] = []
        current_policy: TarlPolicy | None = None
        current_set: TarlPolicySet | None = None

        def _flush():
            nonlocal current_policy, current_set
            if current_policy is not None:
                results.append(current_policy)
                current_policy = None
            if current_set is not None:
                results.append(current_set)
                current_set = None

        for lineno, raw_line in enumerate(text.split("\n"), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # ── policy_set header ─────────────────────────────────────────
            m_ps = cls.POLICY_SET_HEADER_RE.match(line)
            if m_ps:
                _flush()
                current_set = TarlPolicySet(name=m_ps.group(1))
                continue

            # ── policy header ─────────────────────────────────────────────
            m_ph = cls.POLICY_HEADER_RE.match(line)
            if m_ph:
                _flush()
                current_policy = TarlPolicy(source=line, name=m_ph.group(1))
                if m_ph.group(2):
                    current_policy.composition = CompositionOp(m_ph.group(2))
                    current_policy.parent = m_ph.group(3)
                if m_ph.group(4):
                    current_policy.version = m_ph.group(4)
                continue

            # ── policy_set body ───────────────────────────────────────────
            if current_set is not None:
                m_combine = cls.COMBINE_RE.match(line)
                if m_combine:
                    op = SetOp(m_combine.group(1))
                    names = [
                        n.strip() for n in m_combine.group(2).split(",")
                        if n.strip()
                    ]
                    current_set.groups.append((op, names))
                    continue
                m_def = cls.DEFAULT_RE.match(line)
                if m_def:
                    current_set.default_verdict = TarlVerdict(
                        m_def.group(1)
                    )
                continue

            # ── policy body ───────────────────────────────────────────────
            if current_policy is None:
                current_policy = TarlPolicy(source="", name="unnamed")

            if line == "STOP":
                current_policy.has_stop = True
                continue

            m_inc = cls.INCLUDE_RE.match(line)
            if m_inc:
                file_path = m_inc.group(1)
                pol_name = m_inc.group(2)
                alias = m_inc.group(3)
                ref = TarlPolicyRef(
                    name=file_path if file_path else pol_name,
                    alias=alias,
                    is_file=bool(file_path),
                )
                current_policy.includes.append(ref)
                continue

            m_iu = cls.IF_UNRESOLVED_RE.match(line)
            if m_iu:
                dur = _parse_duration(m_iu.group(1))
                if dur is not None:
                    current_policy.if_unresolved_after = dur
                current_policy.revert_to = m_iu.group(2)
                continue

            m_meta = cls.METADATA_RE.match(line)
            if m_meta:
                key, val = m_meta.group(1), m_meta.group(2).strip()
                if key == "valid_from":
                    current_policy.valid_from = val
                elif key == "valid_until":
                    current_policy.valid_until = val
                elif key == "supersedes":
                    current_policy.supersedes = val
                elif key == "on_expiry":
                    try:
                        current_policy.on_expiry = TarlVerdict(
                            val.upper()
                        )
                    except ValueError:
                        current_policy.on_expiry = None
                continue

            m_rule = cls.RULE_RE.match(line)
            if m_rule:
                condition = m_rule.group(1).strip()
                verdict = TarlVerdict(m_rule.group(2).upper())
                duration = (
                    _parse_duration(m_rule.group(3))
                    if m_rule.group(3) else None
                )
                current_policy.rules.append(TarlRule(
                    condition=condition,
                    verdict=verdict,
                    source_line=lineno,
                    duration_seconds=duration,
                ))

        _flush()
        return results

    @classmethod
    def parse(cls, text: str, name: str = "unnamed") -> TarlPolicy:
        """
        Parse text and return the first TarlPolicy found.
        Backward-compatible: name is used when no policy header is present.
        """
        items = cls.parse_all(text)
        for item in items:
            if isinstance(item, TarlPolicy):
                if item.name == "unnamed" and name != "unnamed":
                    item.name = name
                item.source = text  # full source for proof hashing
                return item
        return TarlPolicy(source=text, name=name)

    @staticmethod
    def _tokenize(expr: str) -> list:
        tokens = []
        i = 0
        n = len(expr)
        while i < n:
            c = expr[i]

            # Whitespace
            if c in " \t":
                i += 1
                continue

            # Parentheses, brackets, comma
            if c == "(":
                tokens.append(ExprToken(LPAREN, "(", i))
                i += 1
            elif c == ")":
                tokens.append(ExprToken(RPAREN, ")", i))
                i += 1
            elif c == "[":
                tokens.append(ExprToken(LBRACKET, "[", i))
                i += 1
            elif c == "]":
                tokens.append(ExprToken(RBRACKET, "]", i))
                i += 1
            elif c == ",":
                tokens.append(ExprToken(COMMA, ",", i))
                i += 1
            elif c == ".":
                tokens.append(ExprToken(DOT, ".", i))
                i += 1

            # Two-char operators
            elif c == "=" and i + 1 < n and expr[i + 1] == "=":
                tokens.append(ExprToken(EQEQ, "==", i))
                i += 2
            elif c == "!" and i + 1 < n and expr[i + 1] == "=":
                tokens.append(ExprToken(NE, "!=", i))
                i += 2
            elif c == "<" and i + 1 < n and expr[i + 1] == "=":
                tokens.append(ExprToken(LE, "<=", i))
                i += 2
            elif c == ">" and i + 1 < n and expr[i + 1] == "=":
                tokens.append(ExprToken(GE, ">=", i))
                i += 2
            elif c == "-" and i + 1 < n and expr[i + 1] == ">":
                tokens.append(ExprToken(ARROW, "->", i))
                i += 2

            # Single-char comparison / arithmetic
            elif c == "<":
                tokens.append(ExprToken(LT, "<", i))
                i += 1
            elif c == ">":
                tokens.append(ExprToken(GT, ">", i))
                i += 1
            elif c == "+":
                tokens.append(ExprToken(PLUS, "+", i))
                i += 1
            elif c == "*":
                tokens.append(ExprToken(STAR, "*", i))
                i += 1
            elif c == "/":
                tokens.append(ExprToken(SLASH, "/", i))
                i += 1
            elif c == "%":
                tokens.append(ExprToken(PERCENT, "%", i))
                i += 1

            # Minus or negative number literal
            elif c == "-":
                nxt = expr[i + 1] if i + 1 < n else ""
                if nxt.isdigit():
                    start = i
                    i += 1
                    is_float = False
                    while i < n and (expr[i].isdigit() or expr[i] == "."):
                        if expr[i] == ".":
                            is_float = True
                        i += 1
                    s = expr[start:i]
                    tokens.append(
                        ExprToken(FLOAT if is_float else INT,
                                  float(s) if is_float else int(s), start)
                    )
                else:
                    tokens.append(ExprToken(MINUS, "-", i))
                    i += 1

            # String literals
            elif c == '"':
                i += 1
                chars = []
                while i < n and expr[i] != '"':
                    if expr[i] == "\\" and i + 1 < n:
                        i += 1
                        chars.append({"n": "\n", "t": "\t", "\\": "\\",
                                      '"': '"'}.get(expr[i], expr[i]))
                    else:
                        chars.append(expr[i])
                    i += 1
                i += 1
                tokens.append(ExprToken(STRING, "".join(chars), i))
            elif c == "'":
                i += 1
                chars = []
                while i < n and expr[i] != "'":
                    chars.append(expr[i])
                    i += 1
                i += 1
                tokens.append(ExprToken(STRING, "".join(chars), i))

            # Number literals
            elif c.isdigit():
                start = i
                is_float = False
                while i < n and (expr[i].isdigit() or expr[i] == "."):
                    if expr[i] == ".":
                        is_float = True
                    i += 1
                s = expr[start:i]
                tokens.append(
                    ExprToken(FLOAT if is_float else INT,
                              float(s) if is_float else int(s), start)
                )

            # Identifiers and keywords
            elif c.isalpha() or c == "_":
                start = i
                while i < n and (expr[i].isalnum() or expr[i] == "_"):
                    i += 1
                word = expr[start:i]

                # source:name — no whitespace allowed between source and :
                if word == "source" and i < n and expr[i] == ":":
                    i += 1
                    src_start = i
                    while i < n and (expr[i].isalnum() or expr[i] == "_"):
                        i += 1
                    tokens.append(ExprToken(SOURCE, expr[src_start:i], start))
                    continue

                word_lower = word.lower()
                if word_lower in _KEYWORDS:
                    ktype = _KEYWORDS[word_lower]
                    val = True if ktype == BOOL_TRUE else (
                        False if ktype == BOOL_FALSE else word_lower
                    )
                    tokens.append(ExprToken(ktype, val, start))
                else:
                    tokens.append(ExprToken(IDENT, word, start))

            else:
                raise ValueError(f"Unexpected character {c!r} at position {i}")

        tokens.append(ExprToken(EOF, None, i))
        return tokens


# ── Duration parsing / temporal utilities ────────────────────────────────────

def _parse_duration(s: str) -> int | None:
    """
    Parse a human-readable duration string into seconds.
    Supports units: s (seconds), m (minutes), h (hours), d (days), w (weeks).
    Compound forms like '1h30m' are supported. Returns None on parse error.

    Examples: '4h' → 14400, '30m' → 1800, '1d' → 86400, '1h30m' → 5400
    """
    if not s:
        return None
    units = {'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}
    total = 0
    num = ""
    for ch in s.strip():
        if ch.isdigit():
            num += ch
        elif ch in units:
            if not num:
                return None
            total += int(num) * units[ch]
            num = ""
        else:
            return None
    if num:  # trailing digits without unit → seconds
        total += int(num)
    return total if total > 0 else None


def _check_policy_temporal(policy: "TarlPolicy") -> Optional["TarlDecision"]:
    """
    Check whether a policy is within its declared effective time window.

    Returns a TarlDecision when the policy is outside its window (not-yet-active
    or expired/auto-expired), using policy.on_expiry or ESCALATE as the verdict.
    Returns None when the policy is in-window and should be evaluated normally.
    """
    now = datetime.datetime.now(datetime.UTC)
    expiry_verdict = policy.on_expiry or TarlVerdict.ESCALATE

    def _parse_dt(s: str) -> datetime.datetime | None:
        s = s.strip().replace("Z", "+00:00")
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.UTC)
            return dt
        except ValueError:
            return None

    # Not-yet-active check
    if policy.valid_from:
        vf = _parse_dt(policy.valid_from)
        if vf and now < vf:
            return TarlDecision(
                verdict=expiry_verdict,
                reason=(
                    f"Policy '{policy.name}' not yet effective "
                    f"(valid_from: {policy.valid_from})"
                ),
            )

    # Build effective_until = min(valid_until, valid_from + if_unresolved_after)
    effective_until: datetime.datetime | None = None
    if policy.valid_until:
        effective_until = _parse_dt(policy.valid_until)
    if policy.if_unresolved_after is not None and policy.valid_from:
        vf = _parse_dt(policy.valid_from)
        if vf:
            succession_at = vf + datetime.timedelta(
                seconds=policy.if_unresolved_after
            )
            if effective_until is None or succession_at < effective_until:
                effective_until = succession_at

    if effective_until and now > effective_until:
        return TarlDecision(
            verdict=expiry_verdict,
            reason=(
                f"Policy '{policy.name}' expired "
                f"(effective until: {effective_until.isoformat()})"
            ),
        )

    return None


# ── Temporal builtins ────────────────────────────────────────────────────────

def _resolve_temporal(name: str):
    now = datetime.datetime.now()
    return {
        "CURRENT_HOUR": now.hour,
        "CURRENT_DAY": now.day,
        "CURRENT_WEEKDAY": now.strftime("%A").upper(),
        "CURRENT_MONTH": now.month,
        "CURRENT_YEAR": now.year,
        "CURRENT_TIMESTAMP": now.isoformat(),
    }.get(name, False)


# ── Safe built-in functions ──────────────────────────────────────────────────

def _call_safe_function(name: str, args: list):
    try:
        if name == "MATCHES":
            return bool(re.search(str(args[1]), str(args[0])))
        if name == "STARTS_WITH":
            return str(args[0]).startswith(str(args[1]))
        if name == "ENDS_WITH":
            return str(args[0]).endswith(str(args[1]))
        if name == "CONTAINS":
            return str(args[1]) in str(args[0])
        if name == "LEN":
            v = args[0]
            return len(v) if isinstance(v, (str, list, dict, set)) else 0
        if name == "LOWER":
            return str(args[0]).lower()
        if name == "UPPER":
            return str(args[0]).upper()
        if name == "ELAPSED_SINCE":
            past = datetime.datetime.fromisoformat(str(args[0]))
            now = datetime.datetime.now(tz=past.tzinfo)
            return (now - past).total_seconds()
    except (IndexError, ValueError, TypeError, AttributeError):
        return False
    return False


# ── Expression evaluator ─────────────────────────────────────────────────────

class SafeExpr:
    """
    Sandboxed condition algebra evaluator.

    Grammar (precedence low → high):
      expr         := and_expr  (OR and_expr)*
      and_expr     := not_expr  (AND not_expr)*
      not_expr     := NOT not_expr | comparison
      comparison   := additive  [(==|!=|<|>|<=|>=) additive |
                                  [NOT] IN in_rhs]
      additive     := multiplicative  ((+|-) multiplicative)*
      multiplicative := unary  ((*|/|%) unary)*
      unary        := -unary | primary
      primary      := literal | ident_or_call | (expr) | inline_set
    """

    class ParseError(Exception):
        pass

    @classmethod
    def evaluate(cls, expr, context: dict) -> bool:
        tokens = (PolicyParser._tokenize(expr)
                  if isinstance(expr, str) else expr)
        parser = cls(tokens)
        result = parser.parse_expr()
        if parser.current().type != EOF:
            raise cls.ParseError(f"Unexpected token: {parser.current()}")
        return bool(cls._eval_node(result, context))

    def __init__(self, tokens: list[ExprToken]):
        self.tokens = tokens
        self.pos = 0

    def current(self) -> ExprToken:
        return (self.tokens[self.pos] if self.pos < len(self.tokens)
                else ExprToken(EOF, None))

    def _peek(self) -> ExprToken:
        p = self.pos + 1
        return (self.tokens[p] if p < len(self.tokens)
                else ExprToken(EOF, None))

    def advance(self) -> ExprToken:
        tok = self.current()
        self.pos += 1
        return tok

    def expect(self, *types) -> ExprToken:
        tok = self.current()
        if tok.type not in types:
            raise self.ParseError(
                f"Expected {types}, got {tok.type}({tok.value!r})"
            )
        return self.advance()

    # or
    def parse_expr(self):
        left = self.parse_and_expr()
        while self.current().type == OR:
            self.advance()
            left = ("or", left, self.parse_and_expr())
        return left

    # and
    def parse_and_expr(self):
        left = self.parse_not_expr()
        while self.current().type == AND:
            self.advance()
            left = ("and", left, self.parse_not_expr())
        return left

    # unary not  (NOT IN is handled in parse_comparison, not here)
    def parse_not_expr(self):
        if self.current().type == NOT and self._peek().type != IN:
            self.advance()
            return ("not", self.parse_not_expr())
        return self.parse_comparison()

    # ==, !=, <, >, <=, >=, IN, NOT IN
    def parse_comparison(self):
        left = self.parse_additive()
        cur = self.current()

        if cur.type == NOT and self._peek().type == IN:
            self.advance()
            self.advance()
            return ("not_in", left, self._parse_in_rhs())

        if cur.type == IN:
            self.advance()
            return ("in", left, self._parse_in_rhs())

        if cur.type in (EQEQ, NE, LT, GT, LE, GE):
            op = cur.type
            self.advance()
            return ("compare", op, left, self.parse_additive())

        return left

    def _parse_in_rhs(self):
        tok = self.current()
        if tok.type == LBRACKET:
            return self._parse_inline_set()
        if tok.type == SOURCE:
            return ("source", self.advance().value)
        if tok.type == IDENT:
            return ("ident", self.advance().value)
        raise self.ParseError(
            f"Expected set, source, or identifier after IN; got {tok}"
        )

    def _parse_inline_set(self):
        self.expect(LBRACKET)
        items = []
        while self.current().type not in (RBRACKET, EOF):
            items.append(self.parse_primary())
            if self.current().type == COMMA:
                self.advance()
        self.expect(RBRACKET)
        return ("set", items)

    # +, -
    def parse_additive(self):
        left = self.parse_multiplicative()
        while self.current().type in (PLUS, MINUS):
            op = self.advance().type
            right = self.parse_multiplicative()
            left = ("add", left, right) if op == PLUS else ("sub", left, right)
        return left

    # *, /, %
    def parse_multiplicative(self):
        left = self.parse_unary()
        while self.current().type in (STAR, SLASH, PERCENT):
            op = self.advance().type
            right = self.parse_unary()
            if op == STAR:
                left = ("mul", left, right)
            elif op == SLASH:
                left = ("div", left, right)
            else:
                left = ("mod", left, right)
        return left

    # unary minus
    def parse_unary(self):
        if self.current().type == MINUS:
            self.advance()
            return ("neg", self.parse_primary())
        return self.parse_primary()

    # literals, identifiers, calls, dot-access, quantifiers, sets
    def parse_primary(self):
        tok = self.current()

        if tok.type == LPAREN:
            self.advance()
            expr = self.parse_expr()
            self.expect(RPAREN)
            return expr

        if tok.type == LBRACKET:
            return self._parse_inline_set()

        if tok.type == INT:
            return ("int", self.advance().value)
        if tok.type == FLOAT:
            return ("float", self.advance().value)
        if tok.type == STRING:
            return ("string", self.advance().value)
        if tok.type == BOOL_TRUE:
            self.advance()
            return ("bool", True)
        if tok.type == BOOL_FALSE:
            self.advance()
            return ("bool", False)
        if tok.type == SOURCE:
            return ("source", self.advance().value)

        if tok.type == IDENT:
            name = self.advance().value

            # Function call or quantifier: NAME(...)
            if self.current().type == LPAREN:
                self.advance()  # consume (
                upper = name.upper()
                if upper in _QUANTIFIERS:
                    return self._parse_quantifier_body(upper)
                return self._parse_function_body(name)

            # Dot-access chain: a.b.c
            parts = [name]
            while self.current().type == DOT and self._peek().type == IDENT:
                self.advance()  # DOT
                parts.append(self.advance().value)  # IDENT

            if len(parts) == 1:
                return ("ident", name)
            return ("attr", parts)

        raise self.ParseError(f"Unexpected token: {tok}")

    def _parse_function_body(self, name: str):
        """Parse arg1, arg2, ...) — opening ( already consumed."""
        args = []
        while self.current().type not in (RPAREN, EOF):
            args.append(self.parse_expr())
            if self.current().type == COMMA:
                self.advance()
        self.expect(RPAREN)
        return ("call", name.upper(), args)

    def _parse_quantifier_body(self, quantifier: str):
        """Parse collection, var -> condition) — opening ( already consumed."""
        collection = self.parse_expr()
        self.expect(COMMA)
        if self.current().type != IDENT:
            raise self.ParseError(
                f"Expected lambda variable in {quantifier}(...)"
            )
        var = self.advance().value
        self.expect(ARROW)
        condition = self.parse_expr()
        self.expect(RPAREN)
        return (quantifier.lower(), collection, var, condition)

    # ── Evaluator ────────────────────────────────────────────────────────────

    @staticmethod
    def _eval_node(node, context: dict):
        if not isinstance(node, tuple):
            return bool(node)
        tag = node[0]

        # Literals
        if tag in ("int", "float", "bool", "string"):
            return node[1]

        # Simple identifier: temporal builtin or context lookup
        if tag == "ident":
            name = node[1]
            if name in _TEMPORAL_BUILTINS:
                return _resolve_temporal(name)
            return context.get(name, False)

        # Dot-access: walk nested dicts
        if tag == "attr":
            val: Any = context
            for part in node[1]:
                if isinstance(val, dict):
                    val = val.get(part)
                    if val is None:
                        return False
                else:
                    return False
            return val

        # Dynamic source (list injected by TarlRuntime as "source:<name>")
        if tag == "source":
            return context.get(f"source:{node[1]}", [])

        # Inline set: list of evaluated items
        if tag == "set":
            return [SafeExpr._eval_node(item, context) for item in node[1]]

        # Arithmetic
        ev = SafeExpr._eval_node
        if tag == "add":
            try:
                return ev(node[1], context) + ev(node[2], context)
            except TypeError:
                return False
        if tag == "sub":
            try:
                return ev(node[1], context) - ev(node[2], context)
            except TypeError:
                return False
        if tag == "mul":
            try:
                return ev(node[1], context) * ev(node[2], context)
            except TypeError:
                return False
        if tag == "div":
            try:
                r = ev(node[2], context)
                return ev(node[1], context) / r if r != 0 else False
            except TypeError:
                return False
        if tag == "mod":
            try:
                r = ev(node[2], context)
                return ev(node[1], context) % r if r != 0 else False
            except TypeError:
                return False
        if tag == "neg":
            try:
                return -SafeExpr._eval_node(node[1], context)
            except TypeError:
                return False

        # Logic
        if tag == "not":
            return not SafeExpr._eval_node(node[1], context)
        if tag == "and":
            return (SafeExpr._eval_node(node[1], context)
                    and SafeExpr._eval_node(node[2], context))
        if tag == "or":
            return (SafeExpr._eval_node(node[1], context)
                    or SafeExpr._eval_node(node[2], context))

        # Set membership
        if tag == "in":
            val = SafeExpr._eval_node(node[1], context)
            col = SafeExpr._eval_node(node[2], context)
            is_col = isinstance(col, (list, set, frozenset))
            return val in col if is_col else False
        if tag == "not_in":
            val = SafeExpr._eval_node(node[1], context)
            col = SafeExpr._eval_node(node[2], context)
            is_col = isinstance(col, (list, set, frozenset))
            return val not in col if is_col else True

        # Comparison
        if tag == "compare":
            op = node[1]
            lv = SafeExpr._eval_node(node[2], context)
            rv = SafeExpr._eval_node(node[3], context)
            if type(lv) is not type(rv):
                try:
                    if isinstance(lv, str) and isinstance(rv, (int, float)):
                        rv = str(rv)
                    elif isinstance(rv, str) and isinstance(lv, (int, float)):
                        lv = str(lv)
                except (ValueError, TypeError):
                    return False
            try:
                if op == EQEQ:
                    return lv == rv
                if op == NE:
                    return lv != rv
                if op == LT:
                    return lv < rv
                if op == GT:
                    return lv > rv
                if op == LE:
                    return lv <= rv
                if op == GE:
                    return lv >= rv
            except TypeError:
                return False
            return False

        # Safe function calls
        if tag == "call":
            args = [SafeExpr._eval_node(a, context) for a in node[2]]
            return _call_safe_function(node[1], args)

        # Quantifiers
        if tag == "all":
            _, collection_node, var, cond = node
            col = SafeExpr._eval_node(collection_node, context)
            if not isinstance(col, (list, set, frozenset)):
                return False
            return all(
                SafeExpr._eval_node(cond, {**context, var: item})
                for item in col
            )
        if tag == "any":
            _, collection_node, var, cond = node
            col = SafeExpr._eval_node(collection_node, context)
            if not isinstance(col, (list, set, frozenset)):
                return False
            return any(
                SafeExpr._eval_node(cond, {**context, var: item})
                for item in col
            )

        return bool(node)

    @staticmethod
    def _resolve_value(node, context: dict):
        """Resolve a node to its raw value (for backwards compatibility)."""
        if isinstance(node, (bool, int, float, str)):
            return node
        if not isinstance(node, tuple):
            return None
        tag = node[0]
        if tag in ("int", "float", "string", "bool"):
            return node[1]
        if tag == "ident":
            return context.get(node[1], node[1])
        if tag == "attr":
            return SafeExpr._eval_node(node, context)
        return None


# ── Module-level evaluate_policy ─────────────────────────────────────────────

def evaluate_policy(
    context: dict,
    policy_text: str = "",
    policy: TarlPolicy | None = None,
) -> TarlDecision:
    """
    Evaluate a policy against a context dict.
    First-match-wins: Eval(P,c) = vₖ where k=min{i|φᵢ(c)=true}, else DENY.

    Phase 5: enforces valid_from/valid_until/if_unresolved_after windows and
    computes expires_at for time-bound verdicts (duration_seconds > 0).
    """
    if policy is None:
        if not policy_text:
            return DEFAULT_DENY
        policy = PolicyParser.parse(policy_text)

    temporal = _check_policy_temporal(policy)
    if temporal is not None:
        return temporal

    for i, rule in enumerate(policy.rules):
        try:
            result = SafeExpr.evaluate(rule.condition, context)
            if result:
                expires_at = None
                if rule.duration_seconds:
                    expires_at = (
                        datetime.datetime.now(datetime.UTC)
                        + datetime.timedelta(seconds=rule.duration_seconds)
                    ).isoformat(timespec="seconds")
                return TarlDecision(
                    verdict=rule.verdict,
                    reason=f"Rule matched: {rule}",
                    rule_index=i,
                    matched_rule=str(rule),
                    expires_at=expires_at,
                )
        except Exception:
            continue

    return DEFAULT_DENY
