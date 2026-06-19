"""
T.A.R.L. Core — Policy Parser and SafeExpr Sandboxed Evaluator
Parses `when <expr> => VERDICT` rules and evaluates them safely.
"""
import re
from utf.tarl.spec import TarlVerdict, TarlDecision, TarlPolicy, TarlRule, DEFAULT_DENY


# Token types for the simple expression language
INT = 'INT'
FLOAT = 'FLOAT'
STRING = 'STRING'
BOOL_TRUE = 'BOOL_TRUE'
BOOL_FALSE = 'BOOL_FALSE'
IDENT = 'IDENT'
PLUS = 'PLUS'
EQEQ = 'EQEQ'
NE = 'NE'
LT = 'LT'
GT = 'GT'
LE = 'LE'
GE = 'GE'
AND = 'AND'
OR = 'OR'
NOT = 'NOT'
LPAREN = 'LPAREN'
RPAREN = 'RPAREN'
EOF = 'EOF'


class ExprToken:
    __slots__ = ('type', 'value', 'pos')

    def __init__(self, type, value, pos=0):
        self.type = type
        self.value = value
        self.pos = pos

    def __repr__(self):
        return f"ExprToken({self.type}, {self.value!r})"


class PolicyParser:
    """Parses TARL policy text into TarlPolicy objects."""

    RULE_RE = re.compile(r'when\s+(.+?)\s*=>\s*(ALLOW|DENY|ESCALATE)\s*')

    @classmethod
    def parse(cls, text: str, name: str = "unnamed") -> TarlPolicy:
        """Parse TARL policy text into a TarlPolicy."""
        policy = TarlPolicy(source=text, name=name)
        lines = text.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped.startswith('policy'):
                parts = stripped.split()
                if len(parts) > 1:
                    policy.name = parts[1]
                continue
            match = cls.RULE_RE.match(stripped)
            if match:
                condition = match.group(1).strip()
                verdict_str = match.group(2).upper()
                verdict = TarlVerdict(verdict_str)
                rule = TarlRule(condition=condition, verdict=verdict, source_line=i + 1)
                policy.rules.append(rule)
        return policy

    @staticmethod
    def _tokenize(expr: str) -> list:
        """Tokenize a condition expression string."""
        tokens = []
        i = 0
        while i < len(expr):
            c = expr[i]
            if c in ' \t':
                i += 1
                continue
            if c == '(':
                tokens.append(ExprToken(LPAREN, '(', i))
                i += 1
            elif c == ')':
                tokens.append(ExprToken(RPAREN, ')', i))
                i += 1
            elif c == '=' and i + 1 < len(expr) and expr[i + 1] == '=':
                tokens.append(ExprToken(EQEQ, '==', i))
                i += 2
            elif c == '!' and i + 1 < len(expr) and expr[i + 1] == '=':
                tokens.append(ExprToken(NE, '!=', i))
                i += 2
            elif c == '<' and i + 1 < len(expr) and expr[i + 1] == '=':
                tokens.append(ExprToken(LE, '<=', i))
                i += 2
            elif c == '<':
                tokens.append(ExprToken(LT, '<', i))
                i += 1
            elif c == '>' and i + 1 < len(expr) and expr[i + 1] == '=':
                tokens.append(ExprToken(GE, '>=', i))
                i += 2
            elif c == '>':
                tokens.append(ExprToken(GT, '>', i))
                i += 1
            elif c == '+':
                tokens.append(ExprToken(PLUS, '+', i))
                i += 1
            elif c == '"':
                i += 1
                s = ''
                while i < len(expr) and expr[i] != '"':
                    if expr[i] == '\\' and i + 1 < len(expr):
                        i += 1
                        esc = {'n': '\n', 't': '\t', '\\': '\\', '"': '"'}
                        s += esc.get(expr[i], expr[i])
                    else:
                        s += expr[i]
                    i += 1
                i += 1
                tokens.append(ExprToken(STRING, s, i))
            elif c == "'":
                i += 1
                s = ''
                while i < len(expr) and expr[i] != "'":
                    s += expr[i]
                    i += 1
                i += 1
                tokens.append(ExprToken(STRING, s, i))
            elif c.isdigit() or (c == '-' and i + 1 < len(expr) and expr[i + 1].isdigit()):
                start = i
                i += 1
                is_float = False
                while i < len(expr) and (expr[i].isdigit() or expr[i] == '.'):
                    if expr[i] == '.':
                        is_float = True
                    i += 1
                num_str = expr[start:i]
                if is_float:
                    tokens.append(ExprToken(FLOAT, float(num_str), start))
                else:
                    tokens.append(ExprToken(INT, int(num_str), start))
            elif c.isalpha() or c == '_':
                start = i
                while i < len(expr) and (expr[i].isalnum() or expr[i] == '_'):
                    i += 1
                word = expr[start:i]
                if word == 'true':
                    tokens.append(ExprToken(BOOL_TRUE, True, start))
                elif word == 'false':
                    tokens.append(ExprToken(BOOL_FALSE, False, start))
                elif word == 'and':
                    tokens.append(ExprToken(AND, 'and', start))
                elif word == 'or':
                    tokens.append(ExprToken(OR, 'or', start))
                elif word == 'not':
                    tokens.append(ExprToken(NOT, 'not', start))
                else:
                    tokens.append(ExprToken(IDENT, word, start))
            else:
                raise ValueError(f"Unexpected character '{c}' at position {i}")
        tokens.append(ExprToken(EOF, None, i))
        return tokens


class SafeExpr:
    """
    Sandboxed expression evaluator.
    ONLY allows: Identifier, IntLiteral, FloatLiteral, StringLiteral,
    BoolLiteral, CompareOp, BinaryOp (and/or), UnaryOp (not).
    """

    class ParseError(Exception):
        pass

    @classmethod
    def evaluate(cls, expr, context: dict) -> bool:
        """
        Evaluate an expression against a context dict.
        Accepts either a raw string or a tokenized list.
        Returns boolean result.
        """
        if isinstance(expr, str):
            tokens = PolicyParser._tokenize(expr)
        else:
            tokens = expr
        parser = cls(tokens)
        result = parser.parse_expr()
        if parser.current().type != EOF:
            raise cls.ParseError(f"Unexpected token: {parser.current()}")
        return cls._eval_node(result, context)

    def __init__(self, tokens: list):
        self.tokens = tokens
        self.pos = 0

    def current(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ExprToken(EOF, None)

    def advance(self):
        tok = self.current()
        self.pos += 1
        return tok

    def expect(self, *types):
        tok = self.current()
        if tok.type not in types:
            raise self.ParseError(f"Expected {types}, got {tok.type}({tok.value})")
        return self.advance()

    def parse_expr(self):
        left = self.parse_and_expr()
        while self.current().type == OR:
            self.advance()
            right = self.parse_and_expr()
            left = ('or', left, right)
        return left

    def parse_and_expr(self):
        left = self.parse_not_expr()
        while self.current().type == AND:
            self.advance()
            right = self.parse_not_expr()
            left = ('and', left, right)
        return left

    def parse_not_expr(self):
        if self.current().type == NOT:
            self.advance()
            operand = self.parse_not_expr()
            return ('not', operand)
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_arithmetic()
        if self.current().type in (EQEQ, NE, LT, GT, LE, GE):
            op = self.current().type
            self.advance()
            right = self.parse_arithmetic()
            return ('compare', op, left, right)
        return left

    def parse_arithmetic(self):
        left = self.parse_primary()
        while self.current().type == PLUS:
            self.advance()
            right = self.parse_primary()
            left = ('add', left, right)
        return left

    def parse_primary(self):
        tok = self.current()
        if tok.type == LPAREN:
            self.advance()
            expr = self.parse_expr()
            self.expect(RPAREN)
            return expr
        elif tok.type == INT:
            self.advance()
            return ('int', tok.value)
        elif tok.type == FLOAT:
            self.advance()
            return ('float', tok.value)
        elif tok.type == STRING:
            self.advance()
            return ('string', tok.value)
        elif tok.type == BOOL_TRUE:
            self.advance()
            return ('bool', True)
        elif tok.type == BOOL_FALSE:
            self.advance()
            return ('bool', False)
        elif tok.type == IDENT:
            self.advance()
            return ('ident', tok.value)
        else:
            raise self.ParseError(f"Unexpected token: {tok}")

    @staticmethod
    def _eval_node(node, context: dict):
        """Evaluate a parsed expression node against context, returning a value."""
        if isinstance(node, bool):
            return node
        if not isinstance(node, tuple):
            return bool(node)

        tag = node[0]

        if tag in ('int', 'float', 'bool'):
            return node[1]
        elif tag == 'string':
            return node[1]
        elif tag == 'ident':
            name = node[1]
            if name in context:
                return context[name]
            # Unknown identifiers return False rather than leaking their string name
            return False

        elif tag == 'add':
            return SafeExpr._eval_node(node[1], context) + SafeExpr._eval_node(node[2], context)

        elif tag == 'not':
            return not SafeExpr._eval_node(node[1], context)
        
        elif tag == 'and':
            return SafeExpr._eval_node(node[1], context) and SafeExpr._eval_node(node[2], context)

        elif tag == 'or':
            return SafeExpr._eval_node(node[1], context) or SafeExpr._eval_node(node[2], context)

        elif tag == 'compare':
            op = node[1]
            left_val = SafeExpr._eval_node(node[2], context)
            right_val = SafeExpr._eval_node(node[3], context)

            # Handle type mismatch in comparisons
            if not isinstance(left_val, type(right_val)):
                # Try to coerce
                try:
                    if isinstance(left_val, str) and isinstance(right_val, (int, float)):
                        right_val = str(right_val)
                    elif isinstance(right_val, str) and isinstance(left_val, (int, float)):
                        left_val = str(left_val)
                except (ValueError, TypeError):
                    return False

            try:
                if op == EQEQ:
                    return left_val == right_val
                elif op == NE:
                    return left_val != right_val
                elif op == LT:
                    return left_val < right_val
                elif op == GT:
                    return left_val > right_val
                elif op == LE:
                    return left_val <= right_val
                elif op == GE:
                    return left_val >= right_val
            except TypeError:
                return False
            return False

        return bool(node)

    @staticmethod
    def _resolve_value(node, context: dict):
        """Resolve a value from an expression node, looking up identifiers in context."""
        if isinstance(node, (bool, int, float, str)):
            return node
        if not isinstance(node, tuple):
            return None
        tag = node[0]
        if tag in ('int', 'float', 'string', 'bool'):
            return node[1]
        elif tag == 'ident':
            name = node[1]
            return context.get(name, name)
        return None


def evaluate_policy(context: dict, policy_text: str = "", policy: TarlPolicy = None) -> TarlDecision:
    """
    Evaluate a policy against a context dict.
    Accepts either raw policy_text or a pre-parsed TarlPolicy.
    Returns TarlDecision with verdict and reason.
    """
    if policy is None:
        if not policy_text:
            return DEFAULT_DENY
        policy = PolicyParser.parse(policy_text)

    for i, rule in enumerate(policy.rules):
        try:
            tokens = PolicyParser._tokenize(rule.condition)
            result = SafeExpr.evaluate(tokens, context)
            if result:
                return TarlDecision(
                    verdict=rule.verdict,
                    reason=f"Rule matched: {rule}",
                    rule_index=i,
                    matched_rule=str(rule)
                )
        except Exception:
            continue

    return DEFAULT_DENY