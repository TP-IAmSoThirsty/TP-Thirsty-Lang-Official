"""
TSCG — Thirst's Symbolic Constitutional Grammar
9 core + 7 extended symbols with parser, canonical normalization, and checksum.
"""
import hashlib
from dataclasses import dataclass

# Core symbols (opcodes 0x00-0x08)
SYMBOLS = {
    'COG': 0x00,  # Cognition — thought/reflection
    'DNT': 0x01,  # Don't — prohibition/restriction
    'SHD': 0x02,  # Should — recommendation/guidance
    'INV': 0x03,  # Invariant — constant/unchanging
    'CAP': 0x04,  # Capacity — boundary/limit
    'QRM': 0x05,  # Quorum — consensus/majority
    'COM': 0x06,  # Command — directive/order
    'ANC': 0x07,  # Anchor — foundation/base
    'RFX': 0x08,  # Reflex — self-reference
}

# Extended symbols (opcodes 0x10-0x16)
EXTENDED_SYMBOLS = {
    'SAFE': 0x10,  # Safety — protection/security
    'ING': 0x11,   # Ingestion — input/consumption
    'LED': 0x12,   # Ledger — record/audit
    'MUT': 0x13,   # Mutation — transformation/change
    'SEL': 0x14,   # Selection — choice/decision
    'QRM_LINEAR': 0x15,  # Linear quorum — sequential consensus
    'QRM_STATIC': 0x16,  # Static quorum — fixed consensus
}

ALL_SYMBOLS = {**SYMBOLS, **EXTENDED_SYMBOLS}
OPCODE_TO_SYMBOL = {v: k for k, v in ALL_SYMBOLS.items()}


@dataclass
class TSCGNode:
    """Base TSCG AST node."""
    pass


@dataclass
class SymbolExpr(TSCGNode):
    """A single symbol reference, e.g., $COG"""
    symbol_name: str
    opcode: int = 0

    def __post_init__(self):
        if self.symbol_name in ALL_SYMBOLS:
            self.opcode = ALL_SYMBOLS[self.symbol_name]


@dataclass
class PipelineExpr(TSCGNode):
    """Pipeline operator: left -> right"""
    left: TSCGNode
    right: TSCGNode


@dataclass
class CombineExpr(TSCGNode):
    """Combine operator: left ^ right (AND) or left || right (OR)"""
    left: TSCGNode
    right: TSCGNode
    op: str  # '^' or '||'


class TSCGParser:
    """Parses TSCG expressions."""

    def __init__(self, text: str):
        self.text = text.strip()
        self.tokens = self._tokenize()
        self.pos = 0

    def _tokenize(self):
        """Tokenize the input text."""
        tokens = []
        i = 0
        while i < len(self.text):
            c = self.text[i]
            if c in ' \t\n':
                i += 1
                continue
            if c == '$':
                # Symbol reference
                start = i + 1
                j = start
                while j < len(self.text) and (self.text[j].isalnum() or self.text[j] == '_'):
                    j += 1
                symbol = self.text[start:j]
                if symbol not in ALL_SYMBOLS:
                    raise ValueError(f"Unknown symbol: ${symbol}")
                tokens.append(('SYMBOL', symbol))
                i = j
            elif c == '-' and i + 1 < len(self.text) and self.text[i + 1] == '>':
                tokens.append(('PIPE', '->'))
                i += 2
            elif c == '^':
                tokens.append(('AND', '^'))
                i += 1
            elif c == '|' and i + 1 < len(self.text) and self.text[i + 1] == '|':
                tokens.append(('OR', '||'))
                i += 2
            elif c == '(':
                tokens.append(('LPAREN', '('))
                i += 1
            elif c == ')':
                tokens.append(('RPAREN', ')'))
                i += 1
            else:
                raise ValueError(f"Unexpected character '{c}' at position {i}")
        tokens.append(('EOF', None))
        return tokens

    def current(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ('EOF', None)

    def advance(self):
        tok = self.current()
        self.pos += 1
        return tok

    def expect(self, *types):
        tok = self.current()
        if tok[0] not in types:
            raise ValueError(f"Expected {types}, got {tok}")
        return self.advance()

    def parse(self) -> TSCGNode:
        """Parse a full TSCG expression."""
        result = self.parse_pipeline()
        if self.current()[0] != 'EOF':
            raise ValueError(f"Unexpected token after expression: {self.current()}")
        return result

    def parse_pipeline(self) -> TSCGNode:
        """Parse pipeline expression (lowest precedence)."""
        left = self.parse_combine()
        while self.current()[0] == 'PIPE':
            self.advance()
            right = self.parse_combine()
            left = PipelineExpr(left=left, right=right)
        return left

    def parse_combine(self) -> TSCGNode:
        """Parse combine expressions (^ or ||)."""
        left = self.parse_primary()
        while self.current()[0] in ('AND', 'OR'):
            op_type, op = self.current()
            self.advance()
            right = self.parse_primary()
            left = CombineExpr(left=left, right=right, op=op)
        return left

    def parse_primary(self) -> TSCGNode:
        """Parse primary expression."""
        tok_type, tok_value = self.current()
        if tok_type == 'SYMBOL':
            self.advance()
            return SymbolExpr(symbol_name=tok_value)
        elif tok_type == 'LPAREN':
            self.advance()
            expr = self.parse_pipeline()
            self.expect('RPAREN')
            return expr
        else:
            raise ValueError(f"Expected symbol or '(', got {tok_type}")


def canonical_form(node: TSCGNode) -> str:
    """Reduce a TSCG expression to canonical (normalized) form."""
    if isinstance(node, SymbolExpr):
        return f"${node.symbol_name}"
    elif isinstance(node, PipelineExpr):
        return f"{canonical_form(node.left)} -> {canonical_form(node.right)}"
    elif isinstance(node, CombineExpr):
        return f"{canonical_form(node.left)} {node.op} {canonical_form(node.right)}"
    return str(node)


def checksum(expr_text: str) -> str:
    """SHA-256 checksum of a TSCG expression."""
    return hashlib.sha256(expr_text.encode('utf-8')).hexdigest()


def validate_symbols(text: str) -> list:
    """Validate that all $symbols in text are recognized. Returns list of errors."""
    errors = []
    i = 0
    while i < len(text):
        if text[i] == '$':
            j = i + 1
            while j < len(text) and (text[j].isalnum() or text[j] == '_'):
                j += 1
            symbol = text[i + 1:j]
            if symbol not in ALL_SYMBOLS:
                errors.append(f"Unknown symbol: ${symbol}")
            i = j
        else:
            i += 1
    return errors


def parse(text: str) -> TSCGNode:
    """Parse a TSCG expression string into an AST."""
    parser = TSCGParser(text)
    return parser.parse()
