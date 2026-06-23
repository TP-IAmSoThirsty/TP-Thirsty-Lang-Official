"""
Tests for TSCG (Thirst's Symbolic Constitutional Grammar)
Tests symbols, parsing, canonical form, checksum, and validation.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utf.tscg.core import (
    ALL_SYMBOLS,
    EXTENDED_SYMBOLS,
    OPCODE_TO_SYMBOL,
    SYMBOLS,
    CombineExpr,
    PipelineExpr,
    SymbolExpr,
    canonical_form,
    checksum,
    parse,
    validate_symbols,
)


class TestSymbols:
    """Test TSCG symbol definitions."""

    def test_core_symbols_count(self):
        assert len(SYMBOLS) == 9

    def test_core_symbols_opcodes(self):
        assert SYMBOLS['COG'] == 0x00
        assert SYMBOLS['DNT'] == 0x01
        assert SYMBOLS['SHD'] == 0x02
        assert SYMBOLS['INV'] == 0x03
        assert SYMBOLS['CAP'] == 0x04
        assert SYMBOLS['QRM'] == 0x05
        assert SYMBOLS['COM'] == 0x06
        assert SYMBOLS['ANC'] == 0x07
        assert SYMBOLS['RFX'] == 0x08

    def test_extended_symbols_count(self):
        assert len(EXTENDED_SYMBOLS) == 7

    def test_extended_symbols_opcodes(self):
        assert EXTENDED_SYMBOLS['SAFE'] == 0x10
        assert EXTENDED_SYMBOLS['ING'] == 0x11
        assert EXTENDED_SYMBOLS['LED'] == 0x12
        assert EXTENDED_SYMBOLS['MUT'] == 0x13
        assert EXTENDED_SYMBOLS['SEL'] == 0x14
        assert EXTENDED_SYMBOLS['QRM_LINEAR'] == 0x15
        assert EXTENDED_SYMBOLS['QRM_STATIC'] == 0x16

    def test_all_symbols_combined(self):
        assert len(ALL_SYMBOLS) == 16  # 9 + 7

    def test_opcode_to_symbol(self):
        assert OPCODE_TO_SYMBOL[0x00] == 'COG'
        assert OPCODE_TO_SYMBOL[0x10] == 'SAFE'

    def test_symbol_expr_creation(self):
        se = SymbolExpr(symbol_name='COG')
        assert se.symbol_name == 'COG'
        assert se.opcode == 0x00


class TestParser:
    """Test TSCG expression parsing."""

    def test_parse_single_symbol(self):
        ast = parse('$COG')
        assert isinstance(ast, SymbolExpr)
        assert ast.symbol_name == 'COG'
        assert ast.opcode == 0x00

    def test_parse_single_extended_symbol(self):
        ast = parse('$SAFE')
        assert isinstance(ast, SymbolExpr)
        assert ast.symbol_name == 'SAFE'
        assert ast.opcode == 0x10

    def test_parse_pipeline(self):
        ast = parse('$COG -> $DNT')
        assert isinstance(ast, PipelineExpr)
        assert isinstance(ast.left, SymbolExpr)
        assert ast.left.symbol_name == 'COG'
        assert isinstance(ast.right, SymbolExpr)
        assert ast.right.symbol_name == 'DNT'

    def test_parse_long_pipeline(self):
        ast = parse('$COG -> $DNT -> $SHD')
        assert isinstance(ast, PipelineExpr)
        # Left should be a PipelineExpr, right should be SymbolExpr
        assert isinstance(ast.left, PipelineExpr)
        assert ast.left.left.symbol_name == 'COG'
        assert ast.left.right.symbol_name == 'DNT'
        assert ast.right.symbol_name == 'SHD'

    def test_parse_and_combine(self):
        ast = parse('$COG ^ $DNT')
        assert isinstance(ast, CombineExpr)
        assert ast.op == '^'
        assert ast.left.symbol_name == 'COG'
        assert ast.right.symbol_name == 'DNT'

    def test_parse_or_combine(self):
        ast = parse('$COG || $DNT')
        assert isinstance(ast, CombineExpr)
        assert ast.op == '||'

    def test_parse_complex_expression(self):
        ast = parse('$COG -> ($DNT ^ $SHD)')
        assert isinstance(ast, PipelineExpr)
        assert isinstance(ast.right, CombineExpr)
        assert ast.right.op == '^'

    def test_parse_error_unknown_symbol(self):
        try:
            parse('$UNKNOWN')
            raise AssertionError("Should have raised ValueError")
        except ValueError:
            pass

    def test_parse_error_unexpected_char(self):
        try:
            parse('$COG @ $DNT')
            raise AssertionError("Should have raised ValueError")
        except ValueError:
            pass


class TestCanonicalForm:
    """Test TSCG canonical normalization."""

    def test_canonical_single_symbol(self):
        ast = parse('$COG')
        cf = canonical_form(ast)
        assert cf == '$COG'

    def test_canonical_pipeline(self):
        ast = parse('$COG -> $DNT')
        cf = canonical_form(ast)
        assert cf == '$COG -> $DNT'

    def test_canonical_combine(self):
        ast = parse('$COG ^ $DNT')
        cf = canonical_form(ast)
        assert cf == '$COG ^ $DNT'

    def test_canonical_roundtrip(self):
        """Parsing and canonicalizing should yield a normalized form."""
        expr = '$COG -> $DNT ^ $CAP'
        ast = parse(expr)
        cf = canonical_form(ast)
        assert '$COG' in cf
        assert '$DNT' in cf
        assert '$CAP' in cf


class TestChecksum:
    """Test TSCG SHA-256 checksum."""

    def test_checksum_format(self):
        cs = checksum('$COG')
        assert len(cs) == 64  # SHA-256 hex
        assert all(c in '0123456789abcdef' for c in cs)

    def test_checksum_deterministic(self):
        cs1 = checksum('$COG -> $DNT')
        cs2 = checksum('$COG -> $DNT')
        assert cs1 == cs2

    def test_checksum_different(self):
        cs1 = checksum('$COG')
        cs2 = checksum('$DNT')
        assert cs1 != cs2


class TestValidation:
    """Test TSCG symbol validation."""

    def test_validate_all_known(self):
        errors = validate_symbols('$COG -> $DNT')
        assert len(errors) == 0

    def test_validate_with_unknown(self):
        errors = validate_symbols('$COG -> $UNKNOWN')
        assert len(errors) >= 1
        assert 'UNKNOWN' in errors[0]

    def test_validate_extended(self):
        errors = validate_symbols('$SAFE $MUT $LED')
        assert len(errors) == 0


if __name__ == "__main__":
    for name in dir():
        obj = globals()[name]
        if isinstance(obj, type) and name.startswith("Test"):
            print(f"\n{'='*60}")
            print(f"Running {name}...")
            print('='*60)
            instance = obj()
            for attr in dir(instance):
                if attr.startswith("test_"):
                    try:
                        getattr(instance, attr)()
                        print(f"  ✓ {attr}")
                    except Exception as e:
                        print(f"  ✗ {attr}: {e}")
                        raise
    print("\n✅ All TSCG tests passed!")
