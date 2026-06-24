"""Full coverage of the lexer: number bases, escapes, comments, operators,
and error recovery."""
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.token import TokenType


def types(src):
    return [t.type for t in Lexer(src).lex()]


def lex(src):
    lx = Lexer(src)
    return lx.lex(), lx.errors


def test_number_bases():
    toks, errs = lex("0xFF 0b101 0o17 42")
    assert not errs
    assert [t.type for t in toks if t.type == TokenType.INT].__len__() == 4


def test_float_forms():
    toks, errs = lex("1.5 1e10 1.5e-3 2E+4")
    floats = [t for t in toks if t.type == TokenType.FLOAT]
    assert len(floats) == 4
    assert not errs


def test_trailing_dot_peeknext_end():
    # "3." at EOF: not a float (no digit after dot) → INT then DOT.
    toks = Lexer("3.").lex()
    assert toks[0].type == TokenType.INT
    assert toks[1].type == TokenType.DOT


def test_string_escapes():
    toks, errs = lex(r'"a\nb\t\\\"\'\0\q"')
    assert not errs
    s = toks[0]
    assert s.type == TokenType.STRING
    assert "\n" in s.lexeme and "\t" in s.lexeme
    assert "q" in s.lexeme  # unknown escape falls through to the char


def test_string_with_newline():
    toks, errs = lex('"line1\nline2"')
    assert not errs
    assert toks[0].type == TokenType.STRING


def test_unterminated_string():
    _toks, errs = lex('"abc')
    assert any(e.code == "E002" for e in errs)


def test_line_and_block_comments():
    toks, errs = lex("1 // comment\n2 /* block\nmultiline */ 3")
    ints = [t for t in toks if t.type == TokenType.INT]
    assert len(ints) == 3
    assert not errs


def test_nested_block_comment():
    toks, errs = lex("/* outer /* inner */ still */ 5")
    assert not errs
    assert any(t.type == TokenType.INT for t in toks)


def test_unterminated_block_comment():
    _toks, errs = lex("/* never closed")
    assert any(e.code == "E003" for e in errs)


def test_operators():
    src = "a = b == c != d <= e >= f < g > h + i - j * k / l % m -> n | o || p ^ q \\ r"
    toks = Lexer(src).lex()
    present = {t.type for t in toks}
    for tt in (TokenType.ASSIGN, TokenType.EQEQ, TokenType.NE, TokenType.LE,
               TokenType.GE, TokenType.LT, TokenType.GT, TokenType.PLUS,
               TokenType.MINUS, TokenType.STAR, TokenType.SLASH, TokenType.PERCENT,
               TokenType.ARROW, TokenType.PIPE, TokenType.PIPEPIPE,
               TokenType.HATHAT, TokenType.BACKSLASH):
        assert tt in present, tt


def test_bang_error():
    _toks, errs = lex("!x")
    assert any(e.code == "E001" for e in errs)


def test_unrecognized_char():
    _toks, errs = lex("@")
    assert any(e.code == "E001" for e in errs)


def test_get_errors_method():
    lx = Lexer("@")
    lx.lex()
    assert lx.get_errors() == lx.errors


def test_walrus_and_colon():
    assert TokenType.COLONEQ in types("x := 1")
    assert TokenType.COLON in types("a: int")
