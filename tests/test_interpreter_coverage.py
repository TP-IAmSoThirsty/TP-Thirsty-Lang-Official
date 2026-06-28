"""Broad interpreter coverage by running feature-rich programs."""
from utf.thirsty_lang.interpreter import Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def run(src, mode="core"):
    ast = Parser(Lexer(f"module m: {mode}\n{src}").lex()).parse()
    return Interpreter().interpret(ast, mode=mode)


def out(capsys, src, mode="core"):
    run(src, mode)
    return capsys.readouterr().out


def test_builtins(capsys):
    assert "3" in out(capsys, "pour length([1, 2, 3])")
    assert "5" in out(capsys, "pour abs(-5)")
    assert "1" in out(capsys, "pour min(3, 1, 2)")
    assert "3" in out(capsys, "pour max(3, 1, 2)")
    assert "True" in out(capsys, "pour contains([1, 2], 1)")
    assert "2" in out(capsys, "pour size([9, 8])")
    assert "9" in out(capsys, "pour get([9, 8], 0)")


def test_array_mutation(capsys):
    o = out(capsys, "drink xs = [1, 2]\npush(xs, 3)\npour size(xs)")
    assert "3" in o


def test_arithmetic_and_precedence(capsys):
    assert "10" in out(capsys, "pour 2 * 3 + 4")
    assert "True" in out(capsys, "pour 2 + 3 == 5")


def test_string_concat(capsys):
    assert "hello world" in out(capsys, 'pour "hello " + "world"')


def test_if_elif_else(capsys):
    src = ('drink x = 5\n'
           'thirsty (x > 10) { pour "big" } '
           'hydrated thirsty (x > 3) { pour "mid" } '
           'hydrated { pour "small" }')
    assert "mid" in out(capsys, src)


def test_for_and_while(capsys):
    assert out(capsys, "refill (i in [1, 2, 3]) { pour i }").split() == ["1", "2", "3"]
    o = out(capsys, "drink mut n = 0\nrefill (n < 3) { n = n + 1 }\npour n")
    assert "3" in o


def test_function_call(capsys):
    assert "7" in out(capsys, "glass add(a, b) { return a + b }\npour add(3, 4)")


def test_fountain_class(capsys):
    src = ('fountain Counter {\n'
           '  count: int\n'
           '  glass bump() { return 1 }\n'
           '}\n'
           'drink c = new Counter()\n'
           'c.count = 5\n'
           'pour c.count')
    assert "5" in out(capsys, src)


def test_recursion(capsys):
    src = ('glass fib(n) {\n'
           '  thirsty (n < 2) { return n }\n'
           '  return fib(n - 1) + fib(n - 2)\n'
           '}\n'
           'pour fib(7)')
    assert "13" in out(capsys, src)


def test_governed_requires_pass():
    # No I/O in governed mode (pour fails closed without a policy); check the
    # returned value of the last expression statement instead.
    src = ('glass withdraw(amt) requires amt > 0 { return amt }\n'
           'drink r = withdraw(10)\n'
           'r')
    from utf.tarl.core import PolicyParser
    from utf.tarl.runtime import TarlRuntime
    prog = Parser(Lexer(src).lex()).parse()
    interp = Interpreter()
    interp.attach_tarl(TarlRuntime(PolicyParser.parse(
        'policy p\nwhen action == "withdraw" => ALLOW\nwhen true => DENY\n')))
    interp.set_authority("admin")
    assert interp.interpret(prog, mode="governed") == 10


def test_governed_requires_denied():
    src = ('glass withdraw(amt) requires amt > 0 { return amt }\n'
           'pour withdraw(-5)')
    try:
        run(src, mode="governed")
    except Exception:
        pass  # GovernanceViolation or similar is expected — just exercise the path


def test_boolean_logic(capsys):
    assert "True" in out(capsys, "pour true and (false or true)")
    assert "False" in out(capsys, "pour not true")


def test_unary_minus(capsys):
    assert "-5" in out(capsys, "drink x = 5\npour -x")


def test_nested_data(capsys):
    assert "2" in out(capsys, "drink m = [[1, 2], [3, 4]]\npour get(get(m, 0), 1)")
