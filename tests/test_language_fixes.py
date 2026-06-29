"""Regression tests for core-language fixes:

* self- and mutual recursion no longer trip the arity checker (E030),
* `this` / member assignment / method dispatch work in fountains,
* the `|>` pipe operator lexes (as well as bare `|`),
* `error (name) { ... }` binds the thrown value in the handler, and
* nested functions close over their defining (lexical) scope.
"""
from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.interpreter import Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.token import TokenType


def _parse(src):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    return ast


def _check(src):
    return [e.code for e in check_ast(_parse(src))]


def _run(src, capsys):
    Interpreter().interpret(_parse(src))
    return capsys.readouterr().out.strip()


# --- recursion ------------------------------------------------------------

def test_self_recursion_checks_and_runs(capsys):
    src = ("module m: core\n"
           "glass fact(n: Int) -> Int {\n"
           "    thirsty (n <= 1) { return 1 }\n"
           "    return n * fact(n - 1)\n"
           "}\n"
           "pour fact(5)")
    assert "E030" not in _check(src)
    assert _run(src, capsys) == "120"


def test_mutual_recursion(capsys):
    src = ("module m: core\n"
           "glass is_even(n) {\n"
           "    thirsty (n == 0) { return true }\n"
           "    return is_odd(n - 1)\n"
           "}\n"
           "glass is_odd(n) {\n"
           "    thirsty (n == 0) { return false }\n"
           "    return is_even(n - 1)\n"
           "}\n"
           "pour is_even(4)")
    assert "E030" not in _check(src)
    assert _run(src, capsys) == "True"


# --- fountains / `this` ---------------------------------------------------

def test_this_member_assignment_and_methods(capsys):
    src = ("module m: core\n"
           "fountain Acc {\n"
           "    drink total: Int = 0\n"
           "    glass init(start) { this.total = start }\n"
           "    glass add(n) { this.total = this.total + n }\n"
           "    glass value() { return this.total }\n"
           "}\n"
           "drink a = new Acc(10)\n"
           "a.add(5)\n"
           "a.add(7)\n"
           "pour a.value()")
    assert "E011" not in _check(src)
    assert _run(src, capsys) == "22"


def test_field_default_initializers(capsys):
    # Fields with default values are initialized at construction, with or
    # without the optional `drink` prefix.
    src = ("module m: core\n"
           "fountain Counter {\n"
           "    drink count: Int = 0\n"
           "    glass increment() { this.count = this.count + 1 }\n"
           "    glass get() { return this.count }\n"
           "}\n"
           "drink c = new Counter()\n"
           "c.increment()\n"
           "c.increment()\n"
           "pour c.get()")
    assert _run(src, capsys) == "2"


def test_field_default_without_drink_prefix(capsys):
    src = ("module m: core\n"
           "fountain P {\n"
           "    x: Int = 10\n"
           "    y: Int = 20\n"
           "    glass sum() { return this.x + this.y }\n"
           "}\n"
           "drink p = new P()\n"
           "pour p.sum()")
    assert _run(src, capsys) == "30"


def test_explicit_self_convention_still_works(capsys):
    # The pre-existing `glass m(self, ...)` convention must keep working.
    src = ("module m: core\n"
           "fountain Box {\n"
           "    val: Int\n"
           "    glass init(self) { self.val = 0 }\n"
           "    glass set(self, n) { self.val = n }\n"
           "    glass get(self) { return self.val }\n"
           "}\n"
           "drink b = new Box()\n"
           "b.set(42)\n"
           "pour b.get()")
    assert _run(src, capsys) == "42"


# --- pipe operator --------------------------------------------------------

def test_pipe_arrow_lexes():
    types = [t.type for t in Lexer("a |> b").lex()]
    assert TokenType.PIPE in types and TokenType.GT not in types
    # bare `|` remains the same operator
    assert TokenType.PIPE in [t.type for t in Lexer("a | b").lex()]


def test_pipe_chain_runs(capsys):
    src = ("module m: core\n"
           "glass dbl(n) { return n * 2 }\n"
           "glass inc(n) { return n + 1 }\n"
           "pour 5 |> dbl |> inc")
    assert _run(src, capsys) == "11"


# --- error binding --------------------------------------------------------

def test_error_binding(capsys):
    src = ("module m: core\n"
           "spillage {\n"
           "    throw \"boom\"\n"
           "} error (e) {\n"
           "    pour \"caught: \" + e\n"
           "}")
    assert "E011" not in _check(src)
    assert _run(src, capsys) == "caught: boom"


def test_error_without_binding(capsys):
    src = ("module m: core\n"
           "spillage {\n"
           "    throw \"x\"\n"
           "} error {\n"
           "    pour \"handled\"\n"
           "}")
    assert _run(src, capsys) == "handled"


# --- closures -------------------------------------------------------------

def test_nested_function_closes_over_scope(capsys):
    src = ("module m: core\n"
           "glass make_adder(x) {\n"
           "    glass adder(y) { return x + y }\n"
           "    return adder\n"
           "}\n"
           "drink add5 = make_adder(5)\n"
           "pour add5(10)")
    assert _run(src, capsys) == "15"
