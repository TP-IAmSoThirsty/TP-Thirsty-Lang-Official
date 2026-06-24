"""Full coverage of the AST formatter via direct node construction."""
from utf.thirsty_lang import formatter as F
from utf.thirsty_lang.ast import (
    ArmorExpr,
    ArrayLiteral,
    AssignStmt,
    BinaryOp,
    BlockStmt,
    BoolLiteral,
    CallExpr,
    CascadeCall,
    ClassDecl,
    CleanupStmt,
    CombineExpr,
    CondenseExpr,
    DefendStrat,
    DripExpr,
    EnumDecl,
    ErrorLiteral,
    EvaporateExpr,
    Expr,
    ExprStmt,
    FloatLiteral,
    FloodExpr,
    ForStmt,
    FunctionDecl,
    GovernedFunctionDecl,
    GuardExpr,
    Identifier,
    IfStmt,
    ImportStmt,
    InterfaceDecl,
    IntLiteral,
    MemberAccess,
    ModuleHeader,
    MorphDef,
    NewExpr,
    NoneLiteral,
    PipeExpr,
    PipelineExpr,
    PourStmt,
    Program,
    QuenchedLiteral,
    ReturnStmt,
    SanitizeExpr,
    SecurityBlock,
    ShadowThirstMutation,
    SipStmt,
    SpillageStmt,
    Stmt,
    StringLiteral,
    StructDecl,
    SymbolExpr,
    ThrowStmt,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from utf.thirsty_lang.token import TokenType

N = None


def ident(x):
    return Identifier(span=N, name=x)


def block(*stmts):
    return BlockStmt(span=N, statements=list(stmts))


def fexpr(e, prec=0):
    return F.format_expr(e, prec)


# === expressions ===========================================================

def test_format_literals():
    assert fexpr(IntLiteral(span=N, value=5)) == "5"
    assert fexpr(FloatLiteral(span=N, value=1.5)) == "1.5"
    assert fexpr(StringLiteral(span=N, value='a"\n\t\\')) .startswith('"')
    assert fexpr(BoolLiteral(span=N, value=True)) == "true"
    assert fexpr(BoolLiteral(span=N, value=False)) == "false"
    assert fexpr(NoneLiteral(span=N)) == "empty"
    assert fexpr(ErrorLiteral(span=N, value="oops")) == "error(oops)"
    assert "quenched" in fexpr(QuenchedLiteral(span=N, type_param="Int",
                                               value=IntLiteral(span=N, value=1)))
    assert "empty" in fexpr(QuenchedLiteral(span=N, type_param=None, value=None))
    assert fexpr(ident("x")) == "x"


def test_format_binary_and_unary():
    b = BinaryOp(span=N, left=ident("a"), op=TokenType.OR, right=ident("b"))
    assert fexpr(b) == "a or b"
    # high outer precedence forces parentheses
    assert fexpr(b, prec=10) == "(a or b)"
    # operator without an explicit symbol falls back to name
    weird = BinaryOp(span=N, left=ident("a"), op=TokenType.IN, right=ident("b"))
    assert "in" in fexpr(weird)
    assert fexpr(UnaryOp(span=N, operand=ident("a"), op=TokenType.MINUS)) == "-a"
    assert fexpr(UnaryOp(span=N, operand=ident("a"), op=TokenType.NOT)) == "not a"


def test_format_call_member_array():
    assert fexpr(CallExpr(span=N, callee=ident("f"),
                          args=[IntLiteral(span=N, value=1)])) == "f(1)"
    assert fexpr(MemberAccess(span=N, obj=ident("o"), member="m")) == "o.m"
    assert fexpr(ArrayLiteral(span=N, elements=[IntLiteral(span=N, value=1)])) == "[1]"


def test_format_pipe_guard():
    p = PipeExpr(span=N, left=ident("a"), right=ident("b"))
    assert fexpr(p) == "a |> b"
    assert fexpr(p, prec=5) == "(a |> b)"
    g = GuardExpr(span=N, expr=ident("x"), condition=ident("c"))
    assert "thirst x quench c" == fexpr(g)


def test_format_reservoir_ops():
    assert fexpr(FloodExpr(span=N, target=ident("r"))) == "flood(r)"
    assert fexpr(DripExpr(span=N, target=ident("r"))) == "drip(r)"
    assert fexpr(EvaporateExpr(span=N, target=ident("r"))) == "evaporate(r)"
    assert fexpr(CondenseExpr(span=N, target=ident("r"))) == "condense(r)"


def test_format_misc_exprs():
    assert fexpr(NewExpr(span=N, class_name="C", args=[])) == "new C()"
    assert fexpr(SanitizeExpr(span=N, expr=ident("x"))) == "sanitize(x)"
    assert fexpr(ArmorExpr(span=N, expr=ident("x"))) == "armor(x)"
    assert fexpr(SymbolExpr(span=N, symbol_name="COG")) == "$COG"
    assert fexpr(PipelineExpr(span=N, left=ident("a"), right=ident("b"))) == "a -> b"
    assert fexpr(CombineExpr(span=N, left=ident("a"), op="^", right=ident("b"))) == "a ^ b"
    assert fexpr(CombineExpr(span=N, left=ident("a"), op="||", right=ident("b"))) == "a || b"
    assert "unknown expr" in fexpr(Expr(span=N))


# === statements ============================================================

def test_format_variable_and_funcs():
    v = VariableDecl(span=N, name="x", var_type="int",
                     init_expr=IntLiteral(span=N, value=1), is_mut=True)
    assert "mut drink x: int = 1" in F.format_stmt(v)
    fn = FunctionDecl(span=N, name="f", params=[("a", "int"), ("b", None)],
                      return_type="int", body=block(ReturnStmt(span=N, value=ident("a"))))
    out = F.format_stmt(fn)
    assert "glass f(a: int, b): int {" in out


def test_format_class():
    m = FunctionDecl(span=N, name="g", params=[], return_type=None, body=block())
    c = ClassDecl(span=N, name="C", methods=[m], fields=[("x", "int")])
    out = F.format_stmt(c)
    assert "fountain C {" in out
    assert "drink x: int" in out


def test_format_if_chain():
    # if A {} hydrated if B {} hydrated if C {} hydrated {}  → exercises recursion
    inner = IfStmt(span=N, condition=ident("c"), then_block=block(), else_block=block())
    mid = IfStmt(span=N, condition=ident("b"), then_block=block(), else_block=inner)
    outer = IfStmt(span=N, condition=ident("a"), then_block=block(), else_block=mid)
    out = F.format_stmt(outer)
    assert "thirsty a {" in out and "hydrated" in out
    # plain else block branch
    plain = IfStmt(span=N, condition=ident("a"), then_block=block(), else_block=block())
    assert "hydrated {" in F.format_stmt(plain)
    # no else
    assert "hydrated" not in F.format_stmt(
        IfStmt(span=N, condition=ident("a"), then_block=block(), else_block=None))


def test_format_loops():
    assert "refill c {" in F.format_stmt(
        WhileStmt(span=N, condition=ident("c"), body=block()))
    assert "refill i in xs {" in F.format_stmt(
        ForStmt(span=N, variable=ident("i"), iterable=ident("xs"), body=block()))


def test_format_simple_stmts():
    assert F.format_stmt(ReturnStmt(span=N, value=None)).strip() == "return"
    assert "pour x" in F.format_stmt(PourStmt(span=N, value=ident("x")))
    assert "sip -> y" in F.format_stmt(SipStmt(span=N, target=ident("y")))
    assert F.format_stmt(SipStmt(span=N, target=None)).strip() == "sip"
    assert "a = b" in F.format_stmt(
        AssignStmt(span=N, target=ident("a"), value=ident("b")))
    assert "import 'm' as alias" in F.format_stmt(
        ImportStmt(span=N, module_path="m", alias="alias"))
    assert "import 'm'" in F.format_stmt(ImportStmt(span=N, module_path="m", alias=None))
    assert "x" in F.format_stmt(ExprStmt(span=N, expr=ident("x")))
    assert "throw x" in F.format_stmt(ThrowStmt(span=N, value=ident("x")))
    assert "cascade x" in F.format_stmt(CascadeCall(span=N, expr=ident("x")))


def test_format_blocks_and_handlers():
    sec = SecurityBlock(span=N, block_type="shield", body=block())
    assert "shield {" in F.format_stmt(sec)
    sp = SpillageStmt(span=N, body=block(),
                      handlers=[("ValueError", block())])
    out = F.format_stmt(sp)
    assert "spillage {" in out and "spillage ValueError {" in out
    cl = CleanupStmt(span=N, body=block(), finalizer=block())
    assert "cleanup {" in F.format_stmt(cl) and "finally {" in F.format_stmt(cl)


def test_format_governed_and_morph():
    g = GovernedFunctionDecl(
        span=N, name="w", params=[("a", "int")], return_type="int",
        body=block(), requires_annotation="a > 0",
        ensures_annotation="result > 0", invariant_annotation="a < 100")
    out = F.format_stmt(g)
    assert "requires a > 0" in out
    assert "ensures result > 0" in out
    assert "invariant a < 100" in out
    mo = MorphDef(span=N, name="m", params=[("a", "int")], body=block())
    assert "morph m(a: int) {" in F.format_stmt(mo)


def test_format_decls():
    assert "defend d: pol = a, b" in F.format_stmt(
        DefendStrat(span=N, name="d", policy="pol", actions=["a", "b"]))
    assert "enum E = A, B" in F.format_stmt(
        EnumDecl(span=N, name="E", variants=["A", "B"]))
    assert "struct S(a: int, b)" in F.format_stmt(
        StructDecl(span=N, name="S", fields=[("a", "int"), ("b", None)]))
    assert "interface I(f, g)" in F.format_stmt(
        InterfaceDecl(span=N, name="I", methods=["f", "g"]))


def test_format_mutation():
    mut = ShadowThirstMutation(
        span=N, name="mx",
        shadow_block=block(ReturnStmt(span=N, value=ident("x"))),
        invariant_block=block(ReturnStmt(span=N, value=ident("x"))),
        canonical_block=block(ReturnStmt(span=N, value=ident("x"))))
    out = F.format_stmt(mut)
    assert "mutation mx {" in out
    assert "shadow {" in out and "invariant {" in out and "canonical {" in out


def test_format_blockstmt_via_format_stmt():
    out = F.format_stmt(block(PourStmt(span=N, value=ident("x"))))
    assert "pour x" in out


def test_format_unknown_stmt():
    assert "unknown node" in F.format_stmt(Stmt(span=N))


def test_format_program_and_top_level():
    prog = Program(span=N, header=ModuleHeader(span=N, name="m", mode="core"),
                   stmts=[PourStmt(span=N, value=IntLiteral(span=N, value=1))])
    out = F.format(prog)
    assert out.startswith("module m: core")
    assert out.endswith("\n")
