"""
Thirsty-Lang Recursive Descent Parser
Produces an AST Program from a list of Tokens. Supports error recovery
and "did you mean?" suggestions within edit distance 3.
"""
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
    SymbolStmt,
    ThrowStmt,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from utf.thirsty_lang.diagnostics import Diagnostic, make_error
from utf.thirsty_lang.token import KEYWORDS, Token, TokenType


def _edit_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def _nearest_match(name: str, candidates: list[str], max_dist: int = 3) -> list[str]:
    """Find all candidates within edit distance max_dist of name."""
    return [c for c in candidates if _edit_distance(name, c) <= max_dist]


class Parser:
    """Recursive descent parser for Thirsty-Lang."""

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.current = 0
        self.errors: list[Diagnostic] = []

    def parse(self) -> Program:
        """Parse the token stream into a Program AST."""
        header = self._parse_module_header()
        stmts = []
        while not self._is_at_end():
            try:
                stmt = self._parse_statement()
                if stmt is not None:
                    stmts.append(stmt)
                else:
                    self._advance()  # Skip unrecognized
            except Exception as e:
                self.errors.append(make_error("E901", span=self._current_span(),
                                              detail=str(e)))
                self._synchronize()
        span = self._span_range()
        # Fail closed for governed modules: if parsing produced any errors, the
        # recovered statements cannot be trusted to preserve author intent, so
        # discard them entirely rather than letting recovery smuggle executable
        # statements past a malformed boundary. The interpreter refuses to run a
        # program flagged this way.
        if self.errors and header is not None and header.mode == "governed":
            return Program(stmts=[], header=header, span=span,
                           parse_failed=True)
        return Program(stmts=stmts, header=header, span=span)

    def _is_at_end(self) -> bool:
        return self._peek().type == TokenType.EOF

    def _peek(self) -> Token:
        return self.tokens[self.current]

    def _previous(self) -> Token:
        return self.tokens[self.current - 1]

    def _advance(self) -> Token:
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _check(self, *types: TokenType) -> bool:
        if self._is_at_end():
            return False
        return self._peek().type in types

    def _match(self, *types: TokenType) -> bool:
        for t in types:
            if self._check(t):
                self._advance()
                return True
        return False

    def _expect(self, token_type: TokenType, error_code: str = "E901", **kwargs) -> Token:
        if self._check(token_type):
            return self._advance()
        msg = f"Expected {token_type.name} but got {self._peek().type.name}"
        span = self._current_span()
        self.errors.append(make_error(error_code, span=span, detail=msg))
        # Return a synthetic token
        return Token(token_type, "", self._peek().line, self._peek().col)

    def _current_span(self) -> tuple:
        t = self._peek()
        return (t.line, t.col, t.line, t.col + len(t.lexeme))

    def _span_range(self) -> tuple:
        if len(self.tokens) > 1:
            first = self.tokens[0]
            last = self.tokens[-1]
            return (first.line, first.col, last.line, last.col + len(last.lexeme))
        return (1, 1, 1, 1)

    def _span(self, start_token: Token | None = None) -> tuple:
        if start_token is None:
            start_token = self.tokens[0]
        end_token = self._previous()
        return (start_token.line, start_token.col,
                end_token.line, end_token.col + len(end_token.lexeme))

    def _synchronize(self):
        """Skip tokens until a statement boundary is found (error recovery)."""
        while not self._is_at_end():
            if self._previous().type == TokenType.SEMICOLON:
                return
            t = self._peek().type
            if t in (TokenType.DRINK, TokenType.POUR, TokenType.SIP,
                     TokenType.THIRSTY, TokenType.REFILL, TokenType.RETURN,
                     TokenType.IMPORT, TokenType.GLASS, TokenType.FOUNTAIN,
                     TokenType.SPILLAGE, TokenType.SHIELD, TokenType.MUTATION,
                     TokenType.REQUIRES, TokenType.RBRACE, TokenType.EOF):
                return
            self._advance()

    # === Module Header ===

    def _parse_module_header(self) -> ModuleHeader | None:
        if not self._match(TokenType.MODULE):
            return None
        name_token = self._expect(TokenType.IDENTIFIER, "E901", detail="Expected module name")
        self._expect(TokenType.COLON, "E901", detail="Expected ':' after module name")
        self._peek()
        mode = "core"
        if self._match(TokenType.GOVERNED):
            mode = "governed"
        elif self._match(TokenType.CORE):
            mode = "core"
        elif self._match(TokenType.STRICT):
            mode = "strict"
        elif self._match(TokenType.PURE):
            mode = "pure"
        else:
            self._expect(TokenType.IDENTIFIER, "E901",
                         detail="Expected mode (core/governed/strict/pure)")
        span = self._span(name_token)
        return ModuleHeader(name=name_token.lexeme, mode=mode, span=span)

    # === Statement Parsing ===

    def _parse_statement(self) -> object | None:
        t = self._peek().type

        if t == TokenType.DRINK:
            return self._parse_variable_decl()
        elif t == TokenType.LET:
            return self._parse_let_decl()
        elif t == TokenType.FOR:
            return self._parse_for_stmt()
        elif t == TokenType.IDENTIFIER and self._peek_next(1).type == TokenType.COLONEQ:
            return self._parse_walrus_decl()
        elif t == TokenType.POUR:
            return self._parse_pour_stmt()
        elif t == TokenType.SIP:
            return self._parse_sip_stmt()
        elif t == TokenType.THIRSTY:
            return self._parse_if_stmt()
        elif t == TokenType.REFILL:
            return self._parse_refill_stmt()
        elif t == TokenType.RETURN:
            return self._parse_return_stmt()
        elif t == TokenType.IMPORT:
            return self._parse_import_stmt()
        elif t == TokenType.LBRACE:
            return self._parse_block()
        elif t == TokenType.GLASS:
            return self._parse_function_decl()
        elif t == TokenType.FOUNTAIN:
            return self._parse_class_decl()
        elif t == TokenType.SPILLAGE:
            return self._parse_spillage_stmt()
        elif t == TokenType.CLEANUP:
            return self._parse_cleanup_stmt()
        elif t == TokenType.THROW:
            return self._parse_throw_stmt()
        elif t == TokenType.SHIELD:
            return self._parse_security_block("shield")
        elif t == TokenType.SANITIZE:
            return self._parse_sanitize_expr()
        elif t == TokenType.ARMOR:
            return self._parse_armor_expr()
        elif t == TokenType.MORPH:
            return self._parse_morph_def()
        elif t == TokenType.DETECT:
            return self._parse_security_block("detect")
        elif t == TokenType.DEFEND:
            return self._parse_defend_strat()
        elif t == TokenType.CASCADE:
            return self._parse_cascade_call()
        elif t == TokenType.NEW:
            return self._parse_new_expr()
        elif t == TokenType.ENUM:
            return self._parse_enum_decl()
        elif t == TokenType.STRUCT:
            return self._parse_struct_decl()
        elif t == TokenType.INTERFACE:
            return self._parse_interface_decl()
        elif t == TokenType.MUTATION:
            return self._parse_shadow_thirst_mutation()
        elif t == TokenType.SYMBOL:
            return self._parse_tscg_symbol()
        elif t == TokenType.PIPE:
            return self._parse_pipe_block_stmt()
        else:
            return self._parse_expr_statement()

    def _parse_pipe_block_stmt(self) -> ExprStmt:
        """Parse | [>] expression — pipe block statement.

        At statement level, pipes a value through a pipeline expression.
        The pipe symbol introduces an expression that may contain further
        infix pipe operators (| for PipeExpr).
        """
        start = self._advance()  # consume PIPE
        self._match(TokenType.GT)  # optional > for |>
        expr = self._parse_expr()
        self._expect(TokenType.SEMICOLON, "E901", detail="Expected ';' after pipe expression")
        return ExprStmt(expr=expr, span=self._span(start))

    def _parse_block(self) -> BlockStmt:
        start = self._advance()  # consume {
        stmts = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            stmt = self._parse_statement()
            if stmt:
                stmts.append(stmt)
            else:
                self._advance()
        self._expect(TokenType.RBRACE, "E901", detail="Expected '}' to close block")
        return BlockStmt(statements=stmts, span=self._span(start))

    def _parse_variable_decl(self) -> VariableDecl:
        start = self._advance()  # drink
        is_mut = self._match(TokenType.MUT)
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected variable name after 'drink'")
        var_type = None
        if self._match(TokenType.COLON):
            type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                      detail="Expected type after ':'")
            var_type = type_token.lexeme
        init_expr = None
        if self._match(TokenType.ASSIGN):
            init_expr = self._parse_expr()
        elif self._match(TokenType.EQ):
            init_expr = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return VariableDecl(name=name_token.lexeme, var_type=var_type,
                            init_expr=init_expr, is_mut=is_mut, span=self._span(start))

    def _parse_let_decl(self) -> VariableDecl:
        """let name [: type] = expr — immutable binding (analogous to `drink`)."""
        start = self._advance()  # let
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected variable name after 'let'")
        var_type = None
        if self._match(TokenType.COLON):
            type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                      detail="Expected type after ':'")
            var_type = type_token.lexeme
        init_expr = None
        if self._match(TokenType.ASSIGN):
            init_expr = self._parse_expr()
        elif self._match(TokenType.EQ):
            init_expr = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return VariableDecl(name=name_token.lexeme, var_type=var_type,
                            init_expr=init_expr, is_mut=False,
                            span=self._span(start))

    def _parse_walrus_decl(self) -> VariableDecl:
        """name := expr — define-and-assign a new mutable binding."""
        name_token = self._advance()  # identifier
        self._advance()  # :=
        init_expr = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return VariableDecl(name=name_token.lexeme, var_type=None,
                            init_expr=init_expr, is_mut=True,
                            span=self._span(name_token))

    def _parse_for_stmt(self) -> ForStmt:
        """for [(] x in iterable [)] { body } — keyword form of refill(x in xs)."""
        start = self._advance()  # for
        has_paren = self._match(TokenType.LPAREN)
        var_token = self._expect(TokenType.IDENTIFIER, "E901",
                                 detail="Expected loop variable after 'for'")
        self._expect(TokenType.IN, "E901",
                     detail="Expected 'in' after loop variable")
        iterable = self._parse_expr()
        if has_paren:
            self._expect(TokenType.RPAREN, "E901",
                         detail="Expected ')' after iterable")
        body = self._parse_block()
        return ForStmt(
            variable=Identifier(name=var_token.lexeme,
                                span=self._span(var_token)),
            iterable=iterable, body=body, span=self._span(start))

    def _parse_pour_stmt(self) -> PourStmt:
        start = self._advance()
        value = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return PourStmt(value=value, span=self._span(start))

    def _parse_sip_stmt(self) -> SipStmt:
        start = self._advance()
        target = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return SipStmt(target=target, span=self._span(start))

    def _parse_if_stmt(self) -> IfStmt:
        start = self._advance()  # thirsty
        self._expect(TokenType.LPAREN, "E901", detail="Expected '(' after 'thirsty'")
        condition = self._parse_expr()
        self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after condition")
        then_block = self._parse_block()
        else_block: Stmt | None = None
        if self._match(TokenType.HYDRATED):
            if self._check(TokenType.THIRSTY):
                else_block = self._parse_if_stmt()  # else if
            else:
                else_block = self._parse_block()
        return IfStmt(condition=condition, then_block=then_block,
                      else_block=else_block, span=self._span(start))

    def _parse_refill_stmt(self) -> WhileStmt | ForStmt:
        start = self._advance()  # refill
        self._expect(TokenType.LPAREN, "E901", detail="Expected '(' after 'refill'")
        # Try to detect for-loop: refill(var in iterable)
        if self._check(TokenType.IDENTIFIER) and self._peek_next(1).type == TokenType.IN:
            var_token = self._advance()
            self._advance()  # in
            iterable = self._parse_expr()
            self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after iterable")
            body = self._parse_block()
            return ForStmt(variable=Identifier(name=var_token.lexeme, span=self._span(var_token)),
                           iterable=iterable, body=body, span=self._span(start))
        # While loop: refill(condition)
        condition = self._parse_expr()
        self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after condition")
        body = self._parse_block()
        return WhileStmt(condition=condition, body=body, span=self._span(start))

    def _parse_return_stmt(self) -> ReturnStmt:
        start = self._advance()
        value = None
        if not self._check(TokenType.SEMICOLON) and not self._check(TokenType.RBRACE):
            value = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return ReturnStmt(value=value, span=self._span(start))

    def _parse_import_stmt(self) -> ImportStmt:
        start = self._advance()
        path_token = self._expect(TokenType.STRING, "E901",
                                  detail="Expected module path string after 'import'")
        alias = None
        if self._match(TokenType.AS):
            alias_token = self._expect(TokenType.IDENTIFIER, "E901",
                                       detail="Expected alias name after 'as'")
            alias = alias_token.lexeme
        self._match(TokenType.SEMICOLON)
        return ImportStmt(module_path=path_token.lexeme, alias=alias, span=self._span(start))

    def _parse_function_decl(self) -> FunctionDecl | GovernedFunctionDecl:
        start = self._advance()  # glass
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected function name after 'glass'")
        params = self._parse_params()
        return_type = None
        if self._match(TokenType.ARROW):
            type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                      detail="Expected return type after '->'")
            return_type = type_token.lexeme
        # Governance clauses (any order): requires / ensures / invariant.
        clauses = {}
        while self._check(TokenType.REQUIRES, TokenType.ENSURES,
                          TokenType.INVARIANT):
            kind = self._advance().type
            c_start = self.current
            expr = self._parse_expr()
            text = " ".join(
                t.lexeme for t in self.tokens[c_start:self.current])
            clauses[kind] = (expr, text)
        body = self._parse_block()
        if clauses:
            req = clauses.get(TokenType.REQUIRES, (None, None))
            ens = clauses.get(TokenType.ENSURES, (None, None))
            inv = clauses.get(TokenType.INVARIANT, (None, None))
            return GovernedFunctionDecl(
                name=name_token.lexeme, params=params,
                return_type=return_type, body=body,
                requires_annotation=req[1], requires_expr=req[0],
                ensures_annotation=ens[1], ensures_expr=ens[0],
                invariant_annotation=inv[1], invariant_expr=inv[0],
                span=self._span(start))
        return FunctionDecl(name=name_token.lexeme, params=params,
                            return_type=return_type, body=body, span=self._span(start))

    def _parse_class_decl(self) -> ClassDecl:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected class name after 'fountain'")
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for class body")
        fields = []
        methods = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._check(TokenType.GLASS):
                methods.append(self._parse_function_decl())
            else:
                tok = self._peek()
                if tok.type == TokenType.IDENTIFIER:
                    name_t = self._advance()
                    var_type = None
                    if self._match(TokenType.COLON):
                        type_t = self._expect(TokenType.IDENTIFIER, "E901",
                                              detail="Expected field type")
                        var_type = type_t.lexeme
                    fields.append((name_t.lexeme, var_type))
                    self._match(TokenType.SEMICOLON)
                else:
                    self._advance()
        self._expect(TokenType.RBRACE, "E901", detail="Expected '}' to close class")
        return ClassDecl(name=name_token.lexeme, methods=methods,
                         fields=fields, span=self._span(start))

    def _parse_params(self) -> list:
        params = []
        self._expect(TokenType.LPAREN, "E901", detail="Expected '(' for parameters")
        if not self._check(TokenType.RPAREN):
            name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                      detail="Expected parameter name")
            param_type = None
            if self._match(TokenType.COLON):
                type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                          detail="Expected parameter type")
                param_type = type_token.lexeme
            params.append((name_token.lexeme, param_type))
            while self._match(TokenType.COMMA):
                name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                          detail="Expected parameter name")
                param_type = None
                if self._match(TokenType.COLON):
                    type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                              detail="Expected parameter type")
                    param_type = type_token.lexeme
                params.append((name_token.lexeme, param_type))
        self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after parameters")
        return params

    def _parse_spillage_stmt(self) -> SpillageStmt:
        start = self._advance()
        body = self._parse_block()
        handlers = []
        while self._match(TokenType.ERROR):
            # error (type) { handler_block }
            error_expr = Identifier(name="error", span=self._current_span())
            handler_block = self._parse_block()
            handlers.append((error_expr, handler_block))
        return SpillageStmt(body=body, handlers=handlers, span=self._span(start))

    def _parse_cleanup_stmt(self) -> CleanupStmt:
        start = self._advance()
        body = self._parse_block()
        self._expect(TokenType.FINALLY, "E901",
                      detail="Expected 'finally' after cleanup body")
        finalizer = self._parse_block()
        return CleanupStmt(body=body, finalizer=finalizer, span=self._span(start))

    def _parse_throw_stmt(self) -> ThrowStmt:
        start = self._advance()
        value = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        return ThrowStmt(value=value, span=self._span(start))

    def _parse_security_block(self, block_type: str) -> SecurityBlock:
        start = self._advance()
        body = self._parse_block()
        return SecurityBlock(block_type=block_type, body=body, span=self._span(start))

    def _parse_sanitize_expr(self) -> SanitizeExpr:
        start = self._advance()
        expr = self._parse_expr()
        return SanitizeExpr(expr=expr, span=self._span(start))

    def _parse_armor_expr(self) -> ArmorExpr:
        start = self._advance()
        expr = self._parse_expr()
        return ArmorExpr(expr=expr, span=self._span(start))

    def _parse_morph_def(self) -> MorphDef:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected morph name")
        params = self._parse_params()
        body = self._parse_block()
        return MorphDef(name=name_token.lexeme, params=params,
                        body=body, span=self._span(start))

    def _parse_defend_strat(self) -> DefendStrat:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected defend strategy name")
        # Parse policy name
        policy = ""
        if self._match(TokenType.LPAREN):
            policy_token = self._expect(TokenType.IDENTIFIER, "E901",
                                        detail="Expected policy name")
            policy = policy_token.lexeme
            self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after policy")
        # Parse actions block
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for actions")
        actions = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            actions.append(self._parse_expr())
            self._match(TokenType.SEMICOLON)
        self._expect(TokenType.RBRACE, "E901", detail="Expected '}' after actions")
        return DefendStrat(name=name_token.lexeme, policy=policy,
                           actions=actions, span=self._span(start))

    def _parse_enum_decl(self) -> EnumDecl:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected enum name")
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for enum variants")
        variants = []
        if not self._check(TokenType.RBRACE):
            var_token = self._expect(TokenType.IDENTIFIER, "E901",
                                     detail="Expected variant name")
            variants.append(var_token.lexeme)
            while self._match(TokenType.COMMA):
                var_token = self._expect(TokenType.IDENTIFIER, "E901",
                                         detail="Expected variant name")
                variants.append(var_token.lexeme)
        self._expect(TokenType.RBRACE, "E901", detail="Expected '}' after enum variants")
        return EnumDecl(name=name_token.lexeme, variants=variants, span=self._span(start))

    def _parse_struct_decl(self) -> StructDecl:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected struct name")
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for struct fields")
        fields = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            field_token = self._expect(TokenType.IDENTIFIER, "E901",
                                       detail="Expected field name")
            field_type = None
            if self._match(TokenType.COLON):
                type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                          detail="Expected field type")
                field_type = type_token.lexeme
            fields.append((field_token.lexeme, field_type))
            self._match(TokenType.SEMICOLON)
        self._expect(TokenType.RBRACE, "E901", detail="Expected '}' after struct fields")
        return StructDecl(name=name_token.lexeme, fields=fields, span=self._span(start))

    def _parse_interface_decl(self) -> InterfaceDecl:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected interface name")
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for interface methods")
        methods = []
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            method_token = self._expect(TokenType.IDENTIFIER, "E901",
                                        detail="Expected method name")
            params = self._parse_params()
            ret_type = None
            if self._match(TokenType.ARROW):
                type_token = self._expect(TokenType.IDENTIFIER, "E901",
                                          detail="Expected return type")
                ret_type = type_token.lexeme
            methods.append((method_token.lexeme, params, ret_type))
            self._match(TokenType.SEMICOLON)
        self._expect(TokenType.RBRACE, "E901", detail="Expected '}' after interface methods")
        return InterfaceDecl(name=name_token.lexeme, methods=methods, span=self._span(start))

    def _parse_cascade_call(self) -> CascadeCall:
        start = self._advance()
        expr = self._parse_expr()
        return CascadeCall(expr=expr, span=self._span(start))

    def _parse_new_expr(self) -> NewExpr:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected class name after 'new'")
        args = []
        if self._match(TokenType.LPAREN):
            if not self._check(TokenType.RPAREN):
                args.append(self._parse_expr())
                while self._match(TokenType.COMMA):
                    args.append(self._parse_expr())
            self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after arguments")
        return NewExpr(class_name=name_token.lexeme, args=args, span=self._span(start))

    def _parse_shadow_thirst_mutation(self) -> ShadowThirstMutation:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected mutation name")
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for mutation body")
        self._expect(TokenType.VALIDATED_CANONICAL, "E901",
                      detail="Expected 'validated_canonical'")
        self._expect(TokenType.LBRACE, "E901", detail="Expected '{' for validated_canonical")
        shadow_block = None
        invariant_block = None
        canonical_block = None
        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.SHADOW):
                shadow_block = self._parse_block()
            elif self._match(TokenType.INVARIANT):
                invariant_block = self._parse_block()
            elif self._match(TokenType.CANONICAL):
                canonical_block = self._parse_block()
            else:
                self._advance()
        self._expect(TokenType.RBRACE, "E901",
                      detail="Expected '}' after validated_canonical")
        self._expect(TokenType.RBRACE, "E901",
                      detail="Expected '}' after mutation body")
        return ShadowThirstMutation(name=name_token.lexeme,
                                    shadow_block=shadow_block,
                                    invariant_block=invariant_block,
                                    canonical_block=canonical_block,
                                    span=self._span(start))

    def _parse_tscg_symbol(self) -> object:
        start = self._advance()
        name_token = self._expect(TokenType.IDENTIFIER, "E901",
                                  detail="Expected TSCG symbol name")
        self._match(TokenType.SEMICOLON)
        return SymbolStmt(symbol_name=name_token.lexeme, span=self._span(start))

    def _parse_expr_statement(self) -> Stmt:
        start = self._peek()
        expr = self._parse_expr()
        self._match(TokenType.SEMICOLON)
        # `x = y` parses as an AssignStmt; return it directly so it dispatches
        # to _execute_assign. Wrapping it in an ExprStmt would route it through
        # expression evaluation, which has no AssignStmt branch — making the
        # assignment a silent no-op.
        if isinstance(expr, AssignStmt):
            return expr
        return ExprStmt(expr=expr, span=self._span(start))

    # === Expression Parsing with Precedence ===

    def _parse_expr(self, precedence: int = 0) -> Expr:
        """Parse expression with Pratt-style precedence climbing."""
        prefix = self._parse_prefix()
        if prefix is None:
            t = self._peek()
            msg = f"Unexpected token: {t.type.name} ('{t.lexeme}')"
            # Check "did you mean?" for identifiers
            if t.type == TokenType.IDENTIFIER:
                suggestions = _nearest_match(t.lexeme, list(KEYWORDS.keys()))
                if suggestions:
                    msg += f" Did you mean: {', '.join(suggestions)}?"
            self.errors.append(make_error("E901", span=self._current_span(), detail=msg))
            self._advance()
            return Identifier(name="__error__", span=self._current_span())

        while precedence < self._get_precedence():
            token = self._peek()
            op = token.type
            # Capture the operator's precedence BEFORE advancing past it. After
            # _advance() the current token is the right operand (precedence 0 for
            # literals/identifiers), so reading precedence post-advance silently
            # collapsed every operator to one right-associative level.
            op_prec = self._get_precedence()
            # The loop guard above is strict (`precedence < peek`), so a left-
            # associative operator recurses at `op_prec` (the right side grabs
            # only strictly-tighter operators; an equal-precedence operator
            # returns here and binds to the new left). A right-associative
            # operator recurses at `op_prec - 1` so it also grabs its equal.
            if op == TokenType.ASSIGN or op == TokenType.EQ:
                self._advance()
                right = self._parse_expr(op_prec - 1)  # right-associative
                # Assignment is parsed at expression precedence but yields a
                # statement node (AssignStmt); the caller handles it as such.
                return AssignStmt(  # type: ignore[return-value]
                    target=prefix, value=right,
                    span=(prefix.span[0], prefix.span[1],
                          right.span[2], right.span[3]))
            elif op == TokenType.LPAREN:
                prefix = self._parse_call_suffix(prefix)
            elif op == TokenType.PIPE:
                self._advance()
                right = self._parse_expr(op_prec)
                prefix = PipeExpr(left=prefix, right=right,
                                  span=(prefix.span[0], prefix.span[1],
                                        right.span[2], right.span[3]))
            elif op in (TokenType.PLUS, TokenType.MINUS, TokenType.STAR,
                        TokenType.SLASH, TokenType.PERCENT, TokenType.EQEQ,
                        TokenType.NE, TokenType.LT, TokenType.GT,
                        TokenType.LE, TokenType.GE, TokenType.AND,
                        TokenType.OR):
                self._advance()
                right = self._parse_expr(op_prec)  # left-associative
                prefix = BinaryOp(left=prefix, op=op, right=right,
                                  span=(prefix.span[0], prefix.span[1],
                                        right.span[2], right.span[3]))
            elif op == TokenType.PIPEPIPE:
                self._advance()
                right = self._parse_expr(op_prec)
                prefix = CombineExpr(left=prefix, op="||", right=right,
                                     span=(prefix.span[0], prefix.span[1],
                                           right.span[2], right.span[3]))
            elif op == TokenType.HATHAT:
                self._advance()
                right = self._parse_expr(op_prec)
                prefix = CombineExpr(left=prefix, op="^", right=right,
                                     span=(prefix.span[0], prefix.span[1],
                                           right.span[2], right.span[3]))
            elif op == TokenType.ARROW:
                self._advance()
                right = self._parse_expr(op_prec)
                prefix = PipelineExpr(left=prefix, right=right,
                                      span=(prefix.span[0], prefix.span[1],
                                            right.span[2], right.span[3]))
            elif op == TokenType.DOT:
                self._advance()
                # After '.', the word is a member name in the object's
                # namespace, not a language keyword: accept any token whose
                # lexeme is a valid identifier (e.g. `log.error`, where `error`
                # otherwise lexes as the ERROR keyword).
                if (not self._check(TokenType.IDENTIFIER)
                        and self._peek().lexeme.isidentifier()):
                    member_token = self._advance()
                else:
                    member_token = self._expect(
                        TokenType.IDENTIFIER, "E901",
                        detail="Expected method/property name after '.'")
                member = MemberAccess(
                    obj=prefix, member=member_token.lexeme,
                    span=(prefix.span[0], prefix.span[1],
                          member_token.line,
                          member_token.col + len(member_token.lexeme)))
                if self._check(TokenType.LPAREN):
                    # method call: obj.method(args) — object carried by callee
                    args = []
                    self._advance()
                    if not self._check(TokenType.RPAREN):
                        args.append(self._parse_expr())
                        while self._match(TokenType.COMMA):
                            args.append(self._parse_expr())
                    self._expect(TokenType.RPAREN, "E901",
                                 detail="Expected ')' after arguments")
                    span = (prefix.span[0], prefix.span[1],
                            self._previous().line, self._previous().col + 1)
                    prefix = CallExpr(callee=member, args=args, span=span)
                else:
                    prefix = member
            else:
                break
        return prefix

    def _parse_prefix(self) -> Expr | None:
        """Parse prefix expressions (literals, identifiers, unary operators)."""
        t = self._peek().type

        if t == TokenType.INT:
            return self._parse_int_literal()
        elif t == TokenType.FLOAT:
            return self._parse_float_literal()
        elif t == TokenType.STRING:
            return self._parse_string_literal()
        elif t == TokenType.BOOL_TRUE:
            return self._parse_bool_literal(True)
        elif t == TokenType.BOOL_FALSE:
            return self._parse_bool_literal(False)
        elif t == TokenType.NONE:
            return self._parse_none_literal()
        elif t == TokenType.IDENTIFIER:
            id_token = self._advance()
            return Identifier(name=id_token.lexeme, span=self._span(id_token))
        elif t == TokenType.LPAREN:
            self._advance()
            expr = self._parse_expr()
            self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after expression")
            return expr
        elif t == TokenType.LBRACKET:
            return self._parse_reservoir_literal()
        elif t == TokenType.MINUS:
            self._advance()
            # Unary binds tighter than every binary operator: parse only the
            # primary (with member/call suffixes), not a trailing binary chain,
            # so -2 + 3 is (-2) + 3, not -(2 + 3).
            operand = self._parse_expr(self.UNARY_PRECEDENCE)
            return UnaryOp(operand=operand, op=TokenType.MINUS,
                           span=self._span())
        elif t == TokenType.NOT:
            self._advance()
            # Logical `not` binds looser than comparison but tighter than
            # `and`/`or`: not a == b is not (a == b); not a and b is
            # (not a) and b. Operand grabs everything above the `and` level.
            operand = self._parse_expr(self.NOT_PRECEDENCE)
            return UnaryOp(operand=operand, op=TokenType.NOT,
                           span=self._span())
        elif t == TokenType.FLOOD:
            self._advance()
            target = self._parse_expr()
            return FloodExpr(target=target, span=self._span())
        elif t == TokenType.DRIP:
            self._advance()
            target = self._parse_expr()
            return DripExpr(target=target, span=self._span())
        elif t == TokenType.CONDENSE:
            self._advance()
            target = self._parse_expr()
            return CondenseExpr(target=target, span=self._span())
        elif t == TokenType.EVAPORATE:
            self._advance()
            target = self._parse_expr()
            return EvaporateExpr(target=target, span=self._span())
        elif t == TokenType.THIRST:
            return self._parse_guard_expr()
        elif t == TokenType.QUENCHED:
            return self._parse_quenched_literal()
        elif t == TokenType.SANITIZE:
            return self._parse_sanitize_expr()
        elif t == TokenType.ARMOR:
            return self._parse_armor_expr()
        elif t == TokenType.NEW:
            return self._parse_new_expr()
        elif t == TokenType.CASCADE:
            return self._parse_cascade_call()
        return None

    def _parse_int_literal(self) -> IntLiteral:
        t = self._advance()
        value = int(t.lexeme, 0) if t.lexeme.startswith(("0x", "0X", "0b", "0B", "0o", "0O")) else int(t.lexeme)
        return IntLiteral(value=value, span=self._span(t))

    def _parse_float_literal(self) -> FloatLiteral:
        t = self._advance()
        return FloatLiteral(value=float(t.lexeme), span=self._span(t))

    def _parse_string_literal(self) -> StringLiteral:
        t = self._advance()
        return StringLiteral(value=t.lexeme, span=self._span(t))

    def _parse_bool_literal(self, value: bool) -> BoolLiteral:
        t = self._advance()
        return BoolLiteral(value=value, span=self._span(t))

    def _parse_none_literal(self) -> NoneLiteral:
        t = self._advance()
        return NoneLiteral(span=self._span(t))

    def _parse_quenched_literal(self) -> QuenchedLiteral:
        t = self._advance()
        type_param = "Any"
        value = None
        if self._match(TokenType.LPAREN):
            if not self._check(TokenType.RPAREN):
                value = self._parse_expr()
            self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after quenched value")
        return QuenchedLiteral(type_param=type_param, value=value, span=self._span(t))

    def _parse_reservoir_literal(self) -> Expr:
        """Parse [elem1, elem2, ...] reservoir literal."""
        start = self._advance()
        elements = []
        if not self._check(TokenType.RBRACKET):
            elements.append(self._parse_expr())
            while self._match(TokenType.COMMA):
                elements.append(self._parse_expr())
        self._expect(TokenType.RBRACKET, "E901", detail="Expected ']' after reservoir literal")
        return ArrayLiteral(elements=elements, span=self._span(start))

    def _parse_call_suffix(self, callee: Expr) -> Expr:
        self._advance()  # consume (
        args = []
        if not self._check(TokenType.RPAREN):
            args.append(self._parse_expr())
            while self._match(TokenType.COMMA):
                args.append(self._parse_expr())
        self._expect(TokenType.RPAREN, "E901", detail="Expected ')' after arguments")
        return CallExpr(callee=callee, args=args, span=(callee.span[0], callee.span[1],
                                                         self._previous().line,
                                                         self._previous().col + 1))

    def _parse_guard_expr(self) -> GuardExpr:
        start = self._advance()  # thirst
        expr = self._parse_expr()
        self._expect(TokenType.QUENCH, "E901", detail="Expected 'quench' after guard expression")
        condition = self._parse_expr()
        return GuardExpr(expr=expr, condition=condition, span=self._span(start))

    # === Precedence Table ===

    # Binding power for prefix unary negation (-). Above multiplicative (7) so
    # the operand is just the primary plus its member/call suffixes (DOT/LPAREN
    # are 9, still tighter), never a trailing binary chain: -2 * 3 is (-2) * 3.
    UNARY_PRECEDENCE = 8
    # Binding power for logical `not`. At the `and` level (4) so the operand
    # grabs comparisons/arithmetic (>= 5) but not `and`/`or`.
    NOT_PRECEDENCE = 4

    def _get_precedence(self) -> int:
        """Return precedence of the current token (higher = binds tighter)."""
        token = self._peek()
        return self._precedence_map().get(token.type, 0)

    def _precedence_map(self) -> dict[TokenType, int]:
        return {
            TokenType.ASSIGN: 1,
            TokenType.EQ: 1,
            TokenType.PIPE: 2,
            TokenType.THIRST: 2,
            TokenType.OR: 3,
            TokenType.AND: 4,
            TokenType.EQEQ: 5,
            TokenType.NE: 5,
            TokenType.LT: 5,
            TokenType.GT: 5,
            TokenType.LE: 5,
            TokenType.GE: 5,
            TokenType.PLUS: 6,
            TokenType.MINUS: 6,
            TokenType.STAR: 7,
            TokenType.SLASH: 7,
            TokenType.PERCENT: 7,
            TokenType.ARROW: 8,
            TokenType.PIPEPIPE: 8,
            TokenType.HATHAT: 8,
            TokenType.DOT: 9,
            TokenType.LPAREN: 9,
        }

    def _peek_next(self, n: int = 1) -> Token:
        """Look ahead n tokens without consuming."""
        idx = self.current + n
        if idx >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[idx]
