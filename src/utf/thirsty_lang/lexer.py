"""
Thirsty-Lang Lexer
Character-by-character tokenizer with source span tracking and error handling.
"""
from utf.thirsty_lang.diagnostics import Diagnostic
from utf.thirsty_lang.token import KEYWORDS, Token, TokenType


class Lexer:
    """Tokenizes Thirsty-Lang source code into a list of Tokens."""

    def __init__(self, source: str):
        self.source = source
        self.tokens: list[Token] = []
        self.errors: list[Diagnostic] = []
        self.start = 0       # start of current lexeme
        self.current = 0     # current position
        self.line = 1
        self.col = 1
        self.line_start = 0  # column offset of line start for span tracking

    def lex(self) -> list[Token]:
        """Tokenize the entire source and return tokens."""
        while not self._is_at_end():
            self.start = self.current
            self._scan_token()
        self.tokens.append(Token(TokenType.EOF, "", self.line, self.col))
        return self.tokens

    def _is_at_end(self) -> bool:
        return self.current >= len(self.source)

    def _advance(self) -> str:
        ch = self.source[self.current]
        self.current += 1
        self.col += 1
        return ch

    def _peek(self) -> str:
        if self._is_at_end():
            return "\0"
        return self.source[self.current]

    def _peek_next(self) -> str:
        if self.current + 1 >= len(self.source):
            return "\0"
        return self.source[self.current + 1]

    def _match(self, expected: str) -> bool:
        if self._is_at_end() or self.source[self.current] != expected:
            return False
        self.current += 1
        self.col += 1
        return True

    def _add_token(self, token_type: TokenType, lexeme: str = None):
        text = lexeme if lexeme is not None else self.source[self.start:self.current]
        self.tokens.append(Token(token_type, text, self.line, self.start - self.line_start + 1))

    def _error(self, code: str, message: str):
        col = self.start - self.line_start + 1
        self.errors.append(Diagnostic(
            code=code, message=message,
            span=(self.line, col, self.line, col),
            severity="error"
        ))

    def _scan_token(self):
        ch = self._advance()
        handlers = {
            "(": lambda: self._add_token(TokenType.LPAREN),
            ")": lambda: self._add_token(TokenType.RPAREN),
":": lambda: self._add_token(TokenType.COLON),
            "{": lambda: self._add_token(TokenType.LBRACE),
            "}": lambda: self._add_token(TokenType.RBRACE),
            "[": lambda: self._add_token(TokenType.LBRACKET),
            "]": lambda: self._add_token(TokenType.RBRACKET),
            ",": lambda: self._add_token(TokenType.COMMA),
            ".": lambda: self._add_token(TokenType.DOT),
            ";": lambda: self._add_token(TokenType.SEMICOLON),
            "+": lambda: self._add_token(TokenType.PLUS),
            "-": lambda: self._handle_minus(),
            "*": lambda: self._add_token(TokenType.STAR),
            "%": lambda: self._add_token(TokenType.PERCENT),
            "|": lambda: self._handle_pipe(),
            "^": lambda: self._add_token(TokenType.HATHAT),
            "\\": lambda: self._add_token(TokenType.BACKSLASH),
            "=": lambda: self._handle_equals(),
            "!": lambda: self._handle_bang(),
            "<": lambda: self._handle_less(),
            ">": lambda: self._handle_greater(),
            "/": lambda: self._handle_slash(),
            '"': lambda: self._string('"'),
            "'": lambda: self._string("'"),
            "\n": lambda: self._handle_newline(),
            " ": lambda: None,
            "\r": lambda: None,
            "\t": lambda: None,
        }
        handler = handlers.get(ch)
        if handler:
            handler()
        elif ch.isdigit() or (ch == "0" and self._peek() in "xXbBoO"):
            self._number(ch)
        elif ch.isalpha() or ch == "_":
            self._identifier()
        else:
            self._error("E001", f"Unrecognized character: '{ch}'")

    def _handle_newline(self):
        self.line += 1
        self.line_start = self.current

    def _handle_minus(self):
        if self._match(">"):
            self._add_token(TokenType.ARROW, "->")
        else:
            self._add_token(TokenType.MINUS)

    def _handle_pipe(self):
        if self._match("|"):
            self._add_token(TokenType.PIPEPIPE, "||")
        else:
            self._add_token(TokenType.PIPE)

    def _handle_equals(self):
        if self._match("="):
            self._add_token(TokenType.EQEQ, "==")
        else:
            self._add_token(TokenType.ASSIGN)

    def _handle_bang(self):
        if self._match("="):
            self._add_token(TokenType.NE, "!=")
        else:
            self._error("E001", "Unrecognized character: '!' (use 'not' for negation)")

    def _handle_less(self):
        if self._match("="):
            self._add_token(TokenType.LE, "<=")
        else:
            self._add_token(TokenType.LT)

    def _handle_greater(self):
        if self._match("="):
            self._add_token(TokenType.GE, ">=")
        else:
            self._add_token(TokenType.GT)

    def _handle_slash(self):
        if self._match("/"):
            # Line comment: consume until end of line
            while self._peek() != "\n" and not self._is_at_end():
                self._advance()
        elif self._match("*"):
            # Block comment: consume until */
            depth = 1
            while depth > 0 and not self._is_at_end():
                if self._peek() == "/" and self._peek_next() == "*":
                    self._advance()
                    self._advance()
                    depth += 1
                elif self._peek() == "*" and self._peek_next() == "/":
                    self._advance()
                    self._advance()
                    depth -= 1
                elif self._peek() == "\n":
                    self._advance()
                    self.line += 1
                    self.line_start = self.current
                else:
                    self._advance()
            if depth > 0:
                self._error("E003", "Unterminated block comment")
        else:
            self._add_token(TokenType.SLASH)

    def _identifier(self):
        while self._peek().isalnum() or self._peek() == "_":
            self._advance()
        text = self.source[self.start:self.current]
        token_type = KEYWORDS.get(text, TokenType.IDENTIFIER)
        self._add_token(token_type, text)

    def _number(self, first: str):
        # Detect prefix-based numbers
        if first == "0" and not self._is_at_end():
            nxt = self.source[self.current]
            if nxt in "xX":
                self._advance()
                return self._hex_number()
            elif nxt in "bB":
                self._advance()
                return self._binary_number()
            elif nxt in "oO":
                self._advance()
                return self._octal_number()

        # Regular int or float
        while self._peek().isdigit():
            self._advance()

        is_float = False
        if self._peek() == "." and self._peek_next().isdigit():
            is_float = True
            self._advance()
            while self._peek().isdigit():
                self._advance()

        if self._peek() in "eE":
            is_float = True
            self._advance()
            if self._peek() in "+-":
                self._advance()
            while self._peek().isdigit():
                self._advance()

        text = self.source[self.start:self.current]
        if is_float:
            self._add_token(TokenType.FLOAT, text)
        else:
            self._add_token(TokenType.INT, text)

    def _hex_number(self):
        while self._peek().isalnum():
            self._advance()
        text = self.source[self.start:self.current]
        self._add_token(TokenType.INT, text)

    def _binary_number(self):
        while self._peek() in "01":
            self._advance()
        text = self.source[self.start:self.current]
        self._add_token(TokenType.INT, text)

    def _octal_number(self):
        while self._peek() in "01234567":
            self._advance()
        text = self.source[self.start:self.current]
        self._add_token(TokenType.INT, text)

    def _string(self, quote: str):
        text_parts = []
        while self._peek() != quote and not self._is_at_end():
            if self._peek() == "\n":
                self.line += 1
                self.line_start = self.current + 1
            if self._peek() == "\\":
                self._advance()  # consume backslash
                esc = self._advance()
                esc_map = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "'": "'", "0": "\0"}
                text_parts.append(esc_map.get(esc, esc))
            else:
                text_parts.append(self._advance())

        if self._is_at_end():
            self._error("E002", "Unterminated string literal")
            text = "".join(text_parts)
        else:
            self._advance()  # consume closing quote
            text = "".join(text_parts)

        self._add_token(TokenType.STRING, text)

    def get_errors(self) -> list[Diagnostic]:
        return self.errors
