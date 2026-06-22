from dataclasses import dataclass
from enum import Enum, auto


class TokenType(Enum):
    # --- Core Keywords ---
    DRINK = auto()
    POUR = auto()
    SIP = auto()
    THIRSTY = auto()
    HYDRATED = auto()
    THIRST = auto()
    QUENCH = auto()
    REFILL = auto()
    TIMES = auto()
    GLASS = auto()
    RESERVOIR = auto()
    WELL = auto()
    OF = auto()
    FLOOD = auto()
    DRIP = auto()
    EVAPORATE = auto()
    CONDENSE = auto()
    FOUNTAIN = auto()
    RETURN = auto()
    PARCHED = auto()
    QUENCHED = auto()
    EMPTY = auto()
    MUT = auto()
    IN = auto()
    
    # --- Module Keywords ---
    IMPORT = auto()
    FROM = auto()
    AS = auto()

    # --- Security Keywords ---
    # ── Reserved Security Tokens (Tier 5/6 — TSCG / TSCG-B) ──
    # These keywords are syntactically parsed but not semantically
    # enforced in Thirsty-Lang core (Tier 1). They are reserved for
    # use by Shadow Thirst / TSCG governance transformers at higher
    # tiers. See tarl/spec.py for T.A.R.L. policy definitions and
    # docs/governance_model.md for the tier escalation model.
    SHIELD = auto()      # identity/access context barrier
    SANITIZE = auto()    # data scrubbing annotation
    ARMOR = auto()       # runtime safety wrap
    MORPH = auto()       # type coercion boundary
    DETECT = auto()      # anomaly tap point
    DEFEND = auto()      # invariant enforcement hook

    # --- Thirst of Gods Keywords ---
    CASCADE = auto()
    THIS = auto()
    NEW = auto()
    PUBLIC = auto()
    PRIVATE = auto()
    AWAIT = auto()
    SPILLAGE = auto()
    CLEANUP = auto()
    FINALLY = auto()
    ERROR = auto()
    THROW = auto()

    # --- Policy Keywords ---
    POLICY = auto()
    WHEN = auto()
    ALLOW = auto()
    DENY = auto()
    ESCALATE = auto()

    # --- Declaration Keywords ---
    ENUM = auto()
    STRUCT = auto()
    INTERFACE = auto()
    SYMBOL = auto()

    # --- Shadow Thirst Keywords ---
    MUTATION = auto()
    VALIDATED_CANONICAL = auto()
    INVARIANT = auto()
    SHADOW = auto()
    CANONICAL = auto()
    PROMOTE = auto()
    REJECT = auto()
    GOVERNED = auto()
    REQUIRES = auto()
    ENSURES = auto()
    CORE = auto()
    MODULE = auto()
    
    # --- Literals ---
    INT = auto()
    FLOAT = auto()
    STRING = auto()
    BOOL_TRUE = auto()
    BOOL_FALSE = auto()
    NONE = auto()
    ERROR_LITERAL = auto()

    # --- Delimiters ---
    LPAREN = auto()
    RPAREN = auto()
    LBRACE = auto()
    RBRACE = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    COMMA = auto()
    DOT = auto()
    COLON = auto()
    SEMICOLON = auto()
    EQ = auto()

    # --- Multi-char Operators ---
    ARROW = auto()      # ->
    PIPE = auto()        # |
    BACKSLASH = auto()   # \ (lambda)
    HATHAT = auto()      # ^ (AND-combine)
    PIPEPIPE = auto()    # || (OR-combine)

    # --- Single-char Operators ---
    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    PERCENT = auto()
    EQEQ = auto()
    NE = auto()
    LT = auto()
    GT = auto()
    LE = auto()
    GE = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    ASSIGN = auto()

    # --- Others ---
    IDENTIFIER = auto()
    EOF = auto()


KEYWORDS = {
    "drink": TokenType.DRINK,
    "pour": TokenType.POUR,
    "sip": TokenType.SIP,
    "thirsty": TokenType.THIRSTY,
    "hydrated": TokenType.HYDRATED,
    "thirst": TokenType.THIRST,
    "quench": TokenType.QUENCH,
    "refill": TokenType.REFILL,
    "times": TokenType.TIMES,
    "glass": TokenType.GLASS,
    "reservoir": TokenType.RESERVOIR,
    "well": TokenType.WELL,
    "of": TokenType.OF,
    "flood": TokenType.FLOOD,
    "drip": TokenType.DRIP,
    "evaporate": TokenType.EVAPORATE,
    "condense": TokenType.CONDENSE,
    "fountain": TokenType.FOUNTAIN,
    "return": TokenType.RETURN,
    "parched": TokenType.PARCHED,
    "quenched": TokenType.QUENCHED,
    "empty": TokenType.EMPTY,
    "mut": TokenType.MUT,
    "in": TokenType.IN,
    "import": TokenType.IMPORT,
    "from": TokenType.FROM,
    "as": TokenType.AS,
    "shield": TokenType.SHIELD,
    "sanitize": TokenType.SANITIZE,
    "armor": TokenType.ARMOR,
    "morph": TokenType.MORPH,
    "detect": TokenType.DETECT,
    "defend": TokenType.DEFEND,
    "cascade": TokenType.CASCADE,
    "this": TokenType.THIS,
    "new": TokenType.NEW,
    "public": TokenType.PUBLIC,
    "private": TokenType.PRIVATE,
    "await": TokenType.AWAIT,
    "spillage": TokenType.SPILLAGE,
    "cleanup": TokenType.CLEANUP,
    "finally": TokenType.FINALLY,
    "error": TokenType.ERROR,
    "throw": TokenType.THROW,
    "policy": TokenType.POLICY,
    "when": TokenType.WHEN,
    "allow": TokenType.ALLOW,
    "deny": TokenType.DENY,
    "escalate": TokenType.ESCALATE,
    "mutation": TokenType.MUTATION,
    "validated_canonical": TokenType.VALIDATED_CANONICAL,
    "invariant": TokenType.INVARIANT,
    "shadow": TokenType.SHADOW,
    "canonical": TokenType.CANONICAL,
    "promote": TokenType.PROMOTE,
    "reject": TokenType.REJECT,
    "governed": TokenType.GOVERNED,
    "requires": TokenType.REQUIRES,
    "ensures": TokenType.ENSURES,
    "enum": TokenType.ENUM,
    "struct": TokenType.STRUCT,
    "interface": TokenType.INTERFACE,
    "symbol": TokenType.SYMBOL,
    "module": TokenType.MODULE,
    "core": TokenType.CORE,
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "true": TokenType.BOOL_TRUE,
    "false": TokenType.BOOL_FALSE,
    "none": TokenType.NONE,
}


@dataclass
class Token:
    type: TokenType
    lexeme: str
    line: int = 1
    col: int = 1

    def __repr__(self):
        return f"Token({self.type.name}, '{self.lexeme}', L{self.line}:{self.col})"