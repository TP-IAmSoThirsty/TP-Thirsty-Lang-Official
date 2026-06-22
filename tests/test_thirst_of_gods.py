"""
Tests for Thirst of Gods — structural deity-contract detection.

These prove the detector reasons over real AST constructs (CascadeCall,
SpillageStmt-with-handlers, CleanupStmt, ClassDecl-with-init) wherever they
occur, and is no longer fooled by functions merely *named* cascade/spillage/
cleanup/fountain.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirst_of_gods.core import to_gods, validate_deity_contract


def _ast(src):
    parser = Parser(Lexer(src).lex())
    program = parser.parse()
    assert not parser.errors, [str(e) for e in parser.errors]
    return program


# A program that satisfies every deity contract using real constructs, while
# nothing is *named* cascade / spillage / cleanup / fountain. The cascade lives
# *inside* the spillage body, so its awaited error has a real consumer.
COMPLIANT = """module m: core
fountain Reservoir {
    glass init(self) { return self }
}
glass worker(items) {
    spillage {
        drink r = cascade fetch(items)
        return r
    } error {
        return none
    }
    cleanup {
        return none
    } finally {
        return none
    }
}
"""

# Functions whose names *evoke* the magic words but contain no real governance
# constructs. (The bare words cascade/spillage/cleanup are reserved keywords and
# cannot even be used as identifiers — which is exactly why the old name-based
# detector could never match a parseable program.)
NAME_DECOYS = """module m: core
glass do_cascade(x) { return x }
glass handle_spillage(x) { return x }
glass run_cleanup(x) { return x }
fountain Vessel {
    glass size(self) { return 0 }
}
"""


class TestStructuralDetection:
    def test_real_constructs_pass_without_magic_names(self):
        contract = to_gods(_ast(COMPLIANT))
        assert contract.has_fountain_init
        assert contract.has_cascade_handler
        assert contract.has_spillage_handler
        assert contract.has_cleanup
        assert contract.passed
        assert contract.violations == []

    def test_name_only_decoys_now_report_violations(self):
        contract = to_gods(_ast(NAME_DECOYS))
        assert not contract.passed
        # None of the four signals should be satisfied by mere names.
        assert not contract.has_cascade_handler
        assert not contract.has_spillage_handler
        assert not contract.has_cleanup
        assert len(contract.violations) == 4

    def test_fountain_init_satisfies_g001(self):
        src = """module m: core
fountain Vessel {
    glass init(self) { return self }
}
"""
        contract = to_gods(_ast(src))
        assert contract.has_fountain_init

    def test_fountain_without_init_fails_g001(self):
        src = """module m: core
fountain Vessel {
    glass size(self) { return 0 }
}
"""
        contract = to_gods(_ast(src))
        assert not contract.has_fountain_init

    def test_cascade_inside_nested_spillage_is_guarded(self):
        # A cascade buried inside a nested spillage body is still linked to its
        # handler — containment is found at any depth.
        src = """module m: core
glass deep(items) {
    thirsty (items) {
        spillage {
            drink r = cascade fetch(items)
        } error {
            return none
        }
    }
}
"""
        contract = to_gods(_ast(src))
        assert contract.has_cascade_handler

    def test_cascade_outside_spillage_is_unguarded(self):
        # Co-presence is not enough: a cascade with a spillage elsewhere in the
        # program (not wrapping it) has no real consumer for its awaited error.
        src = """module m: core
glass worker(items) {
    drink r = cascade fetch(items)
    spillage {
        return r
    } error {
        return none
    }
}
"""
        contract = to_gods(_ast(src))
        assert not contract.has_cascade_handler
        assert any("cascade" in v.lower() for v in contract.violations)

    def test_spillage_without_handlers_does_not_count(self):
        src = """module m: core
glass bare(x) {
    spillage {
        return x
    }
}
"""
        contract = to_gods(_ast(src))
        assert not contract.has_spillage_handler


class TestDiagnostics:
    def test_validate_returns_codes_for_decoys(self):
        diags = validate_deity_contract(_ast(NAME_DECOYS))
        codes = {d.code for d in diags}
        assert {"G001", "G002", "G003", "G004"} <= codes

    def test_validate_clean_for_compliant(self):
        diags = validate_deity_contract(_ast(COMPLIANT))
        assert diags == []
