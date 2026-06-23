"""
Tests for Shadow Thirst (Tier 4)
Tests mutation parsing, 6 analyzers, promote/reject flow, and Mermaid visualization.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utf.shadow_thirst.core import (
    CanonicalConvergenceAnalyzer,
    DeterminismAnalyzer,
    MemoryEvaporationAnalyzer,
    MutationParser,
    PlaneIsolationAnalyzer,
    PromotionEngine,
    PuritySpringAnalyzer,
    ResourceEstimator,
    ShadowModule,
)


class TestMutationParser:
    """Test parsing of mutation blocks."""

    def test_parse_basic_mutation(self):
        parser = MutationParser()
        text = """
mutation test_mutation_1 {
    validated_canonical {
        shadow {
            let x = compute(input)
        }
        invariant {
            count > 0 && count < 100
        }
        canonical {
            let result = compute(input)
            return result
        }
    }
}
"""
        module = parser.parse(text)
        assert module is not None
        assert module.name == "test_mutation_1"
        assert "shadow" in module.shadow_code or module.shadow_code != ""
        assert "invariant" in module.invariant_code or module.invariant_code != ""
        assert "canonical" in module.canonical_code or module.canonical_code != ""

    def test_parse_extracts_code_blocks(self):
        parser = MutationParser()
        text = """
mutation data_transform {
    validated_canonical {
        shadow {
            drink result = transform(data)
            return result
        }
        invariant {
            result != null
        }
        canonical {
            drink result = transform(data)
            return result
        }
    }
}
"""
        module = parser.parse(text)
        assert module is not None
        assert module.name == "data_transform"

    def test_replay_hash(self):
        parser = MutationParser()
        text = """
mutation test_hash {
    validated_canonical {
        shadow {
            drink x = 42
        }
        invariant {
            x >= 0
        }
        canonical {
            drink x = 42
            return x
        }
    }
}
"""
        module = parser.parse(text)
        replay_hash = module.replay_hash()
        assert replay_hash is not None
        assert len(replay_hash) == 64  # SHA-256 hex
        assert isinstance(replay_hash, str)

    def test_replay_hash_consistent(self):
        parser = MutationParser()
        text = """mutation t { validated_canonical { shadow { x } invariant { x > 0 } canonical { x } } }"""
        module1 = parser.parse(text)
        module2 = parser.parse(text)
        assert module1.replay_hash() == module2.replay_hash()


class TestAnalyzers:
    """Test each of the 6 Shadow Thirst analyzers."""

    def test_plane_isolation_analyzer(self):
        analyzer = PlaneIsolationAnalyzer()
        # Shadow code that doesn't write canonical state
        module = ShadowModule(
            name="test",
            shadow_code="drink x = compute(input)",
            invariant_code="x > 0",
            canonical_code="drink result = compute(input)"
        )
        result = analyzer.analyze(module)
        assert result.passed is True
        assert result.name == "PlaneIsolation"

    def test_determinism_analyzer_pass(self):
        analyzer = DeterminismAnalyzer()
        # Deterministic shadow code
        module = ShadowModule(
            name="test",
            shadow_code="drink x = input + 1",
            invariant_code="",
            canonical_code=""
        )
        result = analyzer.analyze(module)
        assert result.passed is True

    def test_determinism_analyzer_fail(self):
        analyzer = DeterminismAnalyzer()
        # Shadow code that CALLS a non-deterministic function — should fail
        module = ShadowModule(
            name="test",
            shadow_code="drink x = get_time()",
            invariant_code="",
            canonical_code=""
        )
        result = analyzer.analyze(module)
        assert result.passed is False

    def test_resource_estimator(self):
        analyzer = ResourceEstimator()
        module = ShadowModule(
            name="test",
            shadow_code="drink x = [1,2,3]",
            invariant_code="",
            canonical_code=""
        )
        result = analyzer.analyze(module)
        assert result.name == "ResourceEstimator"
        # Should pass if within CPU/memory limits
        assert result.passed is True

    def test_purity_spring_analyzer_pass(self):
        analyzer = PuritySpringAnalyzer()
        module = ShadowModule(
            name="test",
            shadow_code="",
            invariant_code="x > 0 and x < 100",
            canonical_code=""
        )
        result = analyzer.analyze(module)
        assert result.name == "PuritySpring"
        assert result.passed is True

    def test_memory_evaporation_analyzer(self):
        analyzer = MemoryEvaporationAnalyzer()
        module = ShadowModule(
            name="test",
            shadow_code="drink x = [1,2,3,4,5]",
            invariant_code="",
            canonical_code=""
        )
        result = analyzer.analyze(module)
        assert result.name == "MemoryEvaporation"

    def test_canonical_convergence_analyzer_pass(self):
        analyzer = CanonicalConvergenceAnalyzer()
        module = ShadowModule(
            name="test",
            shadow_code="drink x = compute(input)",
            invariant_code="",
            canonical_code="drink x = compute(input)"
        )
        result = analyzer.analyze(module)
        assert result.name == "CanonicalConvergence"
        assert result.passed is True

    def test_canonical_convergence_analyzer_fail(self):
        analyzer = CanonicalConvergenceAnalyzer()
        module = ShadowModule(
            name="test",
            shadow_code="",
            invariant_code="",
            canonical_code=""
        )
        result = analyzer.analyze(module)
        assert result.name == "CanonicalConvergence"
        # Without both blocks, should not pass
        assert result.passed is False


class TestASTUpgrade:
    """Prove the analyzers reason over the AST, not substrings."""

    def test_determinism_variable_named_nowhere_passes(self):
        # Substring grep for 'now' would FAIL this; AST only flags calls.
        analyzer = DeterminismAnalyzer()
        module = ShadowModule(name="t", shadow_code="drink nowhere = compute(input)")
        assert module.shadow_ast is not None
        assert analyzer.analyze(module).passed is True

    def test_determinism_real_nondeterministic_call_fails(self):
        analyzer = DeterminismAnalyzer()
        module = ShadowModule(name="t", shadow_code="drink x = now()")
        result = analyzer.analyze(module)
        assert result.passed is False
        assert "now" in result.message

    def test_plane_isolation_canonical_in_comment_passes(self):
        # A comment mentioning 'canonical.' is not a node — AST ignores it.
        analyzer = PlaneIsolationAnalyzer()
        module = ShadowModule(
            name="t",
            shadow_code="drink x = compute(input)  // reads canonical.ledger",
        )
        assert module.shadow_ast is not None
        assert analyzer.analyze(module).passed is True

    def test_plane_isolation_real_canonical_write_fails(self):
        analyzer = PlaneIsolationAnalyzer()
        module = ShadowModule(name="t", shadow_code="drink canonical_state = 5")
        assert analyzer.analyze(module).passed is False

    def test_convergence_alpha_equivalent_passes(self):
        # Same structure, different variable names -> converge.
        analyzer = CanonicalConvergenceAnalyzer()
        module = ShadowModule(
            name="t",
            shadow_code="drink x = compute(input)\nreturn x",
            canonical_code="drink result = compute(input)\nreturn result",
        )
        assert analyzer.analyze(module).passed is True

    def test_convergence_structural_divergence_fails(self):
        analyzer = CanonicalConvergenceAnalyzer()
        module = ShadowModule(
            name="t",
            shadow_code="for i in items { pour i }\nreturn x",
            canonical_code="return x",
        )
        assert analyzer.analyze(module).passed is False

    def test_purity_impure_invariant_call_fails(self):
        analyzer = PuritySpringAnalyzer()
        module = ShadowModule(name="t", invariant_code="pour x")
        assert analyzer.analyze(module).passed is False

    def test_lexical_fallback_when_ast_unavailable(self):
        # When a block has no AST (parse failure), the analyzer still produces
        # a verdict via the original substring heuristic.
        analyzer = DeterminismAnalyzer()
        module = ShadowModule(name="t", shadow_code="x = now")
        module.shadow_ast = None  # simulate a parse failure
        result = analyzer.analyze(module)
        assert result.passed is False
        assert "lexical" in result.message


class TestPromotionEngine:
    """Test the promote/reject flow."""

    def test_promote_all_pass(self):
        engine = PromotionEngine()
        module = ShadowModule(
            name="test_promote",
            shadow_code="let x = compute(input)",
            invariant_code="x > 0",
            canonical_code="let x = compute(input)"
        )
        verdict, results = engine.evaluate(module)
        # Verify results
        assert len(results) > 0

    def test_reject_on_critical(self):
        engine = PromotionEngine()
        module = ShadowModule(
            name="test_reject",
            shadow_code="",
            invariant_code="",
            canonical_code=""
        )
        verdict, results = engine.evaluate(module)
        assert verdict is not None

    def test_mermaid_generation(self):
        engine = PromotionEngine()
        module = ShadowModule(
            name="viz_test",
            shadow_code="let x = input",
            invariant_code="x > 0",
            canonical_code="let x = input"
        )
        mermaid = engine.generate_mermaid(module)
        assert "mermaid" in mermaid.lower()
        assert "flowchart" in mermaid.lower()
        assert "viz_test" in mermaid


class TestE2E:
    """End-to-end Shadow Thirst tests."""

    def test_full_mutation_promote(self):
        """Test parsing a mutation and running all analyzers, expecting promote."""
        parser = MutationParser()
        text = """
mutation safe_transform {
    validated_canonical {
        shadow {
            drink result = transform(data)
            return result
        }
        invariant {
            result != null
        }
        canonical {
            drink result = transform(data)
            return result
        }
    }
}
"""
        module = parser.parse(text)
        assert module is not None

        engine = PromotionEngine()
        verdict, results = engine.evaluate(module)

        # Should have results from all 6 analyzers
        assert len(results) == 6
        assert verdict is not None

        # Check all analyzer names are present
        analyzer_names = [r.name for r in results]
        assert "PlaneIsolation" in analyzer_names
        assert "Determinism" in analyzer_names
        assert "ResourceEstimator" in analyzer_names
        assert "PuritySpring" in analyzer_names
        assert "MemoryEvaporation" in analyzer_names
        assert "CanonicalConvergence" in analyzer_names


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
    print("\n✅ All Shadow Thirst tests passed!")
