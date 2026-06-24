"""Full coverage of the type system: construction, unify, assignability,
stringification, and type_from_name parsing."""
from utf.thirsty_lang.typesys import (
    AnyType,
    BoolType,
    EnumType,
    ErrorType,
    FloatType,
    FunctionType,
    GenericType,
    GovernedType,
    InterfaceType,
    IntType,
    QuenchedType,
    ReservoirType,
    ResultType,
    StringType,
    StructType,
    TaskType,
    TypeVariable,
    VoidType,
    is_assignable,
    type_from_name,
    type_to_string,
    unify,
)


def test_str_dunder():
    assert str(IntType()) == "Int"


def test_generic_inner_properties():
    assert isinstance(QuenchedType(IntType()).inner_type, IntType)
    assert isinstance(ReservoirType(IntType()).inner_type, IntType)
    r = ResultType(IntType(), ErrorType())
    assert isinstance(r.ok_type, IntType)
    assert isinstance(r.err_type, ErrorType)
    # empty type_args fall back to AnyType
    empty = GenericType(base_type="Quenched", type_args=[])
    q = QuenchedType.__new__(QuenchedType)
    GenericType.__init__(q, base_type="Quenched", type_args=[])
    assert isinstance(q.inner_type, AnyType)
    assert isinstance(empty, GenericType)


def test_type_from_name_simple():
    assert isinstance(type_from_name("Int"), IntType)
    assert isinstance(type_from_name("  Float "), FloatType)
    assert isinstance(type_from_name("Unknown"), AnyType)


def test_type_from_name_generics():
    assert isinstance(type_from_name("Quenched[Int]"), QuenchedType)
    assert isinstance(type_from_name("Reservoir[String]"), ReservoirType)
    assert isinstance(type_from_name("Task[Int]"), TaskType)
    assert isinstance(type_from_name("Result[Int, Error]"), ResultType)
    assert isinstance(type_from_name("Governed[Int]"), GovernedType)
    custom = type_from_name("MyBox[Int]")
    assert isinstance(custom, GenericType) and custom.base_type == "MyBox"


def test_type_from_name_nested_and_empty():
    nested = type_from_name("Reservoir[Quenched[Int]]")
    assert isinstance(nested.inner_type, QuenchedType)
    # empty arg lists hit the AnyType fallbacks
    assert isinstance(type_from_name("Quenched[]").inner_type, AnyType)
    assert isinstance(type_from_name("Reservoir[]"), ReservoirType)
    assert isinstance(type_from_name("Task[]"), TaskType)
    assert isinstance(type_from_name("Result[]"), ResultType)
    assert isinstance(type_from_name("Governed[]"), GovernedType)


def test_unify():
    assert isinstance(unify(AnyType(), IntType()), AnyType)
    assert isinstance(unify(IntType(), IntType()), IntType)
    assert isinstance(unify(IntType(), FloatType()), FloatType)
    assert isinstance(unify(FloatType(), IntType()), FloatType)
    assert isinstance(unify(IntType(), StringType()), AnyType)
    # generics
    q = unify(QuenchedType(IntType()), QuenchedType(IntType()))
    assert isinstance(q, QuenchedType)
    r = unify(ReservoirType(IntType()), ReservoirType(IntType()))
    assert isinstance(r, ReservoirType)
    f1 = FunctionType([IntType()], IntType())
    f2 = FunctionType([IntType()], IntType())
    assert isinstance(unify(f1, f2), FunctionType)
    # function arity mismatch falls through to t1
    f3 = FunctionType([IntType(), IntType()], IntType())
    assert isinstance(unify(f1, f3), FunctionType)
    # same non-generic class returns t1
    assert isinstance(unify(BoolType(), BoolType()), BoolType)


def test_is_assignable():
    assert is_assignable(IntType(), AnyType()) is True
    assert is_assignable(AnyType(), IntType()) is True
    assert is_assignable(IntType(), IntType()) is True
    assert is_assignable(IntType(), FloatType()) is True
    assert is_assignable(StringType(), IntType()) is False
    assert is_assignable(QuenchedType(IntType()), QuenchedType(IntType())) is True
    assert is_assignable(ReservoirType(IntType()),
                         ReservoirType(StringType())) is False
    f1 = FunctionType([IntType()], IntType())
    f2 = FunctionType([IntType()], IntType())
    assert is_assignable(f1, f2) is True
    assert is_assignable(FunctionType([IntType(), IntType()], IntType()), f2) is False
    assert is_assignable(FunctionType([StringType()], IntType()), f2) is False
    assert is_assignable(FunctionType([IntType()], StringType()), f2) is False
    # Same type constructor → assignable regardless of name.
    assert is_assignable(EnumType("E"), EnumType("E")) is True
    assert is_assignable(StructType("S"), StructType("S")) is True
    assert is_assignable(BoolType(), BoolType()) is True
    # Different constructors → not assignable (hits the final return False).
    assert is_assignable(BoolType(), IntType()) is False


def test_type_to_string_all():
    cases = [
        (IntType(), "Int"), (FloatType(), "Float"), (BoolType(), "Bool"),
        (StringType(), "String"), (VoidType(), "Void"), (AnyType(), "Any"),
        (ErrorType(), "Error"),
        (QuenchedType(IntType()), "Quenched[Int]"),
        (ReservoirType(IntType()), "Reservoir[Int]"),
        (TaskType(IntType()), "Task[Int]"),
        (ResultType(IntType(), ErrorType()), "Result[Int, Error]"),
        (GovernedType(IntType()), "Governed[Int]"),
        (EnumType("E"), "E"), (StructType("S"), "S"), (InterfaceType("I"), "I"),
        (TypeVariable("T"), "T"),
        (FunctionType([IntType()], BoolType()), "(Int) -> Bool"),
        (GenericType("Box", [IntType()]), "Box[Int]"),
    ]
    for t, expected in cases:
        assert type_to_string(t) == expected
    # A non-Type object hits the str() fallback without recursing.
    assert isinstance(type_to_string(object()), str)


def test_type_to_string_empty_generic_args():
    # A bare GenericType named "Task" is NOT a TaskType, so it hits the
    # generic branch with empty args.
    assert type_to_string(GenericType("Task", [])) == "Task[]"
    # An actual TaskType with no type_args reports Task[Any].
    task = TaskType.__new__(TaskType)
    GenericType.__init__(task, base_type="Task", type_args=[])
    assert type_to_string(task) == "Task[Any]"
    gov = GovernedType.__new__(GovernedType)
    GenericType.__init__(gov, base_type="Governed", type_args=[])
    assert type_to_string(gov) == "Governed[Any]"
