"""
Thirsty-Lang Type System
Base types, generic types, unification, and assignability checking.
"""
from dataclasses import dataclass, field


class Type:
    """Base class for all types."""
    def __str__(self):
        return type_to_string(self)


@dataclass
class IntType(Type):
    pass


@dataclass
class FloatType(Type):
    pass


@dataclass
class BoolType(Type):
    pass


@dataclass
class StringType(Type):
    pass


@dataclass
class VoidType(Type):
    pass


@dataclass
class AnyType(Type):
    pass


@dataclass
class ErrorType(Type):
    message: str = ""


# === Generic Types ===

@dataclass
class GenericType(Type):
    base_type: str  # "Quenched", "Reservoir", "Task", "Governed"
    type_args: list[Type] = field(default_factory=list)


class QuenchedType(GenericType):
    def __init__(self, type_arg: Type):
        super().__init__(base_type="Quenched", type_args=[type_arg])

    @property
    def inner_type(self) -> Type:
        return self.type_args[0] if self.type_args else AnyType()


class ReservoirType(GenericType):
    def __init__(self, type_arg: Type):
        super().__init__(base_type="Reservoir", type_args=[type_arg])

    @property
    def inner_type(self) -> Type:
        return self.type_args[0] if self.type_args else AnyType()


class TaskType(GenericType):
    def __init__(self, type_arg: Type):
        super().__init__(base_type="Task", type_args=[type_arg])


class ResultType(GenericType):
    def __init__(self, ok_type: Type, err_type: Type):
        super().__init__(base_type="Result", type_args=[ok_type, err_type])

    @property
    def ok_type(self) -> Type:
        return self.type_args[0] if len(self.type_args) > 0 else AnyType()

    @property
    def err_type(self) -> Type:
        return self.type_args[1] if len(self.type_args) > 1 else AnyType()


class GovernedType(GenericType):
    def __init__(self, type_arg: Type):
        super().__init__(base_type="Governed", type_args=[type_arg])


# === Named Types ===

@dataclass
class EnumType(Type):
    name: str
    variants: list[str] = field(default_factory=list)


@dataclass
class StructType(Type):
    name: str
    field_types: dict[str, Type] = field(default_factory=dict)


@dataclass
class InterfaceType(Type):
    name: str
    method_sigs: dict[str, list[Type]] = field(default_factory=dict)  # name -> [param_types]


# === Type Variables ===

@dataclass
class TypeVariable(Type):
    name: str  # e.g., "T", "E"


# === Function Types ===

@dataclass
class FunctionType(Type):
    param_types: list[Type] = field(default_factory=list)
    return_type: Type = field(default_factory=VoidType)


# === Type String Map ===

TYPE_NAME_MAP: "dict[str, type[Type]]" = {
    "Int": IntType,
    "Float": FloatType,
    "Bool": BoolType,
    "String": StringType,
    "Void": VoidType,
    "Any": AnyType,
    "Error": ErrorType,
}


def type_from_name(name: str) -> Type:
    """Convert a type name string to a Type object. Handles generic syntax like Quenched[Int]."""
    name = name.strip()

    # Check for generic type pattern: BaseType[Args]
    if "[" in name and name.endswith("]"):
        base = name[:name.index("[")].strip()
        inner = name[name.index("[") + 1:-1].strip()
        inner_types = []
        # Split by comma, respecting nesting
        depth = 0
        current = ""
        for ch in inner:
            if ch == "[":
                depth += 1
                current += ch
            elif ch == "]":
                depth -= 1
                current += ch
            elif ch == "," and depth == 0:
                inner_types.append(type_from_name(current.strip()))
                current = ""
            else:
                current += ch
        if current.strip():
            inner_types.append(type_from_name(current.strip()))

        base_lower = base.lower()
        if base_lower == "quenched":
            return QuenchedType(inner_types[0] if inner_types else AnyType())
        elif base_lower == "reservoir":
            return ReservoirType(inner_types[0] if inner_types else AnyType())
        elif base_lower == "task":
            return TaskType(inner_types[0] if inner_types else AnyType())
        elif base_lower == "result":
            return ResultType(inner_types[0] if inner_types else AnyType(),
                              inner_types[1] if len(inner_types) > 1 else AnyType())
        elif base_lower == "governed":
            return GovernedType(inner_types[0] if inner_types else AnyType())
        else:
            # Unknown generic — treat base as custom type
            return GenericType(base_type=base, type_args=inner_types)

    # Simple type lookup
    cls = TYPE_NAME_MAP.get(name)
    if cls:
        return cls()

    # Try as a named type (enum, struct, interface)
    return AnyType()  # Fallback


# === Type Unification & Assignability ===

WIDENING_RULES: dict[type, list[type]] = {
    IntType: [FloatType],
    FloatType: [],
    BoolType: [],
    StringType: [],
}


def unify(t1: Type, t2: Type) -> Type:
    """Find the most specific common supertype of t1 and t2."""
    if isinstance(t1, AnyType) or isinstance(t2, AnyType):
        return AnyType()
    if type(t1) is type(t2):
        # Same base type — check generics
        if isinstance(t1, QuenchedType) and isinstance(t2, QuenchedType):
            inner = unify(t1.inner_type, t2.inner_type)
            return QuenchedType(inner)
        if isinstance(t1, ReservoirType) and isinstance(t2, ReservoirType):
            inner = unify(t1.inner_type, t2.inner_type)
            return ReservoirType(inner)
        if isinstance(t1, FunctionType) and isinstance(t2, FunctionType):
            if len(t1.param_types) == len(t2.param_types):
                params = [unify(p1, p2) for p1, p2 in zip(t1.param_types, t2.param_types, strict=False)]
                ret = unify(t1.return_type, t2.return_type)
                return FunctionType(params, ret)
        return t1
    # Widening
    if isinstance(t1, IntType) and isinstance(t2, FloatType):
        return FloatType()
    if isinstance(t1, FloatType) and isinstance(t2, IntType):
        return FloatType()
    # Fall through to Any
    return AnyType()


def is_assignable(source: Type, target: Type) -> bool:
    """Check if a value of source type can be assigned to a target type variable."""
    if isinstance(target, AnyType):
        return True
    if isinstance(source, AnyType):
        return True
    if type(source) is type(target):
        if isinstance(source, QuenchedType) and isinstance(target, QuenchedType):
            return is_assignable(source.inner_type, target.inner_type)
        if isinstance(source, ReservoirType) and isinstance(target, ReservoirType):
            return is_assignable(source.inner_type, target.inner_type)
        if isinstance(source, FunctionType) and isinstance(target, FunctionType):
            if len(source.param_types) != len(target.param_types):
                return False
            for sp, tp in zip(source.param_types, target.param_types, strict=False):
                if not is_assignable(sp, tp):
                    return False
            return is_assignable(source.return_type, target.return_type)
        return True  # same type
    # Int -> Float widening
    if isinstance(source, IntType) and isinstance(target, FloatType):
        return True
    # Different type constructors are not assignable. (Same-named enums/structs
    # are already accepted above by the same-class check.)
    return False


def type_to_string(t: Type) -> str:
    """Convert a Type object to its string representation."""
    if isinstance(t, IntType):
        return "Int"
    elif isinstance(t, FloatType):
        return "Float"
    elif isinstance(t, BoolType):
        return "Bool"
    elif isinstance(t, StringType):
        return "String"
    elif isinstance(t, VoidType):
        return "Void"
    elif isinstance(t, AnyType):
        return "Any"
    elif isinstance(t, ErrorType):
        return "Error"
    elif isinstance(t, QuenchedType):
        return f"Quenched[{type_to_string(t.inner_type)}]"
    elif isinstance(t, ReservoirType):
        return f"Reservoir[{type_to_string(t.inner_type)}]"
    elif isinstance(t, TaskType):
        inner = type_to_string(t.type_args[0]) if t.type_args else "Any"
        return f"Task[{inner}]"
    elif isinstance(t, ResultType):
        ok = type_to_string(t.ok_type)
        err = type_to_string(t.err_type)
        return f"Result[{ok}, {err}]"
    elif isinstance(t, GovernedType):
        inner = type_to_string(t.type_args[0]) if t.type_args else "Any"
        return f"Governed[{inner}]"
    elif isinstance(t, EnumType):
        return t.name
    elif isinstance(t, StructType):
        return t.name
    elif isinstance(t, InterfaceType):
        return t.name
    elif isinstance(t, TypeVariable):
        return t.name
    elif isinstance(t, FunctionType):
        params = ", ".join(type_to_string(p) for p in t.param_types)
        ret = type_to_string(t.return_type)
        return f"({params}) -> {ret}"
    elif isinstance(t, GenericType):
        args = ", ".join(type_to_string(a) for a in t.type_args)
        return f"{t.base_type}[{args}]"
    else:
        return str(t)
