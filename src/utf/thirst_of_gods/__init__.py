"""Thirst of Gods — Tier 2 governance enforcement."""
from .core import (
    DeityContract,
    ThirstOfGodsError,
    interpret_gods,
    to_gods,
    validate_deity_contract,
)

__all__ = ["to_gods", "interpret_gods", "validate_deity_contract", "ThirstOfGodsError", "DeityContract"]
