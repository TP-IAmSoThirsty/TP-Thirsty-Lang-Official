"""Thirsty-Lang — a governance-first programming language family.

Install: ``pip install thirsty-lang``

Canonical import path: ``from utf import thirsty_lang``
This shim exists so ``import thirsty_lang`` also works.

Exposes the same names as ``utf.thirsty_lang``.
"""
import sys as _sys

from utf import thirsty_lang as _mod

# Replace this shim package in sys.modules with the real canonical module
# so that ``import thirsty_lang`` gives you the same object as
# ``from utf import thirsty_lang``.
_sys.modules["thirsty_lang"] = _mod
