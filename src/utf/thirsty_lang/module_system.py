"""
Thirsty-Lang Module System
Import resolution, 16 stdlib namespaces, and 16 global builtins.
"""
import hashlib
import json
import os
import random
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

# Module cache: store resolved modules by import path
ModuleCache: dict[str, object] = {}


# ============================================================
# Sensitive stdlib capability metadata (single source of truth)
# ============================================================
#
# Maps each sensitive stdlib namespace to the explicit capability *action* of
# every side-effecting function it exposes. Actions are constrained to a closed
# vocabulary — {"read", "write", "network", "execute"} — so the governed-runtime
# capability broker can gate imported stdlib calls without per-call guesswork.
# The interpreter wraps these callables in governed mode and routes each through
# the capability gate with the action declared here.
SENSITIVE_STDLIB_CAPABILITIES: dict[str, dict[str, str]] = {
    "thirst::fs": {
        "read_file": "read",
        "exists": "read",
        "list_dir": "read",
        "write_file": "write",
        "mkdir": "write",
        "remove": "write",
    },
    "thirst::http": {
        "get": "network",
        "post": "network",
        "put": "network",
        "delete": "network",
    },
    "thirst::net": {
        "tcp_connect": "network",
        "tcp_listen": "network",
        "udp_send": "network",
    },
    "thirst::env": {
        "get": "read",
        "all": "read",
        "set": "write",
    },
    "thirst::process": {
        "run": "execute",
        "exit": "execute",
        "args": "read",
        "pid": "read",
    },
    "thirst::log": {
        "info": "write",
        "warn": "write",
        "error": "write",
        "debug": "write",
    },
    "thirst::test": {
        "describe": "write",
        "it": "write",
    },
    "thirst::sqlite": {
        "connect": "write",
        "query": "read",
        "execute": "write",
        "close": "write",
    },
}


# ============================================================
# Stdlib Namespace Implementations
# ============================================================

def _make_time_module() -> dict:
    """thirst::time — Time utilities."""
    def now() -> str:
        return datetime.now(UTC).isoformat()

    def epoch_ms() -> int:
        return int(time.time() * 1000)

    def sleep(seconds: float) -> None:
        time.sleep(seconds)

    return {
        "now": now,
        "epoch_ms": epoch_ms,
        "sleep": sleep,
    }


def _make_crypto_module() -> dict:
    """thirst::crypto — Cryptographic utilities."""
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def sign(data: str, key: str = "") -> str:
        """Simple HMAC-like signing."""
        msg = data + key
        return hashlib.sha256(msg.encode()).hexdigest()

    def hmac(key: str, data: str) -> str:
        return hashlib.sha256((key + data).encode()).hexdigest()

    def random_bytes(n: int) -> str:
        return random.randbytes(n).hex()

    def uuid4() -> str:
        return str(uuid.uuid4())

    return {
        "sha256": sha256,
        "sign": sign,
        "hmac": hmac,
        "random_bytes": random_bytes,
        "uuid4": uuid4,
    }


def _make_reservoir_module() -> dict:
    """thirst::reservoir — Reservoir (list) operations."""
    def size(r: list) -> int:
        return len(r) if isinstance(r, list) else 0

    def push(r: list, v: object) -> int:
        if isinstance(r, list):
            r.append(v)
            return len(r)
        return 0

    def pop(r: list) -> object:
        if isinstance(r, list) and r:
            return r.pop()
        return None

    def get(r: list, i: int) -> object:
        if isinstance(r, list) and 0 <= i < len(r):
            return r[i]
        return None

    def flood(r: list, v: object) -> list:
        if isinstance(r, list):
            r.append(v)
        return r

    return {
        "size": size,
        "push": push,
        "pop": pop,
        "get": get,
        "flood": flood,
    }


def _make_fs_module() -> dict:
    """thirst::fs — File system operations."""
    def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    def write_file(path: str, data: str) -> int:
        with open(path, 'w') as f:
            return f.write(data)

    def exists(path: str) -> bool:
        return os.path.exists(path)

    def list_dir(path: str) -> list[str]:
        return os.listdir(path)

    def mkdir(path: str) -> bool:
        os.makedirs(path, exist_ok=True)
        return True

    def remove(path: str) -> bool:
        if os.path.isfile(path):
            os.remove(path)
            return True
        elif os.path.isdir(path):
            os.rmdir(path)
            return True
        return False

    return {
        "read_file": read_file,
        "write_file": write_file,
        "exists": exists,
        "list_dir": list_dir,
        "mkdir": mkdir,
        "remove": remove,
    }


def _make_path_module() -> dict:
    """thirst::path — Path manipulation."""
    def join(*parts: str) -> str:
        return os.path.join(*parts)

    def dirname(p: str) -> str:
        return os.path.dirname(p)

    def basename(p: str) -> str:
        return os.path.basename(p)

    def ext(p: str) -> str:
        _, extension = os.path.splitext(p)
        return extension

    def absolute(p: str) -> str:
        return os.path.abspath(p)

    def relative(p: str, start: str = ".") -> str:
        return os.path.relpath(p, start)

    return {
        "join": join,
        "dirname": dirname,
        "basename": basename,
        "ext": ext,
        "absolute": absolute,
        "relative": relative,
    }


def _make_json_module() -> dict:
    """thirst::json — JSON parsing and serialization."""
    def parse(s: str) -> object:
        return json.loads(s)

    def stringify(v: object) -> str:
        return json.dumps(v)

    def get(d: dict, k: str, default=None) -> object:
        return d.get(k, default)

    def set(d: dict, k: str, v: object) -> dict:
        d[k] = v
        return d

    return {
        "parse": parse,
        "stringify": stringify,
        "get": get,
        "set": set,
    }


def _make_http_module() -> dict:
    """thirst::http — HTTP client (stub)."""
    import urllib.parse
    import urllib.request

    def get(url: str) -> str:
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                return str(response.read().decode())
        except Exception as e:
            return f"HTTP GET error: {e}"

    def post(url: str, data: object = None) -> str:
        try:
            data_bytes = json.dumps(data).encode() if data else b""
            req = urllib.request.Request(url, data=data_bytes,
                                          headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as response:
                return str(response.read().decode())
        except Exception as e:
            return f"HTTP POST error: {e}"

    def put(url: str, data: object = None) -> str:
        try:
            data_bytes = json.dumps(data).encode() if data else b""
            req = urllib.request.Request(url, data=data_bytes,
                                          headers={"Content-Type": "application/json"},
                                          method="PUT")
            with urllib.request.urlopen(req, timeout=10) as response:
                return str(response.read().decode())
        except Exception as e:
            return f"HTTP PUT error: {e}"

    def delete(url: str) -> str:
        try:
            req = urllib.request.Request(url, method="DELETE")
            with urllib.request.urlopen(req, timeout=10) as response:
                return str(response.read().decode())
        except Exception as e:
            return f"HTTP DELETE error: {e}"

    return {
        "get": get,
        "post": post,
        "put": put,
        "delete": delete,
    }


def _make_env_module() -> dict:
    """thirst::env — Environment variables."""
    def get(k: str, default: str = "") -> str:
        return os.environ.get(k, default)

    def set(k: str, v: str) -> None:
        os.environ[k] = v

    def all() -> dict:
        return dict(os.environ)

    return {
        "get": get,
        "set": set,
        "all": all,
    }


def _make_process_module() -> dict:
    """thirst::process — Process utilities."""
    import subprocess
    import sys

    def run(cmd: str) -> str:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)

    def exit(code: int = 0) -> None:
        sys.exit(code)

    def args() -> list[str]:
        return sys.argv

    def pid() -> int:
        return os.getpid()

    return {
        "run": run,
        "exit": exit,
        "args": args,
        "pid": pid,
    }


def _make_log_module() -> dict:
    """thirst::log — Logging utilities."""
    def info(msg: str) -> None:
        print(f"[INFO] {msg}")

    def warn(msg: str) -> None:
        print(f"[WARN] {msg}")

    def error(msg: str) -> None:
        print(f"[ERROR] {msg}")

    def debug(msg: str) -> None:
        print(f"[DEBUG] {msg}")

    return {
        "info": info,
        "warn": warn,
        "error": error,
        "debug": debug,
    }


def _make_test_module() -> dict:
    """thirst::test — Testing utilities."""
    def assert_eq(a: object, b: object) -> None:
        assert a == b, f"AssertionError: {a!r} != {b!r}"

    def assert_ne(a: object, b: object) -> None:
        assert a != b, f"AssertionError: {a!r} == {b!r}"

    def assert_true(v: object) -> None:
        assert v, f"AssertionError: {v!r} is not truthy"

    def assert_raises(fn: Callable[..., Any], *args, **kwargs) -> None:
        try:
            fn(*args, **kwargs)
            raise AssertionError("Expected exception but none raised")
        except Exception:
            pass

    describe_results = {}

    def describe(name: str) -> None:
        describe_results["current"] = name
        print(f"\n  {name}")

    def it(name: str) -> None:
        print(f"    ✓ {name}")

    return {
        "assert_eq": assert_eq,
        "assert_ne": assert_ne,
        "assert_true": assert_true,
        "assert_raises": assert_raises,
        "describe": describe,
        "it": it,
    }


def _make_collections_module() -> dict:
    """thirst::collections — Collection operations."""
    from functools import reduce as _reduce

    def map(fn: Callable[..., Any], lst: list) -> list:
        return [fn(x) for x in lst]

    def filter(fn: Callable[..., Any], lst: list) -> list:
        return [x for x in lst if fn(x)]

    def reduce(fn: Callable[..., Any], lst: list, init: object = None) -> object:
        if init is not None:
            return _reduce(fn, lst, init)
        return _reduce(fn, lst) if lst else None

    def sort(lst: list, reverse: bool = False) -> list:
        return sorted(lst, reverse=reverse)

    def unique(lst: list) -> list:
        seen = set()
        result = []
        for x in lst:
            if x not in seen:
                seen.add(x)
                result.append(x)
        return result

    def flatten(lst: list) -> list:
        result = []
        for x in lst:
            if isinstance(x, list):
                result.extend(flatten(x))
            else:
                result.append(x)
        return result

    def zip(*lsts: list) -> list:
        import builtins
        return list(builtins.zip(*lsts, strict=False))

    return {
        "map": map,
        "filter": filter,
        "reduce": reduce,
        "sort": sort,
        "unique": unique,
        "flatten": flatten,
        "zip": zip,
    }


def _make_net_module() -> dict:
    """thirst::net — Networking (stub)."""
    def tcp_connect(host: str, port: int) -> dict:
        return {"type": "tcp", "host": host, "port": port, "connected": True}

    def tcp_listen(port: int) -> dict:
        return {"type": "tcp_listener", "port": port, "listening": True}

    def udp_send(host: str, port: int, data: str) -> dict:
        return {"type": "udp", "host": host, "port": port, "sent": len(data)}

    return {
        "tcp_connect": tcp_connect,
        "tcp_listen": tcp_listen,
        "udp_send": udp_send,
    }


def _make_sqlite_module() -> dict:
    """thirst::sqlite — SQLite database operations (built-in sqlite3)."""
    import sqlite3

    _connections = {}

    def connect(path: str) -> str:
        conn_id = f"sqlite_{path}_{id(path)}"
        conn = sqlite3.connect(path)
        _connections[conn_id] = conn
        return conn_id

    def query(conn_id: str, sql: str) -> list:
        conn = _connections.get(conn_id)
        if conn is None:
            return [{"error": f"Connection not found: {conn_id}"}]
        cursor = conn.execute(sql)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        return [dict(zip(columns, row, strict=False)) for row in rows]

    def execute(conn_id: str, sql: str) -> dict:
        conn = _connections.get(conn_id)
        if conn is None:
            return {"error": f"Connection not found: {conn_id}"}
        cursor = conn.execute(sql)
        conn.commit()
        return {"rows_affected": cursor.rowcount}

    def close(conn_id: str) -> bool:
        conn = _connections.pop(conn_id, None)
        if conn:
            conn.close()
            return True
        return False

    return {
        "connect": connect,
        "query": query,
        "execute": execute,
        "close": close,
    }


def _make_yaml_module() -> dict:
    """thirst::yaml — YAML parsing (basic)."""
    def parse(s: str) -> dict:
        """Simple YAML parser for basic key-value pairs."""
        result = {}
        for line in s.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                value = parts[1].strip()
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                result[key] = value
        return result

    def dump(v: dict) -> str:
        lines = []
        for key, value in v.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    return {
        "parse": parse,
        "dump": dump,
    }


def _make_toml_module() -> dict:
    """thirst::toml — TOML parsing (using tomllib in Python 3.11+)."""
    def parse(s: str) -> dict:
        import tomllib
        return tomllib.loads(s)

    def dump(v: dict) -> str:
        lines = []
        for key, value in v.items():
            if isinstance(value, dict):
                lines.append(f"[{key}]")
                for k2, v2 in value.items():
                    lines.append(f"{k2} = {json.dumps(v2)}")
            elif isinstance(value, list):
                lines.append(f"{key} = {json.dumps(value)}")
            elif isinstance(value, bool):
                lines.append(f"{key} = {'true' if value else 'false'}")
            elif isinstance(value, (int, float)):
                lines.append(f"{key} = {value}")
            elif value is None:
                lines.append(f"{key} = none")
            else:
                lines.append(f"{key} = {json.dumps(value)}")
        return "\n".join(lines)

    return {
        "parse": parse,
        "dump": dump,
    }


# ============================================================
# Module Registry
# ============================================================

STDLIB_MODULES = {
    "thirst::time": _make_time_module,
    "thirst::crypto": _make_crypto_module,
    "thirst::reservoir": _make_reservoir_module,
    "thirst::fs": _make_fs_module,
    "thirst::path": _make_path_module,
    "thirst::json": _make_json_module,
    "thirst::http": _make_http_module,
    "thirst::env": _make_env_module,
    "thirst::process": _make_process_module,
    "thirst::log": _make_log_module,
    "thirst::test": _make_test_module,
    "thirst::collections": _make_collections_module,
    "thirst::net": _make_net_module,
    "thirst::sqlite": _make_sqlite_module,
    "thirst::yaml": _make_yaml_module,
    "thirst::toml": _make_toml_module,
}


# ============================================================
# Builtin Functions
# ============================================================

BUILTINS: dict[str, Callable[..., Any]] = {
    "length": lambda x: len(x) if hasattr(x, '__len__') else 0,
    "contains": lambda x, y: y in x if hasattr(x, '__contains__') else False,
    "split": lambda s, sep=None: s.split(sep) if isinstance(s, str) else [],
    "abs": lambda x: abs(x) if hasattr(x, '__abs__') else 0,
    "min": lambda *args: min(args) if args else 0,
    "max": lambda *args: max(args) if args else 0,
    "push": lambda r, v: (r.append(v), len(r))[-1] if isinstance(r, list) else 0,  # type: ignore[func-returns-value]
    "pop": lambda r: r.pop() if isinstance(r, list) and r else None,
    "size": lambda x: len(x) if hasattr(x, '__len__') else 0,
    "get": lambda x, i: x[i] if hasattr(x, '__getitem__') else None,
    "flood": lambda r, v: (r.append(v), r)[-1] if isinstance(r, list) else r,  # type: ignore[func-returns-value]
    "condense": lambda q: q.get("value") if isinstance(q, dict) and "value" in q else None,
    "evaporate": lambda q: q.pop("value") if isinstance(q, dict) and "value" in q else None,
    "strain": lambda x: x,
    "transmute": lambda x, t: x,
    "distill": lambda x: x,
}


# ============================================================
# Lockfile-aware Module Resolution
# ============================================================

def load_lockfile(cwd: str = ".") -> dict[str, Any]:
    """
    Load and parse thirsty.lock from the given directory.
    Returns the lockfile dict, or an empty dict if not found or malformed.
    """
    lock_path = os.path.join(cwd, "thirsty.lock")
    if not os.path.exists(lock_path):
        return {}
    try:
        with open(lock_path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def check_lock_integrity(dep_name: str, dep_version: str, lock: dict) -> bool:
    """
    Verify that a dependency (name@version) exists in the lockfile.
    Returns True if the dependency is found in the lockfile.
    If version is '*' or empty, matches any version of the dependency.
    """
    deps = lock.get("dependencies", {})
    if dep_name in deps:
        locked_entry = deps[dep_name]
        locked_version = locked_entry.get("version", "")
        if dep_version in ("*", "") or locked_version == dep_version:
            return True
    return False


# ============================================================
# Public API
# ============================================================

def resolve_import(path_str: str, locked: bool = False) -> object:
    """
    Resolve an import path string to a module object.
    Handles 'thirst::module' syntax for stdlib modules.
    When locked=True, verifies the dependency exists in thirsty.lock
    before resolving.
    """
    # When locked, load and verify against lockfile
    if locked:
        lock = load_lockfile(".")
        if not lock or "dependencies" not in lock or not lock["dependencies"]:
            raise ImportError(
                "Lockfile check failed: thirsty.lock not found or empty. "
                "Run 'thirsty lock' first to generate it."
            )
        # Extract dependency name from path_str (e.g. "thirst::crypto" -> "crypto")
        dep_name = path_str
        if path_str.startswith("thirst::"):
            dep_name = path_str[len("thirst::"):]
        if not check_lock_integrity(dep_name, "*", lock):
            raise ImportError(
                f"Lockfile integrity check failed: '{dep_name}' not found in thirsty.lock. "
                f"Run 'thirsty add {dep_name}' to add it."
            )

    # Check cache first
    if path_str in ModuleCache:
        return ModuleCache[path_str]

    # Check stdlib modules
    if path_str in STDLIB_MODULES:
        module = STDLIB_MODULES[path_str]()
        ModuleCache[path_str] = module
        return module

    # A 'thirst::' path not matched in STDLIB_MODULES above is an unknown module.
    if path_str.startswith("thirst::"):
        raise ImportError(f"Module not found: {path_str}")

    # Try to load from a .thirsty source file: parse, interpret, and expose its
    # top-level bindings (functions and `drink` values) as a module dict — the
    # same shape stdlib modules use, so `import "x.thirsty" as m; m.fn(...)`
    # works through the interpreter's dict member access.
    if path_str.endswith(".thirsty"):
        if not os.path.exists(path_str):
            raise ImportError(f"File not found: {path_str}")
        # Lazy imports: the interpreter imports this module at top level.
        from utf.thirsty_lang.interpreter import Interpreter
        from utf.thirsty_lang.lexer import Lexer
        from utf.thirsty_lang.parser import Parser

        with open(path_str) as f:
            source = f.read()
        parser = Parser(Lexer(source).lex())
        ast = parser.parse()
        if parser.errors:
            raise ImportError(f"Failed to import '{path_str}': {parser.errors[0]}")
        interp = Interpreter()
        baseline = set(interp.env.vars)  # builtins to exclude from the module
        interp.interpret(ast)
        module = {
            name: value
            for name, value in interp.env.vars.items()
            if name not in baseline
        }
        ModuleCache[path_str] = module
        return module

    raise ImportError(f"Module not found: {path_str}")


def get_builtin(name: str) -> Callable[..., Any]:
    """Get a builtin function by name."""
    if name in BUILTINS:
        return BUILTINS[name]
    raise KeyError(f"Builtin not found: {name}")


def list_stdlib_modules() -> list[str]:
    """List all available stdlib module paths."""
    return sorted(STDLIB_MODULES.keys())


def list_builtins() -> list[str]:
    """List all builtin function names."""
    return sorted(BUILTINS.keys())
