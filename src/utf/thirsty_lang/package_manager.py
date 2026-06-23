"""
Thirsty-Lang Package Manager
thirsty.toml files, thirsty.lock with SHA-256, and dependency management.
"""
import hashlib
import json
import os
import re


class PackageManager:
    """Manage Thirsty-Lang packages (dependencies, manifest, lockfile)."""

    def __init__(self, project_root: str = "."):
        self.project_root = project_root
        self.manifest_path = os.path.join(project_root, "thirsty.toml")
        self.lock_path = os.path.join(project_root, "thirsty.lock")
        self.manifest: dict = {}
        self.lock: dict = {}

    def parse_manifest(self, path: str = None) -> dict:
        """Parse a thirsty.toml manifest file."""
        if path:
            self.manifest_path = path
        if not os.path.exists(self.manifest_path):
            return {}
        with open(self.manifest_path) as f:
            content = f.read()
        self.manifest = self._parse_toml(content)
        return self.manifest

    def _parse_toml(self, content: str) -> dict:
        """Simple TOML parser for thirsty.toml format."""
        result = {}
        current_section = result

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header: [section]
            section_match = re.match(r'^\[([^\]]+)\]$', line)
            if section_match:
                section_name = section_match.group(1)
                parts = section_name.split(".")
                current_section = result
                for part in parts:
                    if part not in current_section:
                        current_section[part] = {}
                    current_section = current_section[part]
                continue

            # Key-value: key = value
            kv_match = re.match(r'^([^=]+)=(.+)$', line)
            if kv_match:
                key = kv_match.group(1).strip()
                raw_value = kv_match.group(2).strip()
                value = self._parse_toml_value(raw_value)
                current_section[key] = value

        return result

    def _parse_toml_value(self, raw: str) -> object:
        """Parse a TOML value."""
        if raw.startswith('"') and raw.endswith('"'):
            return raw[1:-1]
        if raw.startswith("'") and raw.endswith("'"):
            return raw[1:-1]
        if raw == "true":
            return True
        if raw == "false":
            return False
        if raw == "none" or raw == "null":
            return None
        # Array: [1, 2, 3]
        if raw.startswith("[") and raw.endswith("]"):
            inner = raw[1:-1].strip()
            if not inner:
                return []
            items = []
            for item in re.split(r',\s*', inner):
                items.append(self._parse_toml_value(item.strip()))
            return items
        # Inline table: {key = value}
        if raw.startswith("{") and raw.endswith("}"):
            inner = raw[1:-1].strip()
            result = {}
            for pair in re.split(r',\s*', inner):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    result[k.strip()] = self._parse_toml_value(v.strip())
            return result
        # Number
        try:
            if "." in raw:
                return float(raw)
            return int(raw)
        except ValueError:
            pass
        return raw

    def parse_lock(self, path: str = None) -> dict:
        """Parse thirsty.lock lockfile."""
        if path:
            self.lock_path = path
        if not os.path.exists(self.lock_path):
            return {}
        with open(self.lock_path) as f:
            content = f.read()
        self.lock = json.loads(content) if content.strip() else {}
        return self.lock

    def generate_lock(self, dependencies: dict = None) -> dict:
        """Generate a lockfile with SHA-256 hashes."""
        if dependencies is None:
            dependencies = self.manifest.get("dependencies", {})

        lock_entries = {}
        for name, version_spec in dependencies.items():
            version = version_spec if isinstance(version_spec, str) else str(version_spec)
            entry = {
                "version": version,
                "resolved": f"thirsty-registry://{name}@{version}",
                "integrity": self._compute_integrity(name, version),
            }
            lock_entries[name] = entry

        self.lock = {
            "lockfile_version": 1,
            "dependencies": lock_entries,
        }
        return self.lock

    def _compute_integrity(self, name: str, version: str) -> str:
        """Compute SHA-256 integrity hash for a dependency entry."""
        content = f"{name}@{version}"
        return "sha256-" + hashlib.sha256(content.encode()).hexdigest()

    def write_lock(self, path: str = None) -> bool:
        """Write the lockfile."""
        if path:
            self.lock_path = path
        try:
            with open(self.lock_path, 'w') as f:
                json.dump(self.lock, f, indent=2)
            return True
        except Exception:
            return False

    def verify_integrity(self) -> list[dict]:
        """Verify all lockfile entries match their computed hashes."""
        violations = []
        for name, entry in self.lock.get("dependencies", {}).items():
            expected = entry.get("integrity", "")
            computed = self._compute_integrity(name, entry.get("version", ""))
            if expected != computed:
                violations.append({
                    "name": name,
                    "expected": expected,
                    "computed": computed,
                })
        return violations

    def add_dependency(self, name: str, version_spec: str = "*") -> bool:
        """Add a dependency to the manifest."""
        deps = self.manifest.setdefault("dependencies", {})
        deps[name] = version_spec
        return self._write_manifest()

    def remove_dependency(self, name: str) -> bool:
        """Remove a dependency from the manifest."""
        deps = self.manifest.get("dependencies", {})
        if name in deps:
            del deps[name]
            return self._write_manifest()
        return False

    def _write_manifest(self) -> bool:
        """Write the manifest back to disk."""
        try:
            content = self._format_toml(self.manifest)
            with open(self.manifest_path, 'w') as f:
                f.write(content)
            return True
        except Exception:
            return False

    def _format_toml(self, data: dict, prefix: str = "") -> str:
        """Format a dict as a TOML string."""
        lines = []
        for key, value in data.items():
            if isinstance(value, dict) and key != "dependencies":
                lines.append(f"\n[{prefix}{key}]")
                for k2, v2 in value.items():
                    lines.append(f"{k2} = {json.dumps(v2) if isinstance(v2, str) else v2}")
            elif key == "dependencies" and isinstance(value, dict):
                lines.append("\n[dependencies]")
                for dep_name, dep_ver in value.items():
                    lines.append(f"{dep_name} = {json.dumps(str(dep_ver))}")
            else:
                lines.append(f"{key} = {json.dumps(value) if isinstance(value, str) else value}")
        return "\n".join(lines)

    def audit_dependencies(self) -> list[dict]:
        """Audit all dependencies for integrity and version issues."""
        issues = []
        # Parse manifest
        self.parse_manifest()
        # Parse lockfile
        self.parse_lock()

        manifest_deps = self.manifest.get("dependencies", {})
        lock_deps = self.lock.get("dependencies", {})

        for name in manifest_deps:
            if name not in lock_deps:
                issues.append({
                    "type": "missing_lock",
                    "name": name,
                    "message": f"Dependency '{name}' is in manifest but not in lockfile"
                })
            else:
                # Verify integrity
                expected = lock_deps[name].get("integrity", "")
                computed = self._compute_integrity(name, lock_deps[name].get("version", ""))
                if expected != computed:
                    issues.append({
                        "type": "integrity_mismatch",
                        "name": name,
                        "message": f"Integrity mismatch for '{name}'"
                    })

        for name in lock_deps:
            if name not in manifest_deps:
                issues.append({
                    "type": "orphan_lock",
                    "name": name,
                    "message": f"Dependency '{name}' is in lockfile but not in manifest"
                })

        return issues


def create_thirsty_toml(project_dir: str, name: str, version: str = "0.1.0") -> str:
    """Create a default thirsty.toml manifest file."""
    content = f"""[package]
name = "{name}"
version = "{version}"
thirsty-version = "1.0"
mode = "core"

[dependencies]
"""
    path = os.path.join(project_dir, "thirsty.toml")
    with open(path, 'w') as f:
        f.write(content)
    return path


def create_thirsty_lock(project_dir: str) -> str:
    """Create an empty thirsty.lock lockfile."""
    content = json.dumps({
        "lockfile_version": 1,
        "dependencies": {}
    }, indent=2)
    path = os.path.join(project_dir, "thirsty.lock")
    with open(path, 'w') as f:
        f.write(content)
    return path
