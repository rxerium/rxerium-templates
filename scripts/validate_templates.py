#!/usr/bin/env python3
"""
Validate all CVE templates in the repository.

Checks for:
- Valid YAML
- Required top-level keys (id, info)
- Reasonable info fields (name, severity)
- At least one protocol request (http supported today)
- id looks like a CVE

Intended to be run locally and in CI before index updates.
Exits non-zero on any errors.
"""

import sys
import json
from pathlib import Path
from typing import List, Tuple

import yaml

# Shared utils
sys.path.insert(0, str(Path(__file__).parent))
from template_utils import discover_templates, load_template_info, get_repo_root


def validate_template(yaml_path: Path) -> List[str]:
    """Return list of error strings for a single template (empty = OK)."""
    errors: List[str] = []
    rel = yaml_path.relative_to(get_repo_root())

    try:
        raw = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except Exception as e:
        errors.append(f"yaml parse error: {e}")
        return errors

    if not isinstance(data, dict):
        errors.append("root is not a mapping")
        return errors

    # id
    tid = data.get("id")
    if not tid or not str(tid).upper().startswith("CVE-"):
        errors.append("missing or invalid top-level 'id' (must start with CVE-)")

    # info section
    info = data.get("info")
    if not isinstance(info, dict):
        errors.append("missing or invalid 'info' section")
    else:
        if not info.get("name"):
            errors.append("info.name is required")
        if not info.get("severity"):
            errors.append("info.severity is required (critical|high|medium|low|info)")

    # Protocol request block (this collection is mostly http, but some use javascript/requests/etc.)
    KNOWN_PROTOCOLS = {"http", "requests", "dns", "file", "network", "javascript", "tcp", "udp", "ssl", "websocket", "headless", "code"}
    has_protocol = any(
        k in data and isinstance(data.get(k), (list, tuple)) and data.get(k)
        for k in KNOWN_PROTOCOLS
    )
    if not has_protocol:
        errors.append("no recognized protocol request block (http/requests/javascript/dns/etc.) found")

    # Filename / id sanity (lenient)
    stem = yaml_path.stem
    if tid and str(tid).upper() not in (stem.upper(), stem.upper() + "-WIP"):
        # Allow minor differences (some older templates vary)
        pass

    return errors


def main() -> None:
    repo_root = get_repo_root()
    templates = discover_templates(repo_root)

    all_errors: List[Tuple[Path, List[str]]] = []
    for t in templates:
        errs = validate_template(t)
        if errs:
            all_errors.append((t, errs))

    # Optional: cross-check templates.json counts if present (non-fatal)
    json_path = repo_root / "templates.json"
    if json_path.exists():
        try:
            j = json.loads(json_path.read_text(encoding="utf-8"))
            j_total = j.get("total", 0)
            if j_total != len(templates):
                print(f"⚠️  templates.json reports total={j_total} but discovered {len(templates)} templates")
                print("   (run `python3 scripts/update_templates_json.py` to refresh)")
        except Exception:
            pass

    if all_errors:
        print(f"❌ Validation failed for {len(all_errors)} / {len(templates)} templates:\n")
        for path, errs in all_errors:
            rel = path.relative_to(repo_root)
            for e in errs:
                print(f"  - {rel}: {e}")
        print(f"\n{len(all_errors)} templates with issues.")
        sys.exit(1)
    else:
        print(f"✅ All {len(templates)} templates passed validation.")
        sys.exit(0)


if __name__ == "__main__":
    main()
