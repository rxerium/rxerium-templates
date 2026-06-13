#!/usr/bin/env python3
"""
Script to automatically generate templates.json - a machine-readable index of all CVE templates.
Run by GitHub Actions on template changes.
"""

import json
import sys
from pathlib import Path

# Make sibling imports work when running as `python3 scripts/update_templates_json.py`
sys.path.insert(0, str(Path(__file__).parent))
from template_utils import discover_templates, get_wip_templates, load_template_info, get_repo_root


OUTPUT_PATH = get_repo_root() / "templates.json"


def build_templates_index():
    """Build the full templates.json data structure using shared utilities."""
    all_templates = discover_templates()
    wip_templates = get_wip_templates(all_templates)

    template_entries = [load_template_info(t) for t in all_templates]

    # Sort by id descending (newer CVEs first)
    template_entries.sort(key=lambda t: t.get("id", ""), reverse=True)

    total = len(all_templates)
    wip_count = len(wip_templates)
    completed = total - wip_count

    data = {
        "name": "rxerium-templates",
        "schema_version": "1.0",
        "total": total,
        "completed": completed,
        "wip": wip_count,
        "templates": template_entries,
    }

    return data


def write_templates_json(data):
    """Write the index to templates.json (stable output, only writes if changed)."""
    json_str = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    existing = ""
    if OUTPUT_PATH.exists():
        existing = OUTPUT_PATH.read_text(encoding="utf-8")

    if existing == json_str:
        print("✅ templates.json is already up to date (no changes).")
        return False

    OUTPUT_PATH.write_text(json_str, encoding="utf-8")
    print(f"✅ Wrote templates.json with {data['total']} templates ({data['completed']} completed, {data['wip']} WIP)")
    return True


if __name__ == "__main__":
    print("📚 Building templates index...")
    data = build_templates_index()
    print(f"   Discovered {data['total']} templates")
    print("📝 Writing templates.json...")
    changed = write_templates_json(data)
    if changed:
        print("✨ templates.json updated.")
    else:
        print("✨ No update needed.")
