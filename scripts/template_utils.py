#!/usr/bin/env python3
"""
Shared utilities for rxerium-templates automation.

Used by:
- update_readme_stats.py
- update_templates_json.py
- validate_templates.py
- new_cve_template.py (indirectly)
"""

from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional

import yaml


def get_repo_root() -> Path:
    """Return the repository root (parent of scripts/)."""
    return Path(__file__).parent.parent


def discover_templates(repo_root: Optional[Path] = None) -> List[Path]:
    """Return a sorted list of all CVE-*.yaml template paths under year directories."""
    if repo_root is None:
        repo_root = get_repo_root()
    templates: List[Path] = []
    for year_dir in sorted(repo_root.glob("20[0-9][0-9]")):
        if year_dir.is_dir():
            for yaml_file in sorted(year_dir.glob("*.yaml")):
                templates.append(yaml_file)
    return templates


def get_wip_templates(templates: List[Path]) -> List[Path]:
    """Filter WIP templates (by filename convention)."""
    return [t for t in templates if "WIP" in t.name.upper()]


def load_template_info(yaml_path: Path) -> Dict[str, Any]:
    """
    Parse a Nuclei-style CVE template and return a rich info dict.

    Safe on parse errors (returns partial data derived from path + filename).
    """
    repo_root = get_repo_root()
    try:
        rel_path = str(yaml_path.relative_to(repo_root))
    except Exception:
        rel_path = str(yaml_path)

    info: Dict[str, Any] = {
        "id": yaml_path.stem,
        "name": None,
        "path": rel_path,
        "year": yaml_path.parent.name,
        "author": None,
        "severity": None,
        "description": None,
        "cvss_score": None,
        "cisa_kev": False,
        "verified": False,
        "vendor": None,
        "product": None,
        "cwe_id": None,
        "shodan_query": None,
        "tags": [],
        "references": [],
        "wip": "WIP" in yaml_path.name.upper(),
    }

    try:
        content = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}

        if "id" in content:
            info["id"] = content["id"]

        info_section = content.get("info") or {}

        info["name"] = info_section.get("name")
        info["author"] = info_section.get("author")
        info["severity"] = info_section.get("severity")
        info["description"] = info_section.get("description")

        # references (list or single string)
        refs = info_section.get("reference") or info_section.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        info["references"] = [r for r in refs if r]

        # tags (frequently a comma string in this collection)
        raw_tags = info_section.get("tags", "")
        if isinstance(raw_tags, list):
            info["tags"] = [str(t).strip() for t in raw_tags if str(t).strip()]
        elif isinstance(raw_tags, str):
            info["tags"] = [t.strip() for t in raw_tags.split(",") if t.strip()]

        # metadata + classification (newer Nuclei templates put cvss/cwe here too)
        metadata = info_section.get("metadata") or {}
        classification = info_section.get("classification") or {}

        cvss = metadata.get("cvss-score")
        if cvss is None:
            cvss = classification.get("cvss-score")
        info["cvss_score"] = cvss

        info["cisa_kev"] = bool(metadata.get("cisa-kev", False))
        info["verified"] = bool(metadata.get("verified", False))

        info["vendor"] = metadata.get("vendor")
        info["product"] = metadata.get("product")

        cwe = metadata.get("cwe-id")
        if cwe is None:
            cwe = classification.get("cwe-id")
        info["cwe_id"] = cwe

        info["shodan_query"] = metadata.get("shodan-query")

    except Exception:
        # Return best-effort info derived from filesystem
        pass

    return info


def count_templates(repo_root: Optional[Path] = None) -> Tuple[defaultdict, List[Path], List[Path]]:
    """
    Backwards-compatible count used by update_readme_stats.py.

    Returns (templates_by_year, all_templates, wip_templates)
    """
    if repo_root is None:
        repo_root = get_repo_root()
    all_templates = discover_templates(repo_root)
    templates_by_year: defaultdict = defaultdict(list)
    for t in all_templates:
        templates_by_year[t.parent.name].append(t)
    wip_templates = get_wip_templates(all_templates)
    return templates_by_year, all_templates, wip_templates
