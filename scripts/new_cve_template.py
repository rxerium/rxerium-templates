#!/usr/bin/env python3
"""
Automation for adding a new CVE template to rxerium-templates.

Usage examples:
    python3 scripts/new_cve_template.py CVE-2026-12345
    python3 scripts/new_cve_template.py CVE-2026-9999-WIP --severity critical --vendor "Acme" --product "FooBar" --cvss 9.8 -y --no-edit

Features:
- Creates correctly named file in the right year/ directory (creates year dir if needed)
- Generates a realistic starter template based on the style of this collection (passive version detection)
- Supports --wip (or passing CVE-....-WIP)
- Interactive prompts (or fully non-interactive with --yes + flags)
- Launches $EDITOR (or $VISUAL) after creation so you can flesh out the matchers/extractors/description
- Automatically refreshes templates.json + README stats locally after you're done editing
- Works great with the GitHub Action (just push the new .yaml; CI will keep indexes in sync)
"""

import argparse
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import List, Optional

# Sibling import for utils (when invoked as python3 scripts/new_....py)
sys.path.insert(0, str(Path(__file__).parent))
from template_utils import get_repo_root, discover_templates  # discover only used for existence check


def parse_cve_id(raw: str, force_wip: bool) -> tuple[str, str, str, bool]:
    """
    Normalize a CVE id argument.

    Returns: (full_id_for_yaml, filename, year_str, is_wip)
    Examples:
        "CVE-2026-1234"          -> ("CVE-2026-1234", "CVE-2026-1234.yaml", "2026", False)
        "cve-2026-1234" + --wip  -> ("CVE-2026-1234-WIP", "CVE-2026-1234-WIP.yaml", "2026", True)
        "CVE-2026-1234-WIP"      -> ("CVE-2026-1234-WIP", "CVE-2026-1234-WIP.yaml", "2026", True)
    """
    c = raw.strip().upper()
    if not c.startswith("CVE-"):
        raise ValueError(f"CVE id must start with CVE- (got {raw})")

    m = re.match(r"(CVE-\d{4}-\d+)(?:-WIP)?$", c)
    if not m:
        # Be forgiving for unusual numbers but still require the shape
        m = re.match(r"(CVE-\d{4}-[A-Z0-9]+)(?:-WIP)?$", c)

    if not m:
        raise ValueError(f"Unrecognized CVE id format: {raw} (expected CVE-YYYY-NNNN)")

    numeric = m.group(1)          # CVE-2026-1234
    is_wip = force_wip or c.endswith("-WIP")

    full_id = numeric + ("-WIP" if is_wip else "")
    file_name = f"{numeric}{'-WIP' if is_wip else ''}.yaml"
    year = numeric.split("-")[1]

    return full_id, file_name, year, is_wip


def build_references_block(refs: List[str], base_cve: str) -> str:
    """Return properly indented YAML list for the reference: key."""
    if not refs:
        refs = [f"https://nvd.nist.gov/vuln/detail/{base_cve}"]
    lines = [f"    - {r}" for r in refs]
    return "\n".join(lines)


def indent_description(desc: str) -> str:
    """Indent description body for a | block (4 spaces)."""
    if not desc:
        return "    TODO: Write a concise description of the vulnerability and how the template detects it.\n"
    cleaned = textwrap.dedent(desc).strip()
    return "\n".join("    " + line if line else "    " for line in cleaned.splitlines())


def generate_skeleton(
    full_id: str,
    name: str,
    author: str,
    severity: str,
    description: str,
    vendor: str,
    product: str,
    cvss: Optional[float],
    cisa_kev: bool,
    tags: List[str],
    references: List[str],
) -> str:
    """Return the full YAML content for a new template."""
    base_cve = full_id.split("-WIP")[0]
    year = base_cve.split("-")[1]

    refs_block = build_references_block(references, base_cve)
    tags_str = ",".join(tags) if tags else f"cve,cve{year},{(vendor or 'product').lower().replace(' ', '')}"

    kev_str = "true" if cisa_kev else "false"

    desc_block = indent_description(description)

    # Build metadata block carefully so that cvss-score is only a real number (or commented).
    # This prevents the stats calculator (which does sum on numeric cvss values) from
    # blowing up on "TODO" strings when users create templates without --cvss.
    meta_lines = [
        "    max-request: 1",
        f"    vendor: {vendor or 'TODO-Vendor'}",
        f"    product: {product or 'TODO-Product'}",
    ]
    if cvss is not None:
        meta_lines.append(f"    cvss-score: {cvss}")
    else:
        meta_lines.append("    # cvss-score: 9.8   # TODO: add real CVSS when known")
    meta_lines.extend([
        f"    cisa-kev: {kev_str}",
        "    verified: true",
        "    # shodan-query: 'product:\"Example\"'",
    ])
    metadata_block = "\n".join(meta_lines)

    # A realistic starter based on the patterns used across this repo
    # (single GET, internal version extractor, word + status + dsl matchers).
    skeleton = f'''id: {full_id}

info:
  name: {name}
  author: {author}
  severity: {severity}
  description: |
{desc_block}
  reference:
{refs_block}
  metadata:
{metadata_block}
  tags: {tags_str}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"                    # TODO: change to the page that leaks version (login, /status, /, /mics/login.jsp, etc.)
      # - "{{{{BaseURL}}}}/another/path"

    extractors:
      - type: regex
        name: version
        group: 1
        regex:
          - 'TODO: ([0-9]+\\.[0-9]+\\.[0-9]+(?:\\.[0-9]+)?)'   # TODO: improve the regex to reliably capture the version banner
        internal: true

    # host-redirects: true
    # max-redirects: 2

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "{product or 'ProductName'}"      # TODO: a reliable string that appears on the page when the product is present

      - type: status
        status:
          - 200

      - type: dsl
        dsl:
          # TODO: set the correct vulnerable ranges. Examples:
          # - compare_versions(version, "< 1.2.3") || compare_versions(version, "== 1.2.3") || compare_versions(version, ">= 9.0.0")
          - compare_versions(version, "< 0.0.0")   # <-- replace this
'''

    return skeleton


def prompt(msg: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{msg}{suffix}: ").strip()
    return val or (default or "")


def prompt_multiline(msg: str) -> str:
    print(f"{msg} (end with a blank line):")
    lines: List[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines).strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scaffold a new CVE template for rxerium-templates and keep indexes fresh."
    )
    parser.add_argument("cve_id", help="CVE id, e.g. CVE-2026-12345 or CVE-2026-12345-WIP")
    parser.add_argument("--wip", action="store_true", help="Mark as work-in-progress (appends -WIP to id/filename)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default="critical")
    parser.add_argument("--vendor", help="Vendor name (e.g. Ivanti, Fortra)")
    parser.add_argument("--product", help="Product name (e.g. Endpoint Manager Mobile)")
    parser.add_argument("--cvss", type=float, help="CVSS score, e.g. 9.8")
    parser.add_argument("--cisa-kev", action="store_true", dest="cisa_kev", help="This vulnerability is in CISA KEV")
    parser.add_argument("--author", default="rxerium")
    parser.add_argument("--name", help="Full template name (info.name). Defaults to a sensible value.")
    parser.add_argument("--description", help="Description text (you will usually edit this in $EDITOR)")
    parser.add_argument("--tag", action="append", dest="tags", default=[], help="Extra tag (repeatable)")
    parser.add_argument("--reference", action="append", dest="refs", default=[], help="Reference URL (repeatable)")
    parser.add_argument("--no-edit", action="store_true", help="Skip launching the editor after scaffolding")
    parser.add_argument("-y", "--yes", action="store_true", help="Non-interactive mode (use provided values or sensible defaults; no prompts)")

    args = parser.parse_args()

    try:
        full_id, file_name, year, is_wip = parse_cve_id(args.cve_id, args.wip)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(2)

    repo_root = get_repo_root()
    year_dir = repo_root / year
    target_file = year_dir / file_name

    # Check for existing
    if target_file.exists():
        print(f"⚠️  {target_file} already exists.")
        if not args.yes:
            ans = input("Overwrite? [y/N]: ").strip().lower()
            if ans != "y":
                print("Aborted.")
                sys.exit(0)
        print("Proceeding to overwrite...")

    # Collect values (CLI flags win; then prompts unless --yes)
    vendor = args.vendor or ""
    product = args.product or ""
    cvss = args.cvss
    cisa_kev = args.cisa_kev
    author = args.author
    severity = args.severity

    if not args.yes:
        if not vendor:
            vendor = prompt("Vendor", "TODO-Vendor")
        if not product:
            product = prompt("Product", "TODO-Product")
        if cvss is None:
            cv = prompt("CVSS score (e.g. 9.8) or leave blank", "")
            if cv:
                try:
                    cvss = float(cv)
                except ValueError:
                    cvss = None
        if not cisa_kev:
            kev_ans = prompt("In CISA KEV? [y/N]", "n").lower()
            cisa_kev = kev_ans.startswith("y")

    # Name
    base_for_name = full_id.split("-WIP")[0]
    default_name = f"{base_for_name} - {vendor} {product}".strip().rstrip("- ")
    name = args.name or default_name
    if not args.yes and not args.name:
        name = prompt("Template name (info.name)", default_name) or default_name

    # Description
    description = args.description or ""
    if not args.yes and not description:
        description = prompt_multiline("Short description (full prose goes in the YAML)")

    # Tags & refs
    tags: List[str] = list(args.tags)
    refs: List[str] = list(args.refs)

    if not args.yes:
        if not tags:
            extra = prompt("Extra tags (comma-separated, optional)", "")
            if extra:
                tags.extend([t.strip() for t in extra.split(",") if t.strip()])
        if not refs:
            extra_ref = prompt("Extra reference URL (optional)", "")
            if extra_ref:
                refs.append(extra_ref)

    # Always ensure base tags
    year_tag = f"cve{year}"
    base_tags = ["cve", year_tag]
    for t in tags:
        if t not in base_tags:
            base_tags.append(t)
    tags = base_tags

    # Generate
    content = generate_skeleton(
        full_id=full_id,
        name=name,
        author=author,
        severity=severity,
        description=description,
        vendor=vendor,
        product=product,
        cvss=cvss,
        cisa_kev=cisa_kev,
        tags=tags,
        references=refs,
    )

    # Write
    year_dir.mkdir(parents=True, exist_ok=True)
    target_file.write_text(content, encoding="utf-8")
    print(f"✅ Created {target_file.relative_to(repo_root)}")

    # Edit?
    if not args.no_edit:
        editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "vi"
        print(f"📝 Opening in $EDITOR ({editor}). Save & quit when finished.")
        try:
            subprocess.call([editor, str(target_file)])
        except Exception as e:
            print(f"Could not launch editor ({e}). You can open the file manually.")

    # Refresh local indexes so your working tree is consistent before commit
    print("\n📚 Refreshing templates.json and README statistics locally...")
    scripts_dir = Path(__file__).parent
    try:
        subprocess.check_call([sys.executable, str(scripts_dir / "update_templates_json.py")])
        subprocess.check_call([sys.executable, str(scripts_dir / "update_readme_stats.py")])
    except subprocess.CalledProcessError:
        print("⚠️  Index update scripts reported an error (indexes may be slightly stale until next run).")

    print("\n✨ Next steps:")
    print(f"   git add {target_file.relative_to(repo_root)} templates.json README.md")
    print('   git commit -m "feat: add template for {}"'.format(full_id))
    print("   git push")
    print("\n   (CI will validate + auto-update indexes again with the final committed version.)")


if __name__ == "__main__":
    main()
