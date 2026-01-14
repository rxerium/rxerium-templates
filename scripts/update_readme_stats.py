#!/usr/bin/env python3
"""
Script to automatically update README.md with repository statistics.
"""

import os
import re
import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Get the repository root directory
REPO_ROOT = Path(__file__).parent.parent
README_PATH = REPO_ROOT / "README.md"


def count_templates():
    """Count all YAML template files and organize by year."""
    templates_by_year = defaultdict(list)
    all_templates = []
    wip_templates = []
    
    # Find all YAML files in year directories
    for year_dir in sorted(REPO_ROOT.glob("20[0-9][0-9]")):
        if year_dir.is_dir():
            year = year_dir.name
            for yaml_file in year_dir.glob("*.yaml"):
                templates_by_year[year].append(yaml_file)
                all_templates.append(yaml_file)
                if "WIP" in yaml_file.name.upper():
                    wip_templates.append(yaml_file)
    
    return templates_by_year, all_templates, wip_templates


def extract_template_info(yaml_file):
    """Extract information from a YAML template file."""
    info = {
        'file': yaml_file,
        'cve': yaml_file.stem,
        'year': yaml_file.parent.name,
        'severity': None,
        'cvss_score': None,
        'verified': None,
        'cisa_kev': None,
    }
    
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)
            if content and 'info' in content:
                info_section = content['info']
                info['severity'] = info_section.get('severity')
                if 'metadata' in info_section:
                    metadata = info_section['metadata']
                    info['cvss_score'] = metadata.get('cvss-score')
                    info['verified'] = metadata.get('verified', False)
                    info['cisa_kev'] = metadata.get('cisa-kev', False)
    except Exception as e:
        # If parsing fails, continue with basic info
        pass
    
    return info


def calculate_stats():
    """Calculate all repository statistics."""
    templates_by_year, all_templates, wip_templates = count_templates()
    
    # Basic counts
    total_templates = len(all_templates)
    total_wip = len(wip_templates)
    total_completed = total_templates - total_wip
    
    # Year breakdown
    year_counts = {year: len(templates) for year, templates in sorted(templates_by_year.items())}
    year_range = f"{min(year_counts.keys())}-{max(year_counts.keys())}"
    
    # Extract template info for additional stats
    template_info = [extract_template_info(t) for t in all_templates]
    
    # Severity distribution
    severity_counts = defaultdict(int)
    for info in template_info:
        if info['severity']:
            severity_counts[info['severity']] += 1
    
    # CVSS score stats
    cvss_scores = [info['cvss_score'] for info in template_info if info['cvss_score'] is not None]
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else None
    critical_count = len([s for s in cvss_scores if s >= 9.0])
    high_count = len([s for s in cvss_scores if 7.0 <= s < 9.0])
    
    # Verified and CISA KEV stats
    verified_count = len([info for info in template_info if info['verified']])
    cisa_kev_count = len([info for info in template_info if info['cisa_kev']])
    
    # Most recent template (by filename, assuming newer CVEs have higher numbers)
    most_recent = max(all_templates, key=lambda x: x.name) if all_templates else None
    oldest = min(all_templates, key=lambda x: x.name) if all_templates else None
    
    return {
        'total_templates': total_templates,
        'total_completed': total_completed,
        'total_wip': total_wip,
        'year_range': year_range,
        'year_counts': year_counts,
        'severity_counts': dict(severity_counts),
        'avg_cvss': avg_cvss,
        'critical_count': critical_count,
        'high_count': high_count,
        'verified_count': verified_count,
        'cisa_kev_count': cisa_kev_count,
        'most_recent': most_recent.stem if most_recent else None,
        'oldest': oldest.stem if oldest else None,
    }


def update_readme(stats):
    """Update README.md with calculated statistics."""
    with open(README_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Update total templates count in description (handle both with and without +)
    content = re.sub(
        r'(\*\*)\d+\+?(\s+Nuclei templates\*\*)',
        f'\\g<1>{stats["total_templates"]}+\\g<2>',
        content
    )
    
    # Update badge count if present
    content = re.sub(
        r'(\[!\[Templates\]\([^)]+\)\]\([^)]+\) templates-)\d+(\+-blue)',
        f'\\g<1>{stats["total_templates"]}\\g<2>',
        content
    )
    
    # Update CISA KEV badge if present
    content = re.sub(
        r'(\[!\[CISA KEV\]\([^)]+\)\]\([^)]+\) CISA%20KEV-)\d+(-red)',
        f'\\g<1>{stats["cisa_kev_count"]}\\g<2>',
        content
    )
    
    # Find and update the Statistics section
    stats_pattern = r'(## 📊 Statistics\n\n<!-- Stats are auto-updated by GitHub Actions -->\n\n)(.*?)(\n\n## )'
    match = re.search(stats_pattern, content, re.DOTALL)
    
    if match:
        # Build new statistics section
        stats_section = "## 📊 Statistics\n\n"
        stats_section += "<!-- Stats are auto-updated by GitHub Actions -->\n\n"
        
        # Build compact stats
        stats_section += f"- **Total Templates:** {stats['total_templates']} ({stats['total_completed']} completed, {stats['total_wip']} WIP)\n"
        avg_cvss_str = f"{stats['avg_cvss']:.1f}" if stats['avg_cvss'] else 'N/A'
        stats_section += f"- **Coverage:** {stats['year_range']} | **Avg CVSS:** {avg_cvss_str} | **CISA KEV:** {stats['cisa_kev_count']}\n"
        
        # Severity breakdown
        if stats['severity_counts']:
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            severity_parts = []
            for sev in severity_order:
                if sev in stats['severity_counts']:
                    severity_parts.append(f"{sev.capitalize()}: {stats['severity_counts'][sev]}")
            if severity_parts:
                stats_section += f"- **Severity:** {' | '.join(severity_parts)}\n"
        
        # CVSS breakdown
        if stats['avg_cvss']:
            stats_section += f"- **CVSS Breakdown:** Critical (≥9.0): {stats['critical_count']} | High (7.0-8.9): {stats['high_count']}\n"
        
        # Year distribution
        year_parts = [f"{year}: {count}" for year, count in sorted(stats['year_counts'].items())]
        stats_section += f"- **Year Distribution:** {' | '.join(year_parts)}\n"
        
        stats_section += "\n"
        
        # Replace the statistics section
        content = re.sub(stats_pattern, stats_section + r'\3', content, flags=re.DOTALL)
    
    # Write updated content
    with open(README_PATH, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✅ Updated README.md with statistics:")
    print(f"   - Total templates: {stats['total_templates']}")
    print(f"   - Completed: {stats['total_completed']}")
    print(f"   - WIP: {stats['total_wip']}")
    print(f"   - Year range: {stats['year_range']}")


if __name__ == "__main__":
    print("📊 Calculating repository statistics...")
    stats = calculate_stats()
    print("📝 Updating README.md...")
    update_readme(stats)
    print("✨ Done!")
