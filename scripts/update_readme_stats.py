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
    
    # Update total templates count (handle both with and without +)
    content = re.sub(
        r'(\*\*)\d+\+?(\s+Nuclei templates\*\*)',
        f'\\g<1>{stats["total_templates"]}+\\g<2>',
        content
    )
    
    # Update CVE templates count and year range
    content = re.sub(
        r'(\*\*)\d+(\s+CVE templates\s+spanning\s+)\d+-\d+(\*\*)',
        f'\\g<1>{stats["total_completed"]}\\g<2>{stats["year_range"]}\\g<3>',
        content
    )
    
    # Find the Coverage section and update it
    coverage_pattern = r'(## Coverage\n)(.*?)(\n## |\Z)'
    match = re.search(coverage_pattern, content, re.DOTALL)
    
    if match:
        # Build new coverage section
        coverage_section = "## Coverage\n"
        coverage_section += f"- **{stats['total_completed']} CVE templates** spanning {stats['year_range']}\n"
        coverage_section += f"- **{stats['total_wip']} template{'s' if stats['total_wip'] != 1 else ''} in progress**\n"
        coverage_section += "- Organised by year for easy navigation\n"
        coverage_section += "- Regular updates as new threats emerge\n\n"
        
        # Add detailed stats
        coverage_section += "### Statistics\n"
        coverage_section += f"- **Total Templates:** {stats['total_templates']}\n"
        coverage_section += f"- **Year Breakdown:** {', '.join([f'{year}: {count}' for year, count in sorted(stats['year_counts'].items())])}\n"
        
        if stats['severity_counts']:
            severity_str = ', '.join([f'{sev}: {count}' for sev, count in sorted(stats['severity_counts'].items(), key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x[0].lower(), 5))])
            coverage_section += f"- **Severity Distribution:** {severity_str}\n"
        
        if stats['avg_cvss']:
            coverage_section += f"- **Average CVSS Score:** {stats['avg_cvss']:.1f}\n"
            coverage_section += f"- **Critical (CVSS ≥9.0):** {stats['critical_count']} templates\n"
            coverage_section += f"- **High (CVSS 7.0-8.9):** {stats['high_count']} templates\n"
        
        if stats['verified_count'] > 0:
            coverage_section += f"- **Verified Templates:** {stats['verified_count']}\n"
        
        if stats['cisa_kev_count'] > 0:
            coverage_section += f"- **CISA KEV Listed:** {stats['cisa_kev_count']}\n"
        
        if stats['most_recent']:
            coverage_section += f"- **Most Recent:** {stats['most_recent']}\n"
        
        if stats['oldest']:
            coverage_section += f"- **Oldest:** {stats['oldest']}\n"
        
        coverage_section += "\n"
        
        # Replace the coverage section
        content = re.sub(coverage_pattern, coverage_section + r'\3', content, flags=re.DOTALL)
    
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
