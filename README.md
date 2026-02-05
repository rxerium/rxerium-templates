# @rxerium Nuclei Templates

[![GitHub stars](https://img.shields.io/github/stars/rxerium/rxerium-templates?style=flat-square)](https://github.com/rxerium/rxerium-templates)
[![License](https://img.shields.io/github/license/rxerium/rxerium-templates?style=flat-square)](LICENSE)
[![Templates](https://img.shields.io/badge/templates-74+-blue?style=flat-square)](https://github.com/rxerium/rxerium-templates)
[![CISA KEV](https://img.shields.io/badge/CISA%20KEV-29-red?style=flat-square)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

A curated collection of **81+ Nuclei templates** focusing exclusively on **zero-day and actively exploited vulnerabilities in the wild**. Templates use passive detection techniques (version/date matching) and are organized by year for easy navigation.

> ⚠️ **Note:** Date matching may be less reliable than version detection. Use with caution.

## 📊 Statistics

<!-- Stats are auto-updated by GitHub Actions -->

- **Total Templates:** 81 (80 completed, 1 WIP)
- **Coverage:** 2020-2026 | **Avg CVSS:** 8.2 | **CISA KEV:** 29
- **Severity:** Critical: 45 | High: 14 | Medium: 21 | Low: 1
- **CVSS Breakdown:** Critical (≥9.0): 39 | High (7.0-8.9): 15
- **Year Distribution:** 2020: 3 | 2021: 3 | 2022: 2 | 2023: 9 | 2024: 9 | 2025: 47 | 2026: 8



## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/rxerium/rxerium-templates.git
cd rxerium-templates

# Or use directly with Nuclei
nuclei -t rxerium-templates/ -u https://target.com
```

### Examples

```bash
# Scan a single target
nuclei -t rxerium-templates/ -u https://example.com

# Scan with specific severity
nuclei -t rxerium-templates/ -u https://example.com -severity critical,high

# Scan specific year
nuclei -t rxerium-templates/2025/ -u https://example.com

# Bulk scan from file
nuclei -t rxerium-templates/ -l targets.txt
```

## 📚 Resources

- **Main Nuclei Templates:** [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- **Nuclei Documentation:** [docs.nuclei.sh](https://docs.nuclei.sh)

## 🏆 Recognition

Templates have been cited in security research from [NCSC](https://ctoatncsc.substack.com/p/cto-at-ncsc-summary-week-ending-september-021), [SonicWall](https://www.sonicwall.com/blog/deserialization-leads-to-command-injection-in-goanywhere-mft-cve-2025-10035), [NVD NIST](https://nvd.nist.gov/vuln/detail/cve-2023-40000), [Censys](https://censys.com/advisory/cve-2025-52691), and others.

## ⚖️ Disclaimer

These templates are for **authorized security testing only**. Always obtain proper permission before scanning.
