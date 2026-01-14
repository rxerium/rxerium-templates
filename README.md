# @rxerium Nuclei Templates

A curated collection of **74+ Nuclei templates** by [@rxerium](https://github.com/rxerium), focusing exclusively on **zero-day and actively exploited vulnerabilities in the wild**.

***This repo is in active development**.*

The main Nuclei templates repository can be found [here](https://github.com/projectdiscovery/nuclei-templates).

## Focus
This repository prioritises real-world threats that are being actively exploited, helping security teams detect and respond to the most critical vulnerabilities.

## Notes
- The scripts in this repo focus on passive detection techniques only (version / date matching).
- Date matching may / may not be as reliable as version detection so please proceed with caution when running these types of templates. 

## Coverage
- **73 CVE templates** spanning 2020-2026
- **1 template in progress**
- Organised by year for easy navigation
- Regular updates as new threats emerge

### Statistics
- **Total Templates:** 74
- **Year Breakdown:** 2020: 3, 2021: 3, 2022: 2, 2023: 9, 2024: 9, 2025: 44, 2026: 4
- **Severity Distribution:** critical: 38, high: 14, medium: 21, low: 1
- **Average CVSS Score:** 8.1
- **Critical (CVSS ≥9.0):** 34 templates
- **High (CVSS 7.0-8.9):** 15 templates
- **Verified Templates:** 74
- **CISA KEV Listed:** 29
- **Most Recent:** CVE-2026-22794
- **Oldest:** CVE-2020-12641


## Usage
Use with [Nuclei](https://github.com/projectdiscovery/nuclei):
```bash
nuclei -t rxerium-templates/ -u https://target.com
```

## Honorable Mentions

Scripts created by @rxerium have been cited / referenced in various security research articles and vulnerability reports such as the [NCSC](https://ctoatncsc.substack.com/p/cto-at-ncsc-summary-week-ending-september-021), [SonicWall](https://www.sonicwall.com/blog/deserialization-leads-to-command-injection-in-goanywhere-mft-cve-2025-10035), [NVD NIST](https://nvd.nist.gov/vuln/detail/cve-2023-40000), [Censys](https://censys.com/advisory/cve-2025-52691), [Darkwebinformer](https://x.com/DarkWebInformer/status/1957855818457440700) and many more. 

## Disclaimer
These templates are for authorised security testing only. Always obtain proper permission before scanning.
