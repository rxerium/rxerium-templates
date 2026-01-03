# @rxerium Nuclei Templates

A curated collection of **69 Nuclei templates** by [@rxerium](https://github.com/rxerium), focusing exclusively on **zero-day and actively exploited vulnerabilities in the wild**.

***This repo is in active development**.*

The main Nuclei templates repository can be found [here](https://github.com/projectdiscovery/nuclei-templates).

## Focus
This repository prioritises real-world threats that are being actively exploited, helping security teams detect and respond to the most critical vulnerabilities.

## Notes
- The scripts in this repo focus on passive detection techniques only (version / date matching).
- Date matching may / may not be as reliable as version detection so please proceed with caution when running these types of templates. 

## Coverage
- **69 CVE templates** spanning 2020-2025
- Organised by year for easy navigation
- Regular updates as new threats emerge

## Usage
Use with [Nuclei](https://github.com/projectdiscovery/nuclei):
```bash
nuclei -t rxerium-templates/ -u https://target.com
```

## Honarable Mentions

Scripts created by @rxerium have been cited / referenced in various security research articles and vulnerability reports such as the [NCSC](https://ctoatncsc.substack.com/p/cto-at-ncsc-summary-week-ending-september-021), [SonicWall](https://www.sonicwall.com/blog/deserialization-leads-to-command-injection-in-goanywhere-mft-cve-2025-10035), [NVD NIST](https://nvd.nist.gov/vuln/detail/cve-2023-40000), [Censys](https://censys.com/advisory/cve-2025-52691), [Darkwebinformer](https://x.com/DarkWebInformer/status/1957855818457440700) and many more. 

## Disclaimer
These templates are for authorised security testing only. Always obtain proper permission before scanning.
