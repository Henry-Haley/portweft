# Security Policy

PortWeft is an authorized reconnaissance helper. Use it only on systems you
own, administer, or have explicit permission to test.

## Project Boundaries

PortWeft is not intended to:

- exploit services
- brute force credentials
- perform password spraying
- bypass detection
- deliver payloads
- aggregate vulnerability intelligence
- provide attack recommendations

It runs scoped discovery, uses Nmap as the authoritative service source,
matches observed facts to low-noise profiles, optionally performs allowlisted
Impacket recon and CVE-tagged Nuclei validation, and writes reports. Nuclei
checks are active even when limited to CVE tags; Masscan rates and all targets
must remain within the approved rules of engagement.

## Reporting Security Issues

If you find a security issue in PortWeft itself, open a private report through
GitHub security advisories if available. If private reporting is not available,
open an issue with minimal detail and ask for a private contact path.

Please do not include live target data, credentials, exploit code, or sensitive
scan output in public issues.

## Responsible Use

Operators are responsible for scope control, authorization, scan timing,
network impact, and local laws or rules of engagement.
