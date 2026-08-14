# First Release Scope

This document defines the intended scope for the first usable PortWeft release.

## In Scope

- Run Nmap against one or more user-provided targets.
- Optionally discover all TCP ports with RustScan, Masscan, or Nmap and
  normalize the result before targeted Nmap enumeration.
- Resolve domain targets to IP addresses before scanning.
- Use temporary Nmap XML output for parsing.
- Parse hosts, open services, versions, banners, script output, and rough OS
  hints.
- Prefer banner/service evidence over port numbers when matching profiles.
- Use port numbers as fallback hints.
- Run conservative service-specific Nmap follow-up scans.
- Optionally run allowlisted Impacket recon modules for matched SMB/RPC
  services.
- Optionally run Nuclei once against observed TCP services using CVE-tagged
  templates only.
- Run a small UDP companion scan by default.
- Run low-noise banner grabbing during the initial TCP scan.
- Print operational progress to STDERR.
- Print the cumulative report to STDOUT and save per-host/cumulative text or
  JSON reports.
- Support Linux, macOS, and Windows.
- Use only the Python standard library plus Nmap for normal operation.

## Out Of Scope

- Generic vulnerability-intelligence aggregation.
- Exploit automation.
- Brute force scripts.
- Credential attacks.
- Password spraying.
- Impacket exploitation, relay, dumping, or brute-force tooling.
- Internet enrichment lookups beyond DNS resolution.
- Payload delivery.
- Post-exploitation.
- Evasion features.
- Nuclei exposure, misconfiguration, technology-only, fuzzing, AI, code, or
  headless modes.

## First Release Definition

PortWeft is an opening-recon orchestrator, not an autonomous pentesting
framework. It finds TCP ports, asks Nmap what is running, performs its focused
service-aware checks, optionally asks Impacket and CVE-filtered Nuclei for
additional observations, and stops at a consolidated report.

## Known Limitations

- UDP scans may require elevated privileges or packet capture drivers.
- Nmap OS detection may be missing, uncertain, or wrong.
- Banner matching is heuristic and can be imperfect.
- Follow-up coverage depends on locally available Nmap scripts.
- Optional Impacket recon requires the operator to install the optional package
  ahead of time, plus locally available Impacket console tools.
- RustScan, Masscan, and Nuclei are external installations; auto discovery
  falls back to Nmap when RustScan or Masscan is unavailable.
- Masscan may require elevated/raw-socket privileges and can produce substantial
  traffic if `--masscan-rate` is raised.
- Nuclei findings are validation leads, not proof that exploitation is safe or
  appropriate.
- Service detection depends on Nmap probe quality and target behavior.
- JSON reports are structured, but intentionally limited to observed scan data.
- Profile definitions are currently built into `portweft/profiles.py`.

## Release Checklist

- `python3 -m unittest discover -v`
- `python3 -m compileall portweft.py portweft tests`
- `git diff --check`
- Confirm README quick-start examples are current.
- Confirm profile docs match `portweft/profiles.py`.
