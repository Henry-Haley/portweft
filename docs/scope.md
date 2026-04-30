# First Release Scope

This document defines the intended scope for the first usable PortWeft release.

## In Scope

- Run Nmap against one or more user-provided targets.
- Resolve domain targets to IP addresses before scanning.
- Use temporary Nmap XML output for parsing.
- Parse hosts, open services, versions, banners, script output, and rough OS
  hints.
- Prefer banner/service evidence over port numbers when matching profiles.
- Use port numbers as fallback hints.
- Run conservative service-specific Nmap follow-up scans.
- Optionally run allowlisted Impacket recon modules for matched SMB/RPC
  services.
- Run a small UDP companion scan by default.
- Run low-noise banner grabbing during the initial TCP scan.
- Print progress to screen.
- Write per-host and cumulative plain text or JSON reports.
- Support Linux, macOS, and Windows.
- Use only the Python standard library plus Nmap for normal operation.

## Out Of Scope

- CVE lookup.
- Vulnerability claims.
- Exploit checks.
- Brute force scripts.
- Credential attacks.
- Password spraying.
- Impacket exploitation, relay, dumping, or brute-force tooling.
- Internet enrichment lookups beyond DNS resolution.
- Payload delivery.
- Post-exploitation.
- Evasion features.

## First Release Definition

The first release is a structured Nmap wrapper and XML parser. It should help
operators turn Nmap output into organized service facts. It should not decide
whether a service is vulnerable or recommend offensive next steps.

## Known Limitations

- UDP scans may require elevated privileges or packet capture drivers.
- Nmap OS detection may be missing, uncertain, or wrong.
- Banner matching is heuristic and can be imperfect.
- Follow-up coverage depends on locally available Nmap scripts.
- Optional Impacket recon requires the operator to install the optional package
  ahead of time, plus locally available Impacket console tools.
- Service detection depends on Nmap probe quality and target behavior.
- JSON reports are structured, but intentionally limited to observed scan data.
- Profile definitions are currently built into `portweft/profiles.py`.

## Release Checklist

- `python3 -m unittest discover -v`
- `python3 -m compileall portweft.py portweft tests`
- `git diff --check`
- Confirm README quick-start examples are current.
- Confirm profile docs match `portweft/profiles.py`.
