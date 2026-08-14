# PortWeft Documentation

This folder contains the in-depth PortWeft documentation. The root
`README.md` is intentionally short: what PortWeft is, why it exists, and how
to run it quickly. Everything else lives here.

## Contents

- [Usage](usage.md): target formats, ports, Nmap passthrough, JSON reports,
  discovery backends, Impacket/Nuclei recon, output files, and run examples.
- [Architecture](architecture.md): workflow, modules, report generation, and
  error handling structure.
- [First Release Scope](scope.md): what v1.0 is meant to include and exclude.
- [Profiles](profiles.md): service profile matching and follow-up coverage.
- [Safety And UDP Behavior](safety.md): default network behavior, UDP handling,
  and safe operating practices.
- [Error Handling](errors.md): expected failures, exit behavior, and user-facing
  error messages.
- [Testing](testing.md): test layout, commands, fixtures, and release checks.

## Project Intent

PortWeft is a lightweight opening-recon orchestrator for authorized
assessments. It combines fast TCP discovery, targeted Nmap XML enumeration,
focused service-aware follow-ups, optional allowlisted Impacket recon, and
optional CVE-tagged Nuclei validation. It does not automate exploitation,
credential attacks, brute force, or arbitrary pentest-tool chains.

## Quick Links

- Example report: [../examples/sample-report.txt](../examples/sample-report.txt)
- License: [../LICENSE](../LICENSE)
- Security policy: [../SECURITY.md](../SECURITY.md)
