# PortWeft Documentation

This folder contains the in-depth PortWeft documentation. The root
`README.md` is intentionally short: what PortWeft is, why it exists, and how
to run it quickly. Everything else lives here.

## Contents

- [Usage](usage.md): target formats, ports, Nmap passthrough, JSON reports,
  Impacket recon, output files, and run examples.
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

PortWeft is a lightweight Nmap XML orchestration tool for authorized service
reconnaissance. It gathers service facts and organizes them. Optional Impacket
support is limited to allowlisted recon modules. PortWeft does not identify
vulnerabilities, check CVEs, brute force credentials, exploit services, or
provide attack recommendations.

## Quick Links

- Example report: [../examples/sample-report.txt](../examples/sample-report.txt)
- License: [../LICENSE](../LICENSE)
- Security policy: [../SECURITY.md](../SECURITY.md)
