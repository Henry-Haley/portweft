# PortWeft

PortWeft is a lightweight recon orchestrator for authorized assessments. It
performs fast TCP port discovery, targeted Nmap service enumeration,
service-aware follow-up checks, optional Impacket reconnaissance, and optional
CVE-only Nuclei validation, then consolidates the results into clean text or
JSON reports.

## What It Is

PortWeft is recon tooling for owned systems, labs, CTFs, and explicitly
authorized pentests.

It accepts IPs, domains, and CIDRs and prints the cumulative report to STDOUT
while also saving cumulative and per-host reports. It is intentionally not a
full autonomous pentesting framework.

## Why It Exists

The edge is clean, service-aware discovery without turning recon into an attack
chain.

PortWeft is built around:

- low-noise defaults
- banner-first service matching
- targeted follow-up scans only for observed services
- structured reports that are easier to review or pipe into other tooling
- optional low-noise Impacket recon for SMB/RPC when explicitly requested
- optional Nuclei validation limited to CVE-tagged templates

## What It Does

- Accepts IPs, domains, comma-separated targets, and CIDRs
- Resolves domains before scanning
- Uses RustScan, Masscan, or Nmap for optional full TCP discovery
- Runs targeted Nmap enumeration only on each host's discovered TCP ports
- Parses Nmap XML as the authoritative service data
- Performs targeted follow-up scans per service
- Produces clean text or JSON reports
- Optionally runs allowlisted Impacket recon for SMB/RPC
- Optionally runs one CVE-tagged Nuclei validation pass
- Prints the cumulative report to STDOUT and automatically saves all reports

## What It Does Not Do

- No exploit automation
- No brute forcing or credential attacks
- No generic vulnerability-intelligence aggregation
- No arbitrary pentest-tool chaining
- Nuclei is deliberately limited to CVE-tagged validation

This is recon only.

## Quick Usage

```bash
python3 -m portweft 192.0.2.10
```

Complete opening-recon workflow:

```bash
portweft 192.0.2.10 --full
```

Multiple targets:

```bash
python3 -m portweft 192.0.2.10,example.com
```

Subnet:

```bash
python3 -m portweft 192.0.2.0/24
```

JSON output:

```bash
python3 -m portweft 192.0.2.10 --json
```

Dry run:

```bash
python3 -m portweft 192.0.2.10 --dry-run
```

All-port TCP discovery followed by targeted service enumeration:

```bash
python3 -m portweft 192.0.2.10 --discovery
```

Choose a discovery backend:

```bash
portweft 192.0.2.10 --discovery --discovery-backend rustscan
portweft 192.0.2.0/24 --discovery --discovery-backend masscan
```

CVE-only validation or pipeable JSON:

```bash
portweft 192.0.2.10 --nuclei
portweft 192.0.2.10 --full --json | jq .
```

## Requirements

- Python 3.10+
- Nmap on `PATH`
- Optional: RustScan for fast single-host discovery
- Optional: Masscan for broad/multi-host discovery
- Optional: Nuclei plus its template set for CVE-only validation
- Optional: Impacket with `python3 -m pip install ".[impacket]"`

## Output

Reports are written to:

```text
output/reports/<timestamp>/
```

Each run generates per-host reports and a cumulative report. Operational status
goes to STDERR; the same cumulative report saved on disk goes to STDOUT. An
example report is available at [examples/sample-report.txt](examples/sample-report.txt).

## Documentation

Full docs:

- [Usage](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Profiles](docs/profiles.md)
- [Safety And UDP Behavior](docs/safety.md)
- [Error Handling](docs/errors.md)
- [Testing](docs/testing.md)
