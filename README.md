# PortWeft

PortWeft is a lightweight wrapper around Nmap for authorized service discovery
and structured output, not exploitation.

It runs an initial scan, parses Nmap XML results, and performs low-noise
follow-up checks to extract useful service data such as versions, banners,
headers, and protocol details.

## What It Is

PortWeft is recon tooling for owned systems, labs, CTFs, and explicitly
authorized pentests.

It accepts IPs, domains, and CIDRs; runs Nmap; consolidates the results; and
writes clean per-host and cumulative reports in text or JSON.

## Why It Exists

The edge is clean, service-aware discovery without turning recon into an attack
chain.

PortWeft is built around:

- low-noise defaults
- banner-first service matching
- targeted follow-up scans only for observed services
- structured reports that are easier to review or pipe into other tooling
- optional low-noise Impacket recon for SMB/RPC when explicitly requested

## What It Does

- Accepts IPs, domains, comma-separated targets, and CIDRs
- Resolves domains before scanning
- Runs Nmap and parses XML automatically
- Performs targeted follow-up scans per service
- Produces clean text or JSON reports
- Optionally runs allowlisted Impacket recon for SMB/RPC

## What It Does Not Do

- No CVE lookups
- No exploitation
- No brute forcing
- No credential attacks
- No intrusive scans by default

This is recon only.

## Quick Usage

```bash
python3 -m portweft 192.0.2.10
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

## Requirements

- Python 3.10+
- Nmap on `PATH`
- Optional: Impacket with `python3 -m pip install ".[impacket]"`

## Output

Reports are written to:

```text
output/reports/<timestamp>/
```

Each run generates per-host reports and a cumulative report. An example report
is available at [examples/sample-report.txt](examples/sample-report.txt).

## Documentation

Full docs:

- [Usage](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Profiles](docs/profiles.md)
- [Safety And UDP Behavior](docs/safety.md)
- [Error Handling](docs/errors.md)
- [Testing](docs/testing.md)
