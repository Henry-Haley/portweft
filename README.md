# PortWeft

[![CI](https://github.com/Henry-Haley/portweft/actions/workflows/ci.yml/badge.svg)](https://github.com/Henry-Haley/portweft/actions/workflows/ci.yml)
![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

PortWeft is a lightweight opening-recon orchestrator for authorized
assessments. It combines fast TCP discovery, targeted Nmap service enumeration,
service-aware follow-ups, optional Impacket reconnaissance, and CVE-focused
Nuclei validation into structured text or JSON reports.

It keeps discovery, enrichment, and reporting in one reviewable workflow
without becoming an exploitation framework.

## Install

PortWeft requires Python 3.10+ and Nmap on `PATH`.

```bash
git clone https://github.com/Henry-Haley/portweft.git
cd portweft
python3 -m pip install .
portweft --help
```

RustScan, Masscan, Nuclei, and Impacket are optional. See the
[installation and usage guide](docs/usage.md) for their setup and platform
notes.

## Quick Start

```bash
portweft 192.0.2.10
portweft 192.0.2.10 --discovery
portweft 192.0.2.10 --full
portweft 192.0.2.10 --full --json | jq .
```

`--full` enables all-port TCP discovery, service-aware Nmap follow-ups,
allowlisted Impacket reconnaissance, and CVE-tagged Nuclei validation. It does
not disable the normal UDP companion scan or safety limits. Optional tools must
be installed before use.

## Pipeline

```text
TCP discovery
    ↓
targeted Nmap enumeration
    ↓
service-aware follow-ups
    ↓
optional Impacket / Nuclei
    ↓
structured report
```

Without `--discovery`, PortWeft starts with Nmap's normal port selection.
Operational messages go to STDERR; the final cumulative report goes to STDOUT
and is also saved with per-host reports. See the
[synthetic sample report](examples/sample-report.txt).

## Documentation

- [Documentation index](docs/README.md)
- [CLI usage and installation](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Service profiles](docs/profiles.md)
- [Safety and scan behavior](docs/safety.md)
- [Errors and exit behavior](docs/errors.md)
- [Testing](docs/testing.md)

## Responsible Use

Use PortWeft only on owned systems, labs, CTFs, and explicitly authorized
assessments. It does not automate exploitation, credential attacks, or brute
forcing. Review the full [security and responsible-use policy](SECURITY.md)
before scanning.
