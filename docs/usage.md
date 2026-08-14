# Usage

PortWeft is intended to run on Linux, macOS, and Windows. Linux is the primary
runtime target.

## Requirements

- Python 3.10+
- Nmap available on `PATH`
- Optional: RustScan on `PATH` for fast single-host TCP discovery
- Optional: Masscan for broad/multi-host TCP discovery
- Optional: Nuclei and its templates for CVE-only validation
- Optional: Impacket for `--impacket` recon modules

No Python packages are required for normal use. Impacket is only needed when
optional Impacket recon is enabled.

## Installation

### Direct From The Source Tree

This is the simplest option and requires no pip installation:

```bash
git clone https://github.com/Henry-Haley/portweft.git
cd portweft
python3 -m portweft --help
```

Run PortWeft from the outer repository root:

```text
portweft/                 ← run commands here
├── README.md
├── pyproject.toml
├── portweft/             ← Python package; do not cd here
└── tests/
```

### pipx

If `pipx` is available and you want a global `portweft` command:

```bash
pipx install .
portweft --help
```

### Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
portweft --help
```

Current Kali and Debian releases may reject pip installs outside an isolated
environment under PEP 668. Use direct source execution, pipx, or a virtual
environment; do not bypass the protection with `--break-system-packages`.

For optional Impacket reconnaissance, install the extra with pipx or inside the
activated virtual environment:

```bash
pipx install ".[impacket]"
# or, inside .venv:
python3 -m pip install ".[impacket]"
```

## Run From The Source Tree

Linux and macOS:

```bash
python3 -m portweft 192.0.2.10
```

Print syntax/help:

```bash
python3 portweft
python3 -m portweft
python3 -m portweft -h
```

Windows:

```powershell
python -m portweft 192.0.2.10
```

The legacy root launcher also works:

```bash
python3 portweft.py 192.0.2.10
```

## Full Opening Recon

The convenience profile enables full TCP discovery, existing service-aware
Nmap follow-ups, allowlisted Impacket recon, and CVE-only Nuclei validation:

```bash
portweft 192.0.2.10 --full
```

It is equivalent to `--discovery --impacket --nuclei`. It does not change UDP
defaults, target-count safety limits, or raw Nmap passthrough behavior.
`--full --no-follow-up` is rejected because it contradicts the profile.

## Target Formats

Single target:

```bash
python3 -m portweft 192.0.2.10
```

Domain target:

```bash
python3 -m portweft example.com
```

PortWeft resolves domain names with `socket.getaddrinfo()` before scanning,
passes resolved IP addresses to Nmap, and keeps the original domain name in
reports. DNS failures are logged, skipped, and do not stop other targets.

Comma-separated targets:

```bash
python3 -m portweft 192.0.2.10,example.com
```

CIDR range:

```bash
python3 -m portweft 192.0.2.0/24
```

By default, domains with multiple DNS answers use the first address returned.
To scan every returned IPv4/IPv6 address:

```bash
python3 -m portweft example.com --resolve-mode all
```

## TCP Ports

Specify ports:

```bash
python3 -m portweft 192.0.2.10 -p 22,80,443,445
python3 -m portweft 192.0.2.10 -p 1-1024,8080
python3 -m portweft 192.0.2.10 -p-
```

Port lists accept comma-separated ports, dash ranges, and Nmap's all-ports
`-p-` shorthand.

Use Nmap's default top ports, or specify a count:

```bash
python3 -m portweft 192.0.2.10 --top-ports
python3 -m portweft 192.0.2.10 --top-ports 100
python3 -m portweft 192.0.2.10 --top-ports 1000
```

If neither `-p` nor `--top-ports` is provided, PortWeft lets Nmap use its
default TCP port selection.

The initial TCP scan automatically includes Nmap service detection and the
low-noise NSE `banner` script. If you pass your own `--script` expression,
PortWeft adds `banner` to it instead of replacing it.

## All-Port Discovery

Discover open TCP ports across the full port range, then run service detection
separately for only the ports found on each host:

```bash
python3 -m portweft 192.0.2.10 --discovery
```

Discovery produces a normalized per-host port map. Each host with open TCP
ports then gets its own explicit `-sV --version-light` and `banner` Nmap scan
against only those ports before normal profile follow-ups. Hosts with a failed
detailed scan do not stop other hosts. UDP companion scanning is unchanged.
`--discovery` cannot be combined with `-p/--ports` or `--top-ports`.

Backend selection defaults to `auto`:

- one resolved host: RustScan when available, otherwise Nmap
- multiple resolved hosts or a network: Masscan when available, otherwise Nmap

Choose explicitly:

```bash
python3 -m portweft 192.0.2.10 --discovery --discovery-backend rustscan
python3 -m portweft 192.0.2.0/24 --discovery --discovery-backend masscan
python3 -m portweft 192.0.2.10 --discovery --discovery-backend nmap
```

Explicitly selected missing tools cause a controlled error; only `auto` falls
back. RustScan must be on `PATH` for explicit RustScan discovery unless its
executable is supplied with `--rustscan-path`. Override Masscan similarly with
`--masscan-path`.
Masscan defaults to 1000 packets/second:

```bash
portweft 192.0.2.0/24 --discovery --discovery-backend masscan --masscan-rate 2000
```

## Nmap Passthrough

PortWeft accepts raw Nmap options after its own arguments:

```bash
python3 -m portweft 192.0.2.10 -- -T4 -Pn --max-retries 2
python3 -m portweft --max-retries 2 192.0.2.10 --dry-run
```

Or through `--nmap-args` as separate tokens or a quoted string:

```bash
python3 -m portweft 192.0.2.10 --nmap-args -T4 -Pn
python3 -m portweft 192.0.2.10 --nmap-args "-T4 -Pn --max-retries 2"
```

Malformed `--nmap-args` strings fail before a scan starts. PortWeft validates
common passthrough timing and concurrency value types early, while still
leaving raw Nmap scan choices to the operator.

PortWeft owns Nmap output flags so XML remains parseable. Do not pass `-oX`,
`-oA`, `-oN`, `-oG`, `-oS`, or `--webxml`. Use `--output-dir` instead.

## UDP Options

PortWeft runs a small UDP companion scan by default for UDP-first and
UDP-centric services.

When `-p/--ports` is used, the UDP companion scan is narrowed to only the
requested ports that overlap PortWeft's curated UDP defaults. For example,
`-p 445` skips UDP, while `-p 53,445` runs UDP only for `53`. An explicit
`--udp-ports` value still runs those UDP ports unless `--no-udp` is also set.

Disable it:

```bash
python3 -m portweft 192.0.2.10 --no-udp
```

Override the UDP port list:

```bash
python3 -m portweft 192.0.2.10 --udp-ports 53,123,161
```

UDP scans may require elevated privileges or Npcap/libpcap support depending on
the OS. If Nmap rejects the UDP scan, PortWeft prints Nmap's message and
continues with the TCP results.

The UDP companion scan filters TCP-only scan flags and conflicting
port-selection passthrough flags such as `-sS`, `-sT`, `-PA`, `-PS`, `-p`,
`--top-ports`, `--scanflags`, and passthrough NSE script flags.

## Dry Run

Preview commands without scanning:

```bash
python3 -m portweft 192.0.2.10 -p 22,80,443 --dry-run -- -T4 -Pn
```

Dry-run mode prints planned discovery and known Nmap commands to STDERR, notes
the downstream Nmap/Impacket/Nuclei stages whose targets are not known yet, and
does not write output files.

## JSON Reports

Write structured JSON reports instead of formatted text:

```bash
python3 -m portweft 192.0.2.10 --json
```

STDOUT contains one valid JSON document and operational progress stays on
STDERR, so piping is safe:

```bash
portweft 192.0.2.10 --full --json | jq .
```

JSON reports include targets, DNS resolution details, host information,
services, matched profiles, NSE results, and Impacket results when present.
They also include structured Nuclei findings and high-level stage statuses. The
report files and STDOUT contain only JSON data.

## Optional Impacket Recon

PortWeft can run allowlisted Impacket recon modules after matched Nmap
follow-ups:

```bash
python3 -m portweft 192.0.2.10 --impacket
```

The current allowlist is limited to:

```text
samrdump, rpcdump
```

These modules only run for supported open TCP services in matching profiles,
such as SMB and Microsoft RPC. PortWeft imports the Impacket Python package
only when `--impacket` is used. If the package is missing, PortWeft exits with:

```text
Install with pip install .[impacket]
```

Matching Impacket console tools are still best-effort. If a tool is missing
after the Python package is available, PortWeft prints a skip message for that
module and continues.

Limit retained Impacket output per module:

```bash
python3 -m portweft 192.0.2.10 --impacket --max-impacket-output-chars 4096
```

## Optional Nuclei CVE Validation

Run one Nuclei process against unique targets constructed from Nmap-enriched TCP
services:

```bash
portweft 192.0.2.10 --nuclei
portweft 192.0.2.10 --discovery --nuclei
```

PortWeft always supplies `-tags cve` and JSONL output controls. It does not
enable automatic scan selection, exposure/misconfiguration/technology scans,
fuzzing, AI, code, or headless modes. HTTP services become explicit URLs with
their observed ports; other TCP services use host/port targets; UDP is excluded.
Use `--nuclei-path` for a non-default executable. Missing Nuclei fails preflight;
a later timeout or non-zero exit is recorded as a partial stage failure and
does not discard the other results.

## Output Retention

Keep only the newest completed output runs:

```bash
python3 -m portweft 192.0.2.10 --keep-runs 10
```

The default is `0`, which keeps all existing output.

## Scan Limits

Each external scanner command has a PortWeft timeout by default:

```bash
python3 -m portweft 192.0.2.10 --scan-timeout 900
```

Use `--scan-timeout 0` to disable the PortWeft-managed subprocess timeout.

Long stages emit an elapsed heartbeat to STDERR every five seconds. Change or
disable it with:

```bash
portweft 192.0.2.10 --full --stats-every 10
portweft 192.0.2.10 --full --stats-every 0
```

PortWeft blocks large target expansions by default. Use an explicit override
when the range is in scope:

```bash
python3 -m portweft 10.0.0.0/16 --allow-large-scan
python3 -m portweft 10.0.0.0/16 --max-scan-targets 70000
```

## Script Output Cap

PortWeft keeps NSE script output bounded in memory and reports. Override the
per-script retained character count:

```bash
python3 -m portweft 192.0.2.10 --max-script-output-chars 4096
```

## Nmap Path

If Nmap is not on `PATH`, provide the executable explicitly:

```bash
python3 -m portweft 192.0.2.10 --nmap-path /usr/bin/nmap
```

Windows example:

```powershell
python -m portweft 192.0.2.10 --nmap-path "C:\Program Files (x86)\Nmap\nmap.exe"
```

PortWeft also checks common Windows Nmap installation paths when `--nmap-path`
is left as `nmap`.

## Output Files

Run files are written under:

```text
output/
  reports/
    <run-start-gmt>/
      CUMULATIVE-report.txt
      <host>-report.txt
```

With `--json`:

```text
output/
  reports/
    <run-start-gmt>/
      CUMULATIVE-report.json
      <host>-report.json
```

Nmap XML files are temporary working files under `output/scans/<run-start-gmt>/`
while the run is active. Their names include the GMT scan start timestamp, and
PortWeft removes them after the final reports are written. Reports note that
temporary XML was removed, but do not reference deleted XML paths. Each
responding host gets one report named after the host address, and
`CUMULATIVE-report.txt` contains all responding hosts from the run. The report
keeps Nmap open-port and NSE output separate from the `IMPACKET RESULTS:`
and `NUCLEI CVE RESULTS:` sections. The cumulative file is also printed
byte-for-byte to STDOUT after completion; status, commands, warnings, and errors
go to STDERR. If `--impacket` was not used, that section explicitly reports
`Status: not requested (--impacket not used)`. Reruns create a new timestamped
report directory instead of overwriting existing host reports. If temporary
XML cleanup fails after reports are written, PortWeft warns but keeps the run
successful.
