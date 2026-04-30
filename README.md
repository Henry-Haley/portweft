# PortWeft

PortWeft is a lightweight Nmap orchestration and XML parsing tool for authorized
service reconnaissance. It takes one or more targets, runs an initial Nmap scan,
uses temporary XML output, parses open services, and then runs conservative
service-specific follow-up scans for useful facts such as versions, banners,
headers, protocol metadata, and basic service details.

PortWeft is not intended to be a vulnerability scanner. It does not perform CVE
lookups, exploit checks, brute force actions, or automated "next step" attack
recommendations.

## Scope

PortWeft focuses on:

- single IPs, comma-separated IPs, and CIDR ranges
- initial Nmap scan execution
- temporary XML output generation and parsing
- banner/service fingerprint matching and rough OS-family inference
- Windows, Unix/Linux, and web-oriented service profiles
- low-noise Nmap follow-up scans
- optional low-noise Impacket recon for matched SMB/RPC services
- custom Nmap argument passthrough where it fits the workflow
- progress prints while the tool runs
- final text reports with the gathered service facts

Out of scope:

- vulnerability identification
- CVE database lookups
- exploit recommendations
- credential attacks
- brute forcing
- intrusive NSE scripts by default
- internet lookups
- Impacket exploitation, relay, dumping, or brute-force tooling

## Requirements

- Python 3.10+
- Nmap available on `PATH`
- Optional: Impacket for `--impacket` recon modules

No Python packages are required for normal use. When `--impacket` is provided,
PortWeft imports Impacket for that optional phase. If the package is missing,
PortWeft prints `Install with pip install .[impacket]` and exits without
starting the scan.

Manual optional Impacket package install from the source tree:

```bash
python3 -m pip install ".[impacket]"
```

PortWeft is OS-neutral Python and is intended to run on Linux, macOS, and
Windows. Linux usage is the primary path; Windows is supported for development
and execution.

## Documentation

Longer-form docs live in [docs/](docs/README.md):

- [Usage](docs/usage.md)
- [Architecture](docs/architecture.md)
- [First Release Scope](docs/scope.md)
- [Profiles](docs/profiles.md)
- [Safety And UDP Behavior](docs/safety.md)
- [Error Handling](docs/errors.md)
- [Testing](docs/testing.md)

Project policy files:

- [License](LICENSE)
- [Security Policy](SECURITY.md)

## Project Layout

```text
pyproject.toml
  Package metadata and the optional `portweft` console entrypoint.

portweft.py
  Thin compatibility launcher for the CLI.

portweft/
  __main__.py
    Enables `python -m portweft`.

  cli.py
    Argument parsing and top-level workflow.

  models.py
    Host and service observation objects.

  nmap_runner.py
    Nmap command construction, passthrough handling, and execution.

  impacket_runner.py
    Optional allowlisted Impacket recon command construction and execution.

  nmap_xml.py
    Nmap XML parsing, OS inference, script output parsing, and result merging.

  profiles.py
    Built-in service profiles and conservative NSE script selections.

  matcher.py
    Maps parsed services to matching follow-up profiles. Banner and service
    evidence are preferred; port numbers are fallback hints.

  reporting.py
    Writes per-host and cumulative text reports.

  utils.py
    Progress printing, command display, safe filenames, and formatting helpers.
```

## Example Usage

Print syntax/help:

```bash
python3 portweft
python3 -m portweft
python3 -m portweft -h
```

Run the default scan against one host:

```bash
python3 -m portweft 192.0.2.10
```

Scan a comma-separated target list:

```bash
python3 -m portweft 192.0.2.10,192.0.2.11
```

Scan a subnet:

```bash
python3 -m portweft 192.0.2.0/24
```

Specify ports:

```bash
python3 -m portweft 192.0.2.10 -p 22,80,443,445
```

Pass Nmap timing or host-discovery flags through to Nmap:

```bash
python3 -m portweft 192.0.2.10 -T4 -Pn
```

Pass a quoted Nmap argument string:

```bash
python3 -m portweft 192.0.2.10 --nmap-args "-T4 -Pn --max-retries 2"
```

Or place raw Nmap flags after PortWeft options:

```bash
python3 -m portweft 192.0.2.10 --dry-run -- -T4 -Pn --max-retries 2
```

Preview commands without running scans:

```bash
python3 -m portweft 192.0.2.10 -p 22,80,443 --dry-run
```

Run optional allowlisted Impacket recon for matched SMB/RPC services:

```bash
python3 -m portweft 192.0.2.10 --impacket
```

Keep only the newest output runs:

```bash
python3 -m portweft 192.0.2.10 --keep-runs 10
```

Adjust the retained NSE script output per script:

```bash
python3 -m portweft 192.0.2.10 --max-script-output-chars 4096
```

Disable the default UDP companion scan:

```bash
python3 -m portweft 192.0.2.10 --no-udp
```

Override the UDP companion scan ports:

```bash
python3 -m portweft 192.0.2.10 --udp-ports 53,123,161
```

On Windows, use whichever Python launcher is available:

```powershell
python -m portweft 192.0.2.10
```

If Nmap is installed but not on `PATH`, pass it explicitly:

```powershell
python -m portweft 192.0.2.10 --nmap-path "C:\Program Files (x86)\Nmap\nmap.exe"
```

After installing the package locally, the console entrypoint can be used:

```bash
portweft 192.0.2.10
```

An example report is available at [examples/sample-report.txt](examples/sample-report.txt).

## Output

PortWeft writes run output under:

```text
output/
  reports/
    <run-start-gmt>/
      CUMULATIVE-report.txt
      <host>-report.txt
```

Nmap XML files are timestamped with the GMT scan start time while the run is in
progress, then removed after the consolidated reports are written. Reports note
that temporary XML was removed, but do not reference deleted XML paths. Each
responding host gets its own `<host>-report.txt`; hosts with no observed
response do not get a report. `CUMULATIVE-report.txt` includes every responding
host from the run. Dry-run mode only prints planned commands and does not write
files.

The terminal also prints progress while the run is happening. Examples of the
screen output include:

```text
Initial Nmap scan complete: XML saved to output/scans/<run>/<run>-initial.xml
Initial XML parse complete
OS identified: 192.0.2.10 -> Linux 5.4 - 5.15 (93% accuracy)
Open ports for 192.0.2.10:
  22/tcp ssh OpenSSH 8.9p1 Ubuntu
  443/tcp https nginx 1.24.0
Follow-up profile web complete: 192.0.2.10:443/tcp
Impacket samrdump complete: 192.0.2.11:445/tcp
Report writing complete: 3 file(s) in output/reports/<run>
```

## Testing

PortWeft uses the Python standard library `unittest` runner:

```bash
python3 -m unittest discover -v
```

The test suite uses local XML fixtures and mocks for command failures, so it
does not require live network scanning.

## Matching Behavior

PortWeft is banner-first by default. Nmap service detection is enabled with
`-sV --version-light` unless disabled, and profile matching prefers evidence
from:

- Nmap service name
- product and version fields
- extra service information
- SSL/TLS tunnel metadata
- NSE script output gathered by earlier scans
- optional Impacket recon output gathered by matched profiles

Port numbers are still used, but only as fallback hints when the banner or
service fingerprint does not clearly identify the service. This allows
non-standard ports to be handled correctly, such as SSH on `2222`, HTTP on
`9000`, or SMB-like services exposed away from `445`.

Current built-in profiles cover:

```text
dhcp, dns, docker, elasticsearch, ftp, ike, imap, kerberos, kubernetes,
ldap, memcached, mongodb, mssql, mysql, nfs, ntp, pop3, postgres, rdp,
redis, rpc, rsync, smb, smtp, snmp, ssdp, ssh, syslog, telnet, tftp, tls,
vnc, web, winrm
```

When PortWeft observes service evidence but cannot match it to a follow-up
profile, it prints that fact instead of failing. The service still appears in
the final report with its observed banner/version information.

## UDP Behavior

PortWeft runs a small UDP companion scan by default for UDP-first or
UDP-centric services such as DNS, DHCP, TFTP, NTP, SNMP, Kerberos, NetBIOS,
IKE/IPsec, Syslog, MSSQL Browser, SSDP, NFS/RPC, and Memcached. UDP scan
failures are non-fatal; if Nmap reports a privilege, driver, or flag error,
PortWeft prints the Nmap message and continues with available TCP results.
TCP-only scan flags and conflicting port-selection flags are filtered out of
the UDP companion command.

UDP follow-up scans are only generated for services that Nmap reports as open
UDP services.

## Error Handling

Expected runtime failures are caught and printed cleanly:

- Nmap missing or not on `PATH`
- malformed user-provided Nmap argument strings
- passthrough output flags that conflict with PortWeft-managed XML
- Nmap returning an error for invalid flags or unsupported scan options
- malformed or unreadable Nmap XML
- report write failures
- follow-up XML parse failures

## Safety Defaults

The default behavior is intentionally conservative:

- Nmap XML output is controlled by PortWeft so results can be parsed reliably.
- Service version detection uses light probing unless the user provides their
  own Nmap flags.
- Follow-up scans are selected only for services that were observed open.
- Follow-up scans are batched by host, protocol, and service profile.
- Follow-up scripts are limited to basic information-gathering NSE scripts.
- Optional Impacket modules are limited to allowlisted recon commands.
- NSE script output retained in memory and reports is capped.
- Impacket output retained in memory and reports is capped.
- No vulnerability scripts are selected by default.
- `--dry-run` shows the exact commands before execution.
