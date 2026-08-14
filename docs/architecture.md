# Architecture

PortWeft is intentionally small and standard-library only. Nmap is required;
RustScan, Masscan, Impacket, and Nuclei are optional external tools.

## Flow

```text
targets
   |
discovery backend
  / | \
rust masscan nmap
   |
normalized open-port map
   |
targeted Nmap XML enumeration
   |
service-aware follow-ups
  / \
Impacket Nuclei (CVE only)
  \ /
normalized HostObservation/report data
   |
STDOUT + saved cumulative/per-host reports
```

Without `--discovery`, the ordinary initial Nmap workflow remains in place.
The small UDP companion scan is independent and remains enabled unless
`--no-udp` is used. Progress and errors go to STDERR; only the final cumulative
document goes to STDOUT.

## Modules

```text
portweft.py
  Compatibility launcher.

portweft/__main__.py
  Enables `python -m portweft`.

portweft/cli.py
  Argument parsing and the main workflow.

portweft/models.py
  DiscoveryResult, HostObservation, ServiceObservation, and NucleiFinding
  dataclasses.

portweft/discovery_runner.py
  Backend selection, RustScan greppable parsing, Masscan list parsing, and the
  normalized per-host open TCP port map.

portweft/nmap_runner.py
  Nmap command construction, passthrough validation, executable discovery,
  automatic banner script handling, subprocess execution, and Nmap error
  extraction.

portweft/impacket_runner.py
  Optional lazy Impacket package import, recon module allowlist, executable
  discovery, bounded subprocess output capture, and command construction.

portweft/nuclei_runner.py
  Nmap-enriched target construction, CVE-only command construction, streaming
  JSONL parsing, finding deduplication, and host attachment.

portweft/process_runner.py
  Shared subprocess timeout, Ctrl+C termination, and periodic heartbeat waits.

portweft/nmap_xml.py
  Streaming Nmap XML parsing, OS inference, bounded script-output extraction,
  and result merging.

portweft/profiles.py
  Built-in profile definitions, fallback ports, UDP ports, banner terms, and
  conservative NSE script selections.

portweft/matcher.py
  Banner-first service-to-profile matching.

portweft/reporting.py
  Per-host and cumulative text/JSON rendering, including structured Nuclei
  findings.

portweft/targets.py
  Domain resolution, scan target expansion, and original-target host annotation.

portweft/errors.py
  Expected runtime exceptions with stable exit codes.

portweft/utils.py
  Console printing, command display, safe filenames, and formatting helpers.
```

## Matching Model

Matching prefers service evidence over ports:

1. Nmap service name
2. Product and version fields
3. Extra service info
4. TLS tunnel metadata
5. NSE script names and script output
6. Optional Impacket recon output
7. TCP or UDP fallback ports

This lets PortWeft catch common non-standard deployments, such as SSH on
`2222`, HTTP on `9000`, or SMB/Samba on a non-standard TCP port.

If a banner or service string exists but no profile matches it, PortWeft prints
a progress message and keeps the service in the final report.

## Result Merging

Discovery backends produce only a normalized address-to-TCP-ports map. Each
address with discovered ports then receives a targeted Nmap service scan, and
Nmap XML remains the authoritative structured service source. UDP and Nmap
follow-up XML are merged into the same host list. Impacket results remain on
compatible services; Nuclei findings are first-class host data because a
finding may identify an endpoint differently from Nmap.

Domain names are resolved before scanning. CIDR attribution uses `ipaddress`
membership checks, so individual discovered addresses retain their original
network target without expanding the network in memory.

The merge key for services is:

```text
(protocol, port)
```

This keeps TCP `53` and UDP `53` separate.

## Exit Codes

Expected PortWeft failures return a controlled non-zero code. Nmap failures
return Nmap's exit code when the failure comes from a scan command. See
[Error Handling](errors.md) for details.
