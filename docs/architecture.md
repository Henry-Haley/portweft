# Architecture

PortWeft is intentionally small and standard-library only. Nmap is the only
external runtime dependency.

## Flow

```text
CLI arguments
  -> target parsing
  -> initial TCP Nmap scan
  -> UDP companion Nmap scan unless disabled
  -> XML parsing
  -> banner-first profile matching
  -> batched service-specific follow-up scans
  -> merged host/service observations
  -> terminal progress output
  -> text report
```

## Modules

```text
portweft.py
  Compatibility launcher.

portweft/__main__.py
  Enables `python -m portweft`.

portweft/cli.py
  Argument parsing and the main workflow.

portweft/models.py
  HostObservation and ServiceObservation dataclasses.

portweft/nmap_runner.py
  Nmap command construction, passthrough validation, executable discovery,
  subprocess execution, and Nmap error extraction.

portweft/nmap_xml.py
  Streaming Nmap XML parsing, OS inference, bounded script-output extraction,
  and result merging.

portweft/profiles.py
  Built-in profile definitions, fallback ports, UDP ports, banner terms, and
  conservative NSE script selections.

portweft/matcher.py
  Banner-first service-to-profile matching.

portweft/reporting.py
  Streaming text report generation.

portweft/errors.py
  Expected runtime exceptions with stable exit codes.

portweft/utils.py
  Console printing, command display, run IDs, and formatting helpers.
```

## Matching Model

Matching prefers service evidence over ports:

1. Nmap service name
2. Product and version fields
3. Extra service info
4. TLS tunnel metadata
5. NSE script names and script output
6. TCP or UDP fallback ports

This lets PortWeft catch common non-standard deployments, such as SSH on
`2222`, HTTP on `9000`, or SMB/Samba on a non-standard TCP port.

If a banner or service string exists but no profile matches it, PortWeft prints
a progress message and keeps the service in the final report.

## Result Merging

The initial TCP XML is parsed first. If the UDP companion scan succeeds, its XML
is parsed and merged into the same host list. Follow-up scans then merge script
output, updated product/version fields, and new services back into the existing
host observations.

The merge key for services is:

```text
(protocol, port)
```

This keeps TCP `53` and UDP `53` separate.

## Exit Codes

Expected PortWeft failures return a controlled non-zero code. Nmap failures
return Nmap's exit code when the failure comes from a scan command. See
[Error Handling](errors.md) for details.
