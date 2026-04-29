# Safety And UDP Behavior

PortWeft is designed for authorized reconnaissance and conservative service
fact collection.

## What PortWeft Does

- Runs Nmap scans.
- Resolves domain targets to IP addresses before scanning.
- Uses temporary Nmap XML for parsing.
- Parses open services, banners, versions, and script output.
- Matches services to low-noise follow-up profiles.
- Optionally runs allowlisted Impacket recon modules when `--impacket` is set.
- Prints progress to screen.
- Writes per-host and cumulative text or JSON reports.

## What PortWeft Does Not Do

- Exploit services.
- Brute force credentials.
- Perform password spraying.
- Look up CVEs.
- Decide that a version is vulnerable.
- Run intrusive NSE scripts by default.
- Run Impacket exploitation, relay, dumping, or brute-force tooling.
- Perform internet enrichment lookups beyond DNS resolution.

## Default TCP Behavior

The initial scan uses Nmap service detection unless disabled:

```text
-sV --version-light
```

It also runs the low-noise NSE `banner` script by default so raw service
banners are captured when available. If the operator supplies a custom
`--script` expression, PortWeft adds `banner` to that expression.

User-provided Nmap flags are passed through where possible. PortWeft blocks
Nmap output flags because it owns XML output generation.

Malformed `--nmap-args` strings and common invalid passthrough timing or
parallelism values are rejected before scanning starts. Raw Nmap scan choices
remain under operator control.

## Default UDP Behavior

UDP is scanned by default with a small curated port set:

```text
53,67,68,69,88,111,123,137,138,161,162,389,500,514,520,631,1434,1900,2049,4500,5353,11211
```

These ports cover common UDP-first or UDP-centric services:

```text
DNS, DHCP, TFTP, Kerberos, RPC, NTP, NetBIOS, SNMP, LDAP, IKE/IPsec,
Syslog, RIP, IPP, MSSQL Browser, SSDP, NFS, mDNS, Memcached
```

Disable UDP:

```bash
python3 -m portweft 192.0.2.10 --no-udp
```

Change UDP ports:

```bash
python3 -m portweft 192.0.2.10 --udp-ports 53,123,161
```

The UDP companion scan removes TCP-only scan flags and conflicting
port-selection passthrough flags from its command before adding `-sU` and the
curated UDP port list. Passthrough NSE script flags are also removed from the
UDP companion command so TCP-oriented scripts do not leak into it.

If the operator supplies `-p/--ports`, PortWeft treats that as explicit scan
scope and does not automatically run the full UDP companion list. It runs UDP
only when the requested TCP port list overlaps the curated UDP defaults, and
then only for those overlapping ports. For example, `-p 445` skips UDP, while
`-p 53,445` runs `-sU -p U:53`. Explicit `--udp-ports` values still run unless
`--no-udp` is also set.

## UDP Failure Handling

UDP scans can fail because of OS permissions, missing packet capture drivers,
firewall behavior, or unsupported scan options. PortWeft treats UDP companion
scan failure as non-fatal:

```text
UDP companion scan failed; continuing with available TCP results
```

Nmap's error text is printed so the operator can decide whether to rerun with
different privileges or flags.

## Runtime Guardrails

PortWeft applies a default timeout to each Nmap or Impacket subprocess. Operators
can tune it with `--scan-timeout`, or set `--scan-timeout 0` to disable the
PortWeft-managed timeout when a long-running authorized scan requires it.

Large target expansions are blocked by default. Use `--allow-large-scan` only
when the larger range is explicitly in scope.

Ctrl+C exits cleanly with code `130` and attempts to stop the active scanner
subprocess.

## Optional Impacket Recon

Impacket recon is disabled by default. When enabled with `--impacket`, PortWeft
imports the Impacket Python package. If it is missing, PortWeft prints
`Install with pip install .[impacket]` and exits before scanning. It does not
install packages or otherwise modify the operator machine during a run. When
the package is available, PortWeft only runs allowlisted recon modules against
services that were already observed open and matched to a compatible profile.

Current allowlist:

```text
samrdump, rpcdump
```

The allowlist excludes Impacket tooling for exploitation, relaying,
credential dumping, password guessing, SID brute forcing, or vulnerability
checks. If a required command is not available, PortWeft prints a skip message
and continues.

## Safe Operating Practices

- Use `--dry-run` before scanning unfamiliar ranges.
- Use `--no-udp` when UDP is outside scope.
- Use `--impacket` only when SMB/RPC enumeration is in scope.
- Use `-p` or `--top-ports` to keep scan scope explicit.
- Use `--allow-large-scan` only for approved large ranges.
- Keep Nmap timing flags appropriate for the environment.
- Treat all targets as requiring authorization.
