# Safety And UDP Behavior

PortWeft is designed for authorized reconnaissance and conservative service
fact collection.

## What PortWeft Does

- Runs Nmap scans.
- Saves Nmap XML.
- Parses open services, banners, versions, and script output.
- Matches services to low-noise follow-up profiles.
- Prints progress to screen.
- Writes a text report.

## What PortWeft Does Not Do

- Exploit services.
- Brute force credentials.
- Perform password spraying.
- Look up CVEs.
- Decide that a version is vulnerable.
- Run intrusive NSE scripts by default.
- Perform internet lookups.

## Default TCP Behavior

The initial scan uses Nmap service detection unless disabled:

```text
-sV --version-light
```

User-provided Nmap flags are passed through where possible. PortWeft blocks
Nmap output flags because it owns XML output generation.

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

## UDP Failure Handling

UDP scans can fail because of OS permissions, missing packet capture drivers,
firewall behavior, or unsupported scan options. PortWeft treats UDP companion
scan failure as non-fatal:

```text
UDP companion scan failed; continuing with available TCP results
```

Nmap's error text is printed so the operator can decide whether to rerun with
different privileges or flags.

## Safe Operating Practices

- Use `--dry-run` before scanning unfamiliar ranges.
- Use `--no-udp` when UDP is outside scope.
- Use `-p` or `--top-ports` to keep scan scope explicit.
- Keep Nmap timing flags appropriate for the environment.
- Treat all targets as requiring authorization.
