# Usage

PortWeft is intended to run on Linux, macOS, and Windows. Linux is the primary
runtime target.

## Requirements

- Python 3.10+
- Nmap available on `PATH`
- Optional: Impacket for `--impacket` recon modules

No Python packages are required for normal use. Impacket is only needed when
optional Impacket recon is enabled. If it is missing, PortWeft attempts to
install it automatically with pip before running Impacket recon.

Manual install from the source tree:

```bash
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

If the Windows Python launcher is not on `PATH`, use the full interpreter path:

```powershell
& 'C:\Users\henry\AppData\Local\Python\bin\python.exe' -m portweft 192.0.2.10
```

The legacy root launcher also works:

```bash
python3 portweft.py 192.0.2.10
```

## Target Formats

Single target:

```bash
python3 -m portweft 192.0.2.10
```

Comma-separated targets:

```bash
python3 -m portweft 192.0.2.10,192.0.2.11
```

CIDR range:

```bash
python3 -m portweft 192.0.2.0/24
```

## TCP Ports

Specify ports:

```bash
python3 -m portweft 192.0.2.10 -p 22,80,443,445
```

Use Nmap's top ports:

```bash
python3 -m portweft 192.0.2.10 --top-ports 1000
```

If neither `-p` nor `--top-ports` is provided, PortWeft lets Nmap use its
default TCP port selection.

## Nmap Passthrough

PortWeft accepts raw Nmap options after its own arguments:

```bash
python3 -m portweft 192.0.2.10 -- -T4 -Pn --max-retries 2
```

Or as a quoted string:

```bash
python3 -m portweft 192.0.2.10 --nmap-args "-T4 -Pn --max-retries 2"
```

PortWeft owns Nmap output flags so XML remains parseable. Do not pass `-oX`,
`-oA`, `-oN`, `-oG`, `-oS`, or `--webxml`. Use `--output-dir` instead.

## UDP Options

PortWeft runs a small UDP companion scan by default for UDP-first and
UDP-centric services.

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

## Dry Run

Preview commands without scanning:

```bash
python3 -m portweft 192.0.2.10 -p 22,80,443 --dry-run -- -T4 -Pn
```

Dry-run mode prints the exact Nmap commands that would be executed and does not
write output files.

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
only when `--impacket` is used. If the package is missing, PortWeft runs:

```bash
python3 -m pip install "impacket>=0.11"
```

If pip installation fails, or if matching Impacket console tools are still
missing afterward, PortWeft prints a skip message; they are not required for
normal use.

Limit retained Impacket output per module:

```bash
python3 -m portweft 192.0.2.10 --impacket --max-impacket-output-chars 4096
```

## Output Retention

Keep only the newest completed output runs:

```bash
python3 -m portweft 192.0.2.10 --keep-runs 10
```

The default is `0`, which keeps all existing output.

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
  scans/
    <run-id>/
      initial.xml
      udp.xml
      <host>_<protocol>_<profile>.xml
  reports/
    <run-id>.txt
```

The terminal prints progress while the run is happening. The report is a text
summary of the parsed service facts.
