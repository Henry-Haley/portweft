# Testing

PortWeft uses Python's standard `unittest` framework.

## Run All Tests

```bash
python3 -m unittest discover -v
```

Windows:

```powershell
python -m unittest discover -v
```

## Compile Check

```bash
python3 -m compileall -q portweft.py portweft tests/*.py
```

## Install Smoke Test

From a fresh checkout inside an activated virtual environment:

```bash
python3 -m portweft --help
python3 -m pip install .
portweft --help
```

With `pipx`:

```bash
pipx install .
portweft --help
```

## Test Layout

```text
tests/test_cli.py
  CLI dry-run behavior, target resolution, JSON reports, missing Nmap handling,
  unmatched banners, UDP toggles, --full, and STDOUT/STDERR separation.

tests/test_discovery_runner.py
  Backend selection, RustScan/Masscan parsers and commands, normalized results,
  and targeted Nmap port scope.

tests/test_nuclei_runner.py
  CVE-only commands, service target construction, JSONL parsing, deduplication,
  executable preflight, and partial failure handling.

tests/test_matcher.py
  Banner-first matching, fallback ports, UDP-first ports, unmatched evidence.

tests/test_nmap_runner.py
  Nmap argument parsing, command construction, banner script handling,
  subprocess error handling.

tests/test_integration_scanner.py
  Optional localhost listener detection. Skips when Nmap is not available.

tests/test_impacket_runner.py
  Optional Impacket recon command construction, allowlist support, skipped
  tools, bounded output, and CLI result attachment.

tests/test_nmap_xml.py
  XML parsing, malformed XML, OS detection, merge behavior.

tests/test_profiles.py
  Profile shape and expected profile coverage.

tests/test_reporting.py
  Text and JSON report content, including structured Nuclei findings.

tests/test_targets.py
  Domain resolution, IPv4/IPv6 handling, CIDR membership attribution, and
  original-target mapping.

tests/fixtures/
  Static Nmap XML samples.
```

## Fixture Philosophy

Fixtures are small and purpose-built:

- Linux host with SSH and web.
- Windows host with SMB, RDP, and LDAP.
- Non-standard ports for banner-first matching.
- Empty XML.

The core suite does not require external network scanning. The optional
integration test binds a local listener on loopback and skips itself when Nmap
is not available. GitHub Actions tests Python 3.10–3.13 and has one Ubuntu job
that installs Nmap so this localhost integration path executes.

## Temporary Files

Tests use `tests/.tmp/` for local scratch files. That directory is ignored by
Git.

## Before Committing

Run:

```bash
python3 -m unittest discover -v
python3 -m compileall -q portweft.py portweft tests/*.py
git diff --check
```

GitHub Actions also runs the tests and compile check on push and pull request.
