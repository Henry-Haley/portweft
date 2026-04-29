# Testing

PortWeft uses Python's standard `unittest` framework.

## Run All Tests

```bash
python3 -m unittest discover -v
```

Windows with an explicit interpreter path:

```powershell
& 'C:\Users\henry\AppData\Local\Python\bin\python.exe' -m unittest discover -v
```

## Compile Check

```bash
python3 -m compileall portweft.py portweft tests
```

## Install Smoke Test

From a fresh checkout:

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
  CLI dry-run behavior, missing Nmap handling, unmatched banners, UDP toggles.

tests/test_matcher.py
  Banner-first matching, fallback ports, UDP-first ports, unmatched evidence.

tests/test_nmap_runner.py
  Nmap argument parsing, command construction, subprocess error handling.

tests/test_nmap_xml.py
  XML parsing, malformed XML, OS detection, merge behavior.

tests/test_profiles.py
  Profile shape and expected profile coverage.

tests/test_reporting.py
  Text report content.

tests/fixtures/
  Static Nmap XML samples.
```

## Fixture Philosophy

Fixtures are small and purpose-built:

- Linux host with SSH and web.
- Windows host with SMB, RDP, and LDAP.
- Non-standard ports for banner-first matching.
- Empty XML.

The suite does not require live network scanning.

## Temporary Files

Tests use `tests/.tmp/` for local scratch files. That directory is ignored by
Git.

## Before Committing

Run:

```bash
python3 -m unittest discover -v
python3 -m compileall portweft.py portweft tests
git diff --check
```

GitHub Actions also runs the unit tests and compile check on push and pull
request.
