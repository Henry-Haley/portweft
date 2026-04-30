# Error Handling

PortWeft tries to distinguish expected runtime failures from programming
errors. Expected failures are caught, printed clearly, and returned with a
stable exit code where possible.

## Expected Errors

| Condition | Behavior |
| --- | --- |
| Nmap missing | Prints install/PATH guidance and exits `127`. |
| Bad `--nmap-args` quoting | Prints the parse error and exits `2`. |
| Bad passthrough timing/concurrency value | Prints the invalid option and exits `2`. |
| User passes Nmap output flags | Prints a PortWeft XML ownership message and exits `2`. |
| Target expansion exceeds `--max-scan-targets` | Prints the target estimate and exits `2`. |
| Domain target cannot resolve | Prints a DNS error, skips that target, and continues. |
| No targets remain after DNS resolution | Prints a controlled error and exits `2`. |
| Scanner subprocess timeout | Stops the subprocess, prints a timeout error, and exits `124`. |
| User presses Ctrl+C | Attempts to stop the active subprocess and exits `130`. |
| Nmap rejects a user flag | Prints Nmap's own error and returns Nmap's exit code. |
| Output directory cannot be created | Prints the path and OS error. |
| Nmap XML cannot be parsed | Prints the XML path and parse/read error. |
| Follow-up XML cannot be parsed | Prints the error and continues with the rest of the run. |
| UDP companion scan fails | Prints Nmap's error and continues with TCP results. |
| Impacket package missing | Prints `Install with pip install .[impacket]` and exits before scanning. |
| Impacket recon tool missing | Prints a skip message and continues. |
| Impacket recon module fails | Prints the module output/error and continues. |
| Report cannot be written | Prints the report path and OS error. |

## Error Classes

Defined in `portweft/errors.py`:

```text
PortWeftError
NmapNotFoundError
NmapArgumentStringError
NmapOutputConflictError
NmapPassthroughError
PortSpecError
ImpacketUnavailableError
TargetResolutionError
OutputDirectoryError
NmapXmlParseError
ReportWriteError
```

All expected errors inherit from `PortWeftError`.

## Nmap Error Output

PortWeft captures both stdout and stderr from Nmap. If Nmap exits with a
non-zero code, PortWeft prints a short tail of the Nmap output. This keeps bad
flag errors readable without dumping excessive scan output.

Example:

```text
Error: Nmap returned a non-zero exit code.
Error: nmap: unrecognized option `--bad-flag'
Error: See the output of nmap -h for a summary of options.
```

## XML Error Output

Malformed or unreadable XML is wrapped as:

```text
Error: Could not parse Nmap XML: output/scans/<run>/<run>-initial.xml
Error: <parser or OS message>
```

Follow-up XML parse failures do not stop the entire run. Initial XML parse
failures do stop the run because there is no reliable service inventory to
continue from.

## Impacket Error Output

Optional Impacket recon is best-effort. The Impacket package is imported only
when `--impacket` is used. If it is missing, PortWeft prints
`Install with pip install .[impacket]` and exits before scanning so it does not
change the operator machine. Missing tools and non-zero module exits do not
stop the PortWeft run once the Python package is available. Output is bounded
before being printed or written to the report so a chatty module cannot consume
unbounded memory.
