"""Application-level exceptions."""

from __future__ import annotations


class PortWeftError(Exception):
    """Base exception for expected PortWeft failures."""

    exit_code = 1


class NmapNotFoundError(PortWeftError):
    """Raised when Nmap cannot be located before scanning starts."""

    exit_code = 127

    def __init__(self, nmap_path: str) -> None:
        super().__init__(
            f"Nmap was not found: {nmap_path}\n"
            "Install Nmap, add it to PATH, or pass the full path with --nmap-path."
        )


class NmapArgumentStringError(PortWeftError):
    """Raised when --nmap-args cannot be parsed as a shell-like string."""

    exit_code = 2


class NmapOutputConflictError(PortWeftError):
    """Raised when passthrough args conflict with PortWeft-managed XML output."""

    exit_code = 2


class NmapPassthroughError(PortWeftError):
    """Raised when passthrough Nmap args are malformed before Nmap runs."""

    exit_code = 2


class PortSpecError(PortWeftError):
    """Raised when a PortWeft-managed port list is malformed."""

    exit_code = 2


class ImpacketUnavailableError(PortWeftError):
    """Raised when optional Impacket recon is requested but unavailable."""

    exit_code = 1

    def __init__(self, reason: str) -> None:
        super().__init__(reason)


class TargetResolutionError(PortWeftError):
    """Raised when no input target can be resolved or scanned."""

    exit_code = 2


class OutputDirectoryError(PortWeftError):
    """Raised when output directories cannot be prepared."""

    exit_code = 1

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"Could not prepare output directory: {path}\n{reason}")


class NmapXmlParseError(PortWeftError):
    """Raised when an Nmap XML file cannot be read or parsed."""

    exit_code = 1

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"Could not parse Nmap XML: {path}\n{reason}")


class ReportWriteError(PortWeftError):
    """Raised when the final report cannot be written."""

    exit_code = 1

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"Could not write report: {path}\n{reason}")
