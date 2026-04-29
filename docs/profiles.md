# Profiles

Profiles define how PortWeft recognizes a service and which conservative Nmap
scripts it may run during follow-up.

## Profile Fields

```text
ports
  TCP fallback ports. Used only when banner/service evidence does not produce a
  clear match.

udp_ports
  UDP fallback ports. Optional. Used when Nmap reports a UDP service as open.

services
  Nmap service names that map directly to the profile.

banner_terms
  Lowercase terms searched across service name, product, version, extra info,
  tunnel metadata, script names, and script output.

scripts
  Conservative NSE scripts used for follow-up. Empty means the follow-up scan
  omits `--script` and only gathers version/service data.
```

## Current Built-In Profiles

| Profile | TCP Fallback Ports | UDP Fallback Ports | Follow-Up Scripts |
| --- | --- | --- | --- |
| `web` | 80, 81, 82, 83, 88, 443, 591, 593, 8000, 8008, 8080, 8081, 8088, 8090, 8443, 8800, 8888, 9000, 9443 | none | `http-title`, `http-server-header` |
| `tls` | 443, 465, 563, 636, 853, 989, 990, 993, 995, 8443, 9443, 5986 | none | `ssl-cert` |
| `smb` | 139, 445 | 137, 138 | `smb-protocols`, `smb2-security-mode`, `smb2-time` |
| `ssh` | 22, 2222 | none | `ssh-hostkey`, `ssh2-enum-algos` |
| `ftp` | 20, 21, 989, 990, 2121 | none | `ftp-syst` |
| `telnet` | 23, 2323 | none | `telnet-encryption` |
| `dns` | 53, 5353 | 53, 5353 | `dns-nsid` |
| `dhcp` | none | 67, 68 | none |
| `tftp` | none | 69 | none |
| `ntp` | none | 123 | `ntp-info` |
| `smtp` | 25, 465, 587, 2525 | none | `smtp-commands` |
| `pop3` | 110, 995 | none | `pop3-capabilities` |
| `imap` | 143, 993 | none | `imap-capabilities` |
| `rdp` | 3389 | none | `rdp-enum-encryption` |
| `ldap` | 389, 636, 3268, 3269 | 389 | `ldap-rootdse` |
| `kerberos` | 88, 464, 749 | 88, 464 | none |
| `winrm` | 5985, 5986 | none | `http-title`, `http-server-header` |
| `nfs` | 2049 | 2049 | `nfs-showmount` |
| `rpc` | 111, 135 | 111 | `rpcinfo` |
| `snmp` | 161, 162 | 161, 162 | `snmp-info` |
| `mssql` | 1433, 1434 | 1434 | `ms-sql-info` |
| `mysql` | 3306, 33060 | none | `mysql-info` |
| `postgres` | 5432, 5433 | none | none |
| `redis` | 6379 | none | `redis-info` |
| `mongodb` | 27017, 27018, 27019 | none | `mongodb-info` |
| `elasticsearch` | 9200, 9300 | none | `http-title`, `http-server-header` |
| `memcached` | 11211 | 11211 | `memcached-info` |
| `vnc` | 5800, 5900, 5901, 5902 | none | `vnc-info` |
| `rsync` | 873 | none | none |
| `docker` | 2375, 2376 | none | `http-title`, `http-server-header` |
| `kubernetes` | 6443, 8001, 8080, 10250, 10255 | none | `http-title`, `http-server-header` |
| `ike` | none | 500, 4500 | `ike-version` |
| `syslog` | none | 514 | none |
| `ssdp` | none | 1900 | none |

## Adding A Profile

Add a dictionary entry in `portweft/profiles.py`:

```python
"example": {
    "ports": {12345},
    "udp_ports": set(),
    "services": {"example-service"},
    "banner_terms": {"example product", "exampled"},
    "scripts": [],
}
```

Then add tests in:

```text
tests/test_matcher.py
tests/test_profiles.py
tests/test_nmap_runner.py
```

Prefer banner terms that are specific enough to avoid collisions. For example,
`dovecot` alone can indicate IMAP or POP3, so PortWeft matches on `imap`,
`imapd`, `pop3`, or `pop3d` instead.

## Script Selection Rules

Default scripts should be low-noise information gathering. Do not add scripts
that brute force credentials, attempt exploitation, or produce vulnerability
judgments by default.
