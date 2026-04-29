from __future__ import annotations

import unittest

from portweft.profiles import SERVICE_PROFILES, WEB_PORTS


class ProfileTests(unittest.TestCase):
    def test_profiles_have_expected_shape(self) -> None:
        for name, profile in SERVICE_PROFILES.items():
            with self.subTest(profile=name):
                self.assertIsInstance(profile.get("ports"), set)
                if "udp_ports" in profile:
                    self.assertIsInstance(profile.get("udp_ports"), set)
                self.assertIsInstance(profile.get("services"), set)
                self.assertIsInstance(profile.get("banner_terms"), set)
                self.assertIsInstance(profile.get("scripts"), list)

    def test_web_common_alt_ports_are_present(self) -> None:
        for port in (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443):
            with self.subTest(port=port):
                self.assertIn(port, WEB_PORTS)

    def test_basic_profiles_are_present(self) -> None:
        expected = {
            "dns",
            "dhcp",
            "docker",
            "elasticsearch",
            "ftp",
            "imap",
            "ike",
            "kerberos",
            "kubernetes",
            "ldap",
            "memcached",
            "mongodb",
            "mssql",
            "mysql",
            "nfs",
            "ntp",
            "pop3",
            "postgres",
            "rdp",
            "redis",
            "rpc",
            "rsync",
            "smb",
            "smtp",
            "snmp",
            "ssdp",
            "ssh",
            "syslog",
            "telnet",
            "tftp",
            "tls",
            "vnc",
            "web",
            "winrm",
        }
        self.assertTrue(expected.issubset(SERVICE_PROFILES))


if __name__ == "__main__":
    unittest.main()
