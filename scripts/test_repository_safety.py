import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_repository_safety as safety


class RepositorySafetyTests(unittest.TestCase):
    assembly_version = ".".join(("6", "0", "0", "0"))

    def scan(self, name, text):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / name
            path.write_text(text)
            output = io.StringIO()
            with patch.object(safety, "ROOT", root), patch.object(
                safety, "tracked_files", return_value=[path]
            ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = safety.main()
            return result, output.getvalue()

    def test_manifest_versions_and_official_namespace_are_allowed(self):
        result, _ = self.scan("client.manifest", f'<assemblyIdentity version="{self.assembly_version}" />\n'
                              '<dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings" />')
        self.assertEqual(result, 0)

    def test_manifest_endpoint_is_still_rejected(self):
        address = ".".join(("6", "0", "0", "1"))
        result, output = self.scan("client.manifest", f'<assembly version="{self.assembly_version}" endpoint="' + address + '" />')
        self.assertEqual(result, 1)
        self.assertIn("unapproved public IPv4 address", output)
        self.assertNotIn(address, output)

    def test_version_exception_does_not_apply_to_other_files(self):
        result, _ = self.scan("config.txt", f'version="{self.assembly_version}"')
        self.assertEqual(result, 1)

    def test_unknown_domains_and_device_ids_are_rejected(self):
        for value, category in (("https://private-deployment" + ".net", "unapproved public domain"),
                                ("xy" + "42", "site-like device identifier")):
            with self.subTest(category=category):
                result, output = self.scan("config.txt", value)
                self.assertEqual(result, 1)
                self.assertIn(category, output)
                self.assertNotIn(value, output)

    def test_credentialed_example_url_is_still_rejected(self):
        value = "https://" + "demo-user:demo-password@example.com/loom"
        result, output = self.scan("config.txt", value)
        self.assertEqual(result, 1)
        self.assertIn("credentialed URL", output)
        self.assertNotIn(value, output)

    def test_kotlin_import_is_not_treated_as_endpoint(self):
        content = "package io.example.client\nimport android." + "net.Network\nval scope = Dispatchers." + "IO\n"
        result, _ = self.scan("Client.kt", content)
        self.assertEqual(result, 0)

    def test_kotlin_string_endpoint_is_still_rejected(self):
        value = 'private val endpoint = "https://private-deployment' + '.net/api"'
        result, output = self.scan("Client.kt", value)
        self.assertEqual(result, 1)
        self.assertIn("unapproved public domain", output)

    def test_uppercase_string_endpoint_is_still_rejected(self):
        value = 'private val endpoint = "HTTPS://PRIVATE-DEPLOYMENT' + '.NET/api"'
        result, output = self.scan("Client.kt", value)
        self.assertEqual(result, 1)
        self.assertIn("unapproved public domain", output)

    def test_broad_ipv6_network_literals_are_not_device_ids(self):
        for prefix in ("fc" + "00::/7", "fe" + "80::/10", "fc" + "00::/1",
                       "FE" + "80:0:0:0:0:0:0:0/10"):
            with self.subTest(prefix=prefix):
                result, _ = self.scan("config.go", 'var networks = []string{"' + prefix + '"}')
                self.assertEqual(result, 0)

    def test_ipv6_exception_does_not_allow_bare_device_ids_or_endpoints(self):
        site = "fc" + "00"
        for value in (site, "fe" + "80", site + "::1/7", site + "::/64",
                      "2001:db8:" + site + "::/48", site + "::/129",
                      site + ":::0/7", site + "::/x", site + "::/7suffix",
                      site + "::%demo/7", "[" + site + "::]/7",
                      "https://[" + site + "::1]:443/path", "https://" + site + "::/7",
                      site + "::/7:443", site + "::/7/path"):
            with self.subTest(value=value):
                result, output = self.scan("config.txt", 'value="' + value + '"')
                self.assertEqual(result, 1)
                self.assertIn("site-like device identifier", output)
                self.assertNotIn(value, output)

    def test_ipv6_network_exception_is_limited_to_its_own_span(self):
        site = "fc" + "00"
        result, output = self.scan("config.go", f'networks = ["{site}::/7"]; device = "{site}"')
        self.assertEqual(result, 1)
        self.assertEqual(output.count("site-like device identifier"), 1)

    def test_tracked_files_includes_index_entries_before_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            staged, untracked = root / "staged.py", root / "untracked.py"
            staged.write_text("# staged before first commit\n")
            untracked.write_text("# not staged\n")
            subprocess.run(["git", "add", staged.name], cwd=root, check=True)
            with patch.object(safety, "ROOT", root):
                paths = safety.tracked_files()
            self.assertIn(staged, paths)
            self.assertNotIn(untracked, paths)


if __name__ == "__main__":
    unittest.main()
