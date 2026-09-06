import contextlib
import io
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
