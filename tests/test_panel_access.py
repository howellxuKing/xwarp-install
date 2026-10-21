import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from panel_access import credential_lines, entry_url


class PanelAccessTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Private Unix file permissions are verified by Linux CI")
    def test_new_credentials_and_existing_password_are_distinguished(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIn("保持原设置", credential_lines(directory)[0])
            password_file = Path(directory) / "initial-admin-password.txt"
            password_file.write_text("RandomPassword12\n")
            password_file.chmod(0o600)
            lines = credential_lines(directory)
            self.assertIn("sysadmin", lines[0])
            self.assertEqual(lines[1], "初始登录密码：RandomPassword12")
            self.assertIn("已经修改", lines[2])
            password_file.write_text("invalid\n")
            with self.assertRaises(ValueError):
                credential_lines(directory)
    def test_entry_can_be_shared_to_a_fresh_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "gateway.json"
            config = dict(panel_domain="panel.example", subscription_domain="panel.example",
                          panel_port=55555, subscription_port=443,
                          panel_path="/p-0123456789abcdef/", certificate="/cert/test.crt",
                          private_key="/cert/test.key", entry_key_enabled=True)
            state.write_text(json.dumps(config))
            with self.assertRaises(FileNotFoundError):
                entry_url(state)
            (state.parent / "entry.key").write_text("a+b/c=\n")
            self.assertEqual(entry_url(state), "https://panel.example:55555/p-0123456789abcdef/_entry?key=a%2Bb%2Fc%3D")
            (state.parent / "entry.key").write_text("")
            with self.assertRaises(ValueError):
                entry_url(state)
            config["entry_key_enabled"] = False
            state.write_text(json.dumps(config))
            self.assertEqual(entry_url(state), "https://panel.example:55555/p-0123456789abcdef/")
