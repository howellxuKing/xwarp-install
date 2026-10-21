import json
import socket
import sys
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gateway
from gateway import render
from panel_access import entry_url, legacy_entry_url
from ports import choose_port


class SimplePanelTests(unittest.TestCase):
    def test_gateway_cli_preserves_old_entry_until_explicit_simple_choice(self):
        with tempfile.TemporaryDirectory() as directory:
            state, output = Path(directory) / "gateway.json", Path(directory) / "default.conf"
            old = dict(panel_domain="panel.example", subscription_domain="panel.example",
                       panel_port=55555, subscription_port=443, panel_path="/p-0123456789abcdef/",
                       certificate="/cert/test.crt", private_key="/cert/test.key", entry_key_enabled=True)
            state.write_text(json.dumps(old))
            (state.parent / "entry.key").write_text("fixture-entry-key")
            args = ["gateway.py", "--panel-domain", "panel.example", "--certificate", "/cert/test.crt",
                    "--private-key", "/cert/test.key", "--state", str(state), "--output", str(output)]
            with patch("sys.argv", args), patch("certificates.matched_pair"), redirect_stdout(io.StringIO()):
                gateway.main()
            saved = json.loads(state.read_text())
            self.assertEqual(saved["panel_port"], 55555)
            self.assertEqual(saved["panel_path"], old["panel_path"])
            self.assertTrue(saved["entry_key_enabled"])
            with patch("sys.argv", args + ["--simple-panel"]), patch("certificates.matched_pair"), redirect_stdout(io.StringIO()):
                gateway.main()
            self.assertEqual(entry_url(state), "https://panel.example:55555/")
            self.assertEqual((state.parent / "entry.key").read_text(), "fixture-entry-key")
            with patch("sys.argv", args + ["--entry-key"]), patch("certificates.matched_pair"), redirect_stdout(io.StringIO()):
                gateway.main()
            self.assertIn("/_entry?key=", entry_url(state))

    def test_fresh_install_address_is_read_from_saved_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "default.conf"
            config.write_text('server {\n listen 55555 ssl;\n server_name panel.example;\n}\n')
            self.assertEqual(legacy_entry_url(config), "https://panel.example:55555/")
            config.write_text('server {\n listen 65535;\n server_name 203.0.113.1;\n}\n')
            self.assertEqual(legacy_entry_url(config), "http://203.0.113.1:65535/")

    def test_root_panel_has_short_entry_and_separate_subscription(self):
        config = dict(panel_domain="panel.example", subscription_domain="panel.example",
                      panel_port=55555, subscription_port=443, panel_path="/",
                      certificate="/cert/test.crt", private_key="/cert/test.key",
                      entry_key_enabled=False)
        rendered = render(config)
        panel, subscription = rendered.split("server {", 2)[1:]
        self.assertIn('window.__XWARP_BASE__="/"', panel)
        self.assertNotIn("auth_request", panel)
        self.assertNotIn("location = /_entry", panel)
        self.assertIn("/api/auth/subscribe/ { return 404; }", panel)
        self.assertIn("location ^~ /api/ { return 404; }", subscription)
        self.assertIn("root /tpdata/web", subscription)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "gateway.json"
            state.write_text(json.dumps(config))
            self.assertEqual(entry_url(state), "https://panel.example:55555/")
        config["entry_key_enabled"] = True
        with self.assertRaises(ValueError):
            render(config)

    def test_random_port_retries_busy_tcp_and_udp_and_reserved_port(self):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0)); tcp.listen()
            udp.bind(("127.0.0.1", 0))
            for busy in (tcp.getsockname()[1], udp.getsockname()[1]):
                with self.assertRaises(ValueError):
                    choose_port(busy)
        with patch("ports.secrets.randbelow", side_effect=[0, 1, 16383]), patch("ports.check_available") as check:
            check.side_effect = [ValueError("busy"), None]
            self.assertEqual(choose_port(exclude=[49152]), 65535)
            self.assertEqual(check.call_count, 2)
