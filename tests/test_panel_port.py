import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from panel_port import legacy_plan


class LegacyPanelPortTests(unittest.TestCase):
    def test_unrelated_upstream_ports_are_preserved(self):
        old = 'server {\n listen 8888 ssl;\n listen [::]:8888 ssl;\n location /api { proxy_pass http://127.0.0.1:8081; }\n error_page 497 https://$host:8888$request_uri;\n}\n'
        old_port, new, tls = legacy_plan(old, 55555)
        self.assertEqual(old_port, 8888)
        self.assertTrue(tls)
        self.assertIn('listen [::]:55555 ssl;', new)
        self.assertIn('http://127.0.0.1:8081', new)
        self.assertIn('https://$host:55555$request_uri', new)
        with self.assertRaises(ValueError):
            legacy_plan(old + 'server { listen 443 ssl; }', 55555)
