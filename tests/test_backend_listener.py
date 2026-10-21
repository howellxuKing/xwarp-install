import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from upgrade import current_backend_bind, upgrade_spec


class BackendListenerTests(unittest.TestCase):
    def snapshot(self):
        return dict(Name="/trojan-panel", Image="sha256:" + "a" * 64,
                    State=dict(Pid=42), HostConfig=dict(NetworkMode="host"),
                    Config=dict(Env=["server_port=8081"]), Mounts=[])

    def test_legacy_upgrade_preserves_loopback_private_and_wildcard_listeners(self):
        cases = [("tcp", "0100007F", "127.0.0.1"),
                 ("tcp", "00000000", "0.0.0.0"),
                 ("tcp", "0500000A", "10.0.0.5"),
                 ("tcp6", "00000000000000000000000000000000", "[::]")]
        with tempfile.TemporaryDirectory() as directory:
            net = Path(directory) / "42/net"
            net.mkdir(parents=True)
            for table, encoded, expected in cases:
                for name in ("tcp", "tcp6"):
                    (net / name).write_text("header\n")
                (net / table).write_text("header\n0: " + encoded + ":1F91 00000000:0000 0A\n")
                old = self.snapshot()
                bind = current_backend_bind(old, directory)
                self.assertEqual(bind, expected)
                plan = upgrade_spec(old, "example/backend@sha256:" + "b" * 64, {}, backend_bind=bind)
                self.assertIn("XWARP_API_BIND=" + expected, plan)
                self.assertEqual(old["Config"]["Env"], ["server_port=8081"])

    def test_explicit_binding_is_preserved_and_unknown_listener_is_rejected(self):
        old = self.snapshot()
        old["Config"]["Env"].append("XWARP_API_BIND=127.0.0.1")
        self.assertEqual(current_backend_bind(old, "/nonexistent"), "127.0.0.1")
        old = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                current_backend_bind(old, directory)
