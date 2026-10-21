import io
import json
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gateway, firewall, knock, snapshot, upgrade, certificates, release

class ToolsTests(unittest.TestCase):
    def config(self):
        return dict(panel_path="/p-0123456789abcdef0123456789abcdef/", panel_domain="test.example", subscription_domain="test.example", panel_port=18888, subscription_port=18443, certificate="/cert/test.crt", private_key="/cert/test.key", entry_key_enabled=True, knock_enabled=True)
    def test_gateway_separates_access(self):
        rendered = gateway.render(self.config())
        panel, subscription = rendered.split("server {", 2)[1:]
        self.assertIn("auth_request /_entry_check", panel)
        self.assertNotIn("auth_request", subscription)
        self.assertIn("/api/auth/subscribe/", subscription)
        self.assertIn("window.__XWARP_BASE__", panel)
        self.assertNotIn("301", rendered)
        self.assertIn("listen [::]:", rendered)
        for field, value in [("panel_domain", "test.example;return 200"), ("panel_path", "/short/"), ("certificate", "/cert/../secret"), ("panel_port", 18443)]:
            config = self.config(); config[field] = value
            with self.assertRaises(ValueError): gateway.render(config)
    def test_only_selected_firewall_ports_and_fail_closed_reload(self):
        calls=[]
        def execute(argv, check=True):
            calls.append(argv); return SimpleNamespace(returncode=0)
        firewall.core_rules([8082,8100], ["203.0.113.7/32", "2001:db8::1/128"], execute)
        for binary in ["iptables", "ip6tables"]:
            actual=[a for a in calls if a[0]==binary]
            guard=next(i for i,a in enumerate(actual) if "INPUT" in a and a[-1]=="DROP")
            flush=next(i for i,a in enumerate(actual) if "-F" in a)
            self.assertLess(guard, flush)
            self.assertTrue(any("8082,8100" in a for a in actual))
            self.assertFalse(any("22" in a or "1443" in a for a in actual))
        with self.assertRaises(ValueError): firewall.core_rules([0], [], execute)
    def test_knock_kernel_timeout_and_ip_family(self):
        calls=[]
        def execute(argv, check=True): calls.append(argv); return SimpleNamespace(returncode=1)
        knock.policy(18888, execute)
        knock.grant("2001:db8::2", execute)
        self.assertTrue(any(a[:3]==["ipset", "add", "xwarp_panel6"] and "43200" in a for a in calls))
        self.assertFalse(any("443" in a or "22" in a for a in calls))
    def test_restore_rejects_traversal_and_links(self):
        for name, kind in [("../../outside", tarfile.REGTYPE), ("snapshot/key", tarfile.SYMTYPE), ("tpdata/mariadb/data", tarfile.REGTYPE)]:
            with tempfile.TemporaryDirectory() as directory:
                archive=Path(directory)/"bad.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    member=tarfile.TarInfo(name); member.type=kind
                    if kind==tarfile.REGTYPE: member.size=1; tar.addfile(member,io.BytesIO(b"x"))
                    else: member.linkname="/etc/shadow"; tar.addfile(member)
                archive.with_suffix(".gz.sha256").write_text(snapshot.image_digest(archive))
                with self.assertRaises(ValueError): snapshot.extract_verified(archive,Path(directory)/"restore")
    def test_container_restore_uses_original_image_and_volume(self):
        container=dict(Name="/trojan-panel", Image="sha256:"+"a"*64, HostConfig=dict(NetworkMode="host", RestartPolicy=dict(Name="always")), Config=dict(Env=["FIXTURE=secret"],Entrypoint=["/bin/sh","-c"],Cmd=["start"]),Mounts=[dict(Type="volume",Name="actual-volume",Source="/var/lib/docker/volumes/actual-volume/_data",Destination="/data",RW=True)])
        plan=snapshot.container_spec(container)
        self.assertIn(container["Image"],plan)
        self.assertIn("type=volume,source=actual-volume,target=/data",plan)
        upgraded=upgrade.upgrade_spec(container, "example/new@sha256:"+"b"*64, dict(Entrypoint=["new-wrapper"],Cmd=["new-start"]))
        self.assertIn("new-wrapper",upgraded)
        self.assertIn("new-start",upgraded)
        self.assertNotIn("/bin/sh",upgraded)
        self.assertIn("FIXTURE=secret",upgraded)
        self.assertEqual(container["Config"]["Entrypoint"],["/bin/sh","-c"])
        container["HostConfig"]["Privileged"]=True
        with self.assertRaises(ValueError): snapshot.container_spec(container)
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_certificate_rejects_wrong_hostname_and_key(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder); cert=folder/"cert.crt"; key=folder/"cert.key"; other=folder/"other.key"
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-days","1","-subj","/CN=test.example"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            certificates.matched_pair(cert,key,"test.example")
            with self.assertRaises((ValueError,RuntimeError)): certificates.matched_pair(cert,key,"wrong.example")
            subprocess.run(["openssl","genpkey","-algorithm","RSA","-out",str(other)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            with self.assertRaises(ValueError): certificates.matched_pair(cert,other,"test.example")
    def test_release_rejects_wrong_repository_and_mutable_tag(self):
        manifest=dict(format=1,platform="linux/amd64",images={"backend":"ghcr.io/howellxuking/xwarp@sha256:"+"a"*64,"ui":"ghcr.io/howellxuking/xwarp-ui@sha256:"+"b"*64,"core":"jonssonyan/trojan-panel-core@sha256:"+"c"*64})
        self.assertEqual(len(release.references(manifest)),3)
        manifest["images"]["backend"]="ghcr.io/attacker/backend@sha256:"+"a"*64
        with self.assertRaises(ValueError):release.references(manifest)
        manifest["images"]["backend"]="ghcr.io/howellxuking/xwarp:latest"
        with self.assertRaises(ValueError):release.references(manifest)
    def test_ui_upgrade_migrates_file_mount_without_changing_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/"default.conf";file.write_text("fixture")
            old=dict(Name="/trojan-panel-ui",Image="sha256:"+"a"*64,HostConfig=dict(NetworkMode="host"),Config=dict(Env=[]),Mounts=[dict(Type="bind",Source=str(file),Destination="/etc/nginx/conf.d/default.conf",RW=True)])
            with patch("upgrade.Path.is_dir", return_value=True):
                plan=upgrade.upgrade_spec(old,"example/ui@sha256:"+"b"*64,dict(Entrypoint=["nginx"]))
            self.assertIn("type=bind,source=/tpdata/web,target=/tpdata/web,readonly",plan)
            self.assertEqual(len(old["Mounts"]),1)
            self.assertIn("type=bind,source="+folder+",target=/etc/nginx/conf.d",plan)
            self.assertEqual(old["Mounts"][0]["Source"],str(file))
            self.assertIn("target=/etc/nginx/conf.d/default.conf",snapshot.container_spec(old)[snapshot.container_spec(old).index("--mount")+1])
    def test_upgrade_requires_immutable_digest(self):
        self.assertEqual(upgrade.validate_image("ghcr.io/example/backend@sha256:"+"a"*64),"ghcr.io/example/backend@sha256:"+"a"*64)
        for value in ["example:latest","example:test","example@sha256:invalid","example;rm@sha256:"+"a"*64]:
            with self.assertRaises(ValueError): upgrade.validate_image(value)

if __name__=="__main__": unittest.main()
