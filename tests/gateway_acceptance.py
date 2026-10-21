"""Ephemeral CI gateway test; never connects to an existing server."""
import http.client, json, os, ssl, subprocess, sys, tempfile, threading, time
import socket
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from gateway import render
import panel_port
if os.getenv("GITHUB_ACTIONS")!="true": raise SystemExit("CI only")
prefix="/p-0123456789abcdef0123456789abcdef/"
class Fixture(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        if self.path=="/api/auth/entry/verify": self.send_response(204 if "gateway_fixture=yes" in self.headers.get("Cookie","") else 403)
        elif self.path.startswith("/api/auth/entry/open"):
            self.send_response(303);self.send_header("Location",prefix);self.send_header("Set-Cookie","gateway_fixture=yes; Secure; HttpOnly; Path="+prefix)
        elif self.path=="/api/auth/generateCaptcha/":
            self.send_response(301);self.send_header("Location","/api/auth/generateCaptcha")
        elif self.path=="/api/auth/generateCaptcha": self.send_response(200)
        elif self.path.startswith("/api/auth/subscribe/"):
            self.send_response(200);self.send_header("Content-Type","text/yaml")
        else: self.send_response(401)
        self.end_headers()
        if self.path.startswith("/api/auth/subscribe/"): self.wfile.write(b"rules: [MATCH,DIRECT]\n")
server=ThreadingHTTPServer(("127.0.0.1",8081),Fixture);threading.Thread(target=server.serve_forever,daemon=True).start()
def request(port,path,cookie=None):
    connection=http.client.HTTPSConnection("127.0.0.1",port,context=ssl._create_unverified_context(),timeout=5)
    connection.request("GET",path,headers={"Cookie":cookie} if cookie else {})
    response=connection.getresponse(); result=response.status,response.read(),dict(response.getheaders());connection.close();return result
with tempfile.TemporaryDirectory() as directory:
    directory=Path(directory);(directory/"ui/js").mkdir(parents=True);(directory/"web").mkdir()
    (directory/"ui/index.html").write_text("<!doctype html><head></head><body>fixture panel</body>")
    (directory/"ui/js/test.js").write_text("window.fixture=true;")
    (directory/"web/index.html").write_text("ordinary website")
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(directory/"test.key"),"-out",str(directory/"test.crt"),"-days","1","-subj","/CN=test.example"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    config=dict(panel_path=prefix,panel_domain="test.example",subscription_domain="test.example",panel_port=18888,subscription_port=18443,certificate="/cert/test.crt",private_key="/cert/test.key",entry_key_enabled=True)
    (directory/"nginx").mkdir()
    output=directory/"nginx/default.conf";state=directory/"gateway.json"
    output.write_text(render(config));state.write_text(json.dumps(config))
    args=["docker","run","--rm","--name","xwarp-gateway-ci","--network","host","-v",str(directory/"nginx")+":/etc/nginx/conf.d:ro","-v",str(directory)+":/cert:ro","-v",str(directory/"ui")+":/tpdata/trojan-panel-ui:ro","-v",str(directory/"web")+":/tpdata/web:ro","nginx:1.30.5-alpine"]
    subprocess.run(args+["nginx","-t"],check=True,stdout=subprocess.DEVNULL)
    subprocess.run(args[:2]+["-d"]+args[2:],check=True,stdout=subprocess.DEVNULL)
    try:
        for _ in range(30):
            try: request(18888,"/");break
            except OSError:time.sleep(1)
        assert request(18888,"/")[0]==200
        assert request(18888,prefix)[0]==404
        assert request(18888,prefix+"js/test.js")[0]==404
        assert request(18888,prefix+"api/account/info")[0]==404
        status,body,headers=request(18888,prefix+"_entry?key=fixture")
        assert status==303 and headers["Location"]==prefix
        cookie=headers["Set-Cookie"].split(";",1)[0]
        status,body,_=request(18888,prefix,cookie)
        assert status==200 and b"window.__XWARP_BASE__" in body and b"fixture panel" in body
        assert request(18888,prefix+"js/test.js",cookie)[0]==200
        assert request(18888,prefix+"api/account/info",cookie)[0]==401
        status,_,headers=request(18888,prefix+"api/auth/generateCaptcha/",cookie)
        assert status==301 and urlsplit(headers["Location"]).path==prefix+"api/auth/generateCaptcha"
        assert request(18888,urlsplit(headers["Location"]).path,cookie)[0]==200
        assert request(18888,prefix+"api/auth/subscribe/fixture",cookie)[0]==404
        assert request(18443,"/api/auth/subscribe/fixture")[0]==200
        status,body,headers=request(18443,"/")
        assert status==200 and b"ordinary website" in body and "Location" not in headers
        assert request(18443,prefix)[0]==404
        assert request(18443,"/api/auth/login")[0]==404
        old_config=output.read_text();old_state=state.read_text()
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1",18890))
            try: panel_port.change_port(18890,state,output,directory/"backups","xwarp-gateway-ci")
            except ValueError: pass
            else: raise AssertionError("Occupied port accepted")
        assert output.read_text()==old_config and state.read_text()==old_state
        real_probe=panel_port.probe
        def failed_new_port(value,*args):
            if value==18889: raise RuntimeError("simulated readiness failure")
            return real_probe(value,*args)
        with patch("panel_port.probe",side_effect=failed_new_port):
            try: panel_port.change_port(18889,state,output,directory/"backups","xwarp-gateway-ci")
            except RuntimeError: pass
            else: raise AssertionError("Failed readiness accepted")
        assert output.read_text()==old_config and state.read_text()==old_state
        assert request(18888,prefix,cookie)[0]==200
        panel_port.change_port(18891,state,output,directory/"backups","xwarp-gateway-ci")
        assert request(18891,prefix,cookie)[0]==200
        assert request(18891,prefix)[0]==404
        assert request(18443,"/api/auth/subscribe/fixture")[0]==200
        assert json.loads(state.read_text())["subscription_port"]==18443
        # Switch only the panel to the short root URL; keep subscription and login protection.
        config.update(panel_path="/", panel_port=18891, entry_key_enabled=False)
        output.write_text(render(config));state.write_text(json.dumps(config))
        subprocess.run(["docker","exec","xwarp-gateway-ci","nginx","-t"],check=True)
        subprocess.run(["docker","exec","xwarp-gateway-ci","nginx","-s","reload"],check=True)
        time.sleep(1)
        status,body,_=request(18891,"/")
        assert status==200 and b"fixture panel" in body and b'window.__XWARP_BASE__="/"' in body
        assert request(18891,"/js/test.js")[0]==200
        assert request(18891,"/api/account/info")[0]==401
        assert request(18891,"/api/auth/subscribe/fixture")[0]==404
        assert request(18443,"/api/auth/subscribe/fixture")[0]==200
        assert request(18443,"/api/auth/login")[0]==404
        assert b"ordinary website" in request(18443,"/")[1]
        panel_port.change_port(18892,state,output,directory/"backups","xwarp-gateway-ci")
        assert request(18892,"/")[0]==200
        assert json.loads(state.read_text())["panel_path"]=="/"
        assert request(18443,"/api/auth/subscribe/fixture")[0]==200
        print("HTTPS gateway passed: panel/resource/API gate, clean entry URL, public subscription isolation")
    finally:
        subprocess.run(["docker","stop","xwarp-gateway-ci"],stdout=subprocess.DEVNULL,check=False);server.shutdown()
