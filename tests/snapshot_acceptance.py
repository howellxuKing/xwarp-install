"""Restore an isolated CI fixture database/config/cache; not a server deployment."""
import json,os,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from snapshot import create_backup,restore_backup,run
if os.getenv("GITHUB_ACTIONS")!="true":raise SystemExit("CI only")
names=["trojan-panel-mariadb","trojan-panel-redis","trojan-panel"]
if any(name in run(["docker","ps","-a","--format","{{.Names}}" ]).decode().split() for name in names):raise SystemExit("Fixture names already exist")
def sql(value):
    return run(["docker","exec","trojan-panel-mariadb","sh","-c",'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb -uroot -N -e "$1"',"fixture",value]).decode().strip()
with tempfile.TemporaryDirectory() as directory:
    config=Path("/tpdata/trojan-panel/config");config.mkdir(parents=True)
    (config/"security.key").write_bytes(b"a"*32);os.chmod(config/"security.key",0o600)
    try:
        run(["docker","run","-d","--name",names[0],"--network","host","-e","MYSQL_ROOT_PASSWORD=ci-snapshot-password","-e","MYSQL_DATABASE=trojan_panel_db","mariadb:10.7.3","--port","33079","--bind-address=127.0.0.1"])
        run(["docker","run","-d","--name",names[1],"--network","host","redis:6.2.7","redis-server","--port","33379","--bind","127.0.0.1","--requirepass","ci-cache-password"])
        run(["docker","run","-d","--name",names[2],"--network","host","-v","/tpdata/trojan-panel/config:/data","alpine:3.24.2","sleep","3600"])
        for _ in range(60):
            try:sql("SELECT 1");break
            except RuntimeError:time.sleep(1)
        sql("CREATE TABLE trojan_panel_db.fixture(id INT PRIMARY KEY,value VARCHAR(40));INSERT INTO trojan_panel_db.fixture VALUES(1,'original')")
        archive=create_backup(directory,quiesce=True,include_images=False)
        sql("UPDATE trojan_panel_db.fixture SET value='changed';CREATE TABLE trojan_panel_db.extra(id INT)")
        (config/"security.key").write_bytes(b"b"*32)
        run(["docker","exec","-e","REDISCLI_AUTH=ci-cache-password",names[1],"redis-cli","-p","33379","SET","trojan-panel:token:fixture","old-session"])
        restore_backup(archive,archive.name)
        assert sql("SELECT value FROM trojan_panel_db.fixture")=="original"
        assert sql("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='trojan_panel_db' AND table_name='extra'")=="0"
        assert (config/"security.key").read_bytes()==b"a"*32
        assert run(["docker","exec","-e","REDISCLI_AUTH=ci-cache-password",names[1],"redis-cli","-p","33379","EXISTS","trojan-panel:token:fixture"]).strip()==b"0"
        restored=json.loads(run(["docker","inspect",names[2]]))[0]
        assert restored["State"]["Running"]
        print("Isolated restore passed: SQL/schema, master key, session invalidation, original app container")
    finally:
        for name in reversed(names):subprocess.run(["docker","rm","-f",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
