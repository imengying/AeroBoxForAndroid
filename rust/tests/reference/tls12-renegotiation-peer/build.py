#!/usr/bin/env python3
"""Build a test-only RFC5746 server from an exact cached uTLS version.
Invoke using scripts/run-bounded-build.py to serialize builds and cap RAM.
"""
from pathlib import Path
import hashlib,json,os,shutil,subprocess
root=Path(__file__).resolve().parents[3];here=Path(__file__).resolve().parent
meta=json.loads((here/'upstream.json').read_text())
env=os.environ.copy();env.update(CGO_ENABLED='0',GOMAXPROCS='1',GOMEMLIMIT='256MiB',GOTOOLCHAIN='local',GOPROXY='off')
cache=Path(subprocess.check_output(['go','env','GOMODCACHE'],env=env,text=True).strip())
source=cache/(meta['module']+'@'+meta['version']);dest=root/'target/reference-utls-renegotiation'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for name,h in meta['files'].items():
 if h['original'] is not None:assert digest(source/name)==h['original'],f'upstream source changed: {name}'
if dest.exists():
 assert all(digest(dest/name)==h['patched']for name,h in meta['files'].items()),'existing reference fork differs; review before replacing'
else:
 shutil.copytree(source,dest)
 for p in dest.rglob('*'):
  if p.is_file():p.chmod(0o644)
 subprocess.run(['patch','--batch','--forward','-p1','-i',str(here/'utls-fixture.patch')],cwd=dest,check=True)
 assert all(digest(dest/name)==h['patched']for name,h in meta['files'].items())
program=root/'target/reference-peers/tls12-renegotiation';program.parent.mkdir(exist_ok=True,parents=True)
subprocess.run(['go','build','-mod=readonly','-p=1','-trimpath','-o',str(program),'.'],cwd=here,env=env,check=True)
print(program)
