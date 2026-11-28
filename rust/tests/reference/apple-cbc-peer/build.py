#!/usr/bin/env python3
"""Build the independent test peer under AeroBox's shared build lock."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True, type=Path)
parser.add_argument('--test', action='store_true')
args = parser.parse_args()
root = args.root.resolve()
here = Path(__file__).resolve().parent
metadata = json.loads((here/'upstream.json').read_text())
env = os.environ.copy()
env.update(CGO_ENABLED='0', GOMAXPROCS='1', GOMEMLIMIT='256MiB',
           GOTOOLCHAIN='local', GOPROXY='off')
cache = Path(subprocess.check_output(['go','env','GOMODCACHE'], env=env, text=True).strip())
source = cache/(metadata['module']+'@'+metadata['version'])
destination = root/'target/reference-utls-apple-cbc'
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(source/'LICENSE') == metadata['license_sha256']
assert all(sha(source/n)==h for n,h in metadata['upstream_files'].items())
assert sha(here/'aerobox_apple_fixture.go.txt') == metadata['shim_sha256']
if not destination.exists():
    shutil.copytree(source, destination)
    for path in destination.rglob('*'):
        if path.is_file():
            path.chmod(0o644)
    shutil.copy2(here/'aerobox_apple_fixture.go.txt', destination/'aerobox_apple_fixture.go')
assert all(sha(destination/n)==h for n,h in metadata['upstream_files'].items())
assert sha(destination/'aerobox_apple_fixture.go') == metadata['shim_sha256']
modfile = here/'.fixture-build.mod'
sumfile = here/'.fixture-build.sum'
original = (here/'go.mod').read_text()
expected = 'replace github.com/metacubex/utls => ../../../target/reference-utls-apple-cbc'
assert expected in original
modfile.write_text(original.replace(expected, 'replace github.com/metacubex/utls => '+json.dumps(str(destination))))
shutil.copy2(here/'go.sum', sumfile)
env['AEROBOX_TLS_FIXTURES'] = str(root/'crates/aerobox-crypto/tests/fixtures')
try:
    if args.test:
        subprocess.run(['go','test','-mod=readonly','-modfile='+str(modfile),'-p=1',
                        '-count=1','-timeout=5m','-v','.'],cwd=here,env=env,check=True)
    program = root/'target/reference-peers/apple-cbc'
    program.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run(['go','build','-mod=readonly','-modfile='+str(modfile),'-p=1',
                    '-trimpath','-o',str(program),'.'],cwd=here,env=env,check=True)
    print(program)
finally:
    modfile.unlink(missing_ok=True)
    sumfile.unlink(missing_ok=True)
