#!/usr/bin/env python3
"""Prepare/build only this independent test peer. Build through the shared lock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, help='AeroBox source/overlay root')
parser.add_argument('--prepare-only', action='store_true', help='verify/copy/patch; do not compile')
parser.add_argument('--test', action='store_true', help='run the serial reference self-tests before building')
args = parser.parse_args()
root = args.root.resolve() if args.root else next(
    p for p in here.parents if (p / 'crates/aerobox-crypto/tests/fixtures').is_dir()
)
metadata = json.loads((here / 'upstream.json').read_text())
env = os.environ.copy()
env.update(CGO_ENABLED='0', GOMAXPROCS='1', GOMEMLIMIT='256MiB', GOTOOLCHAIN='local', GOPROXY='off')
cache = Path(subprocess.check_output(['go', 'env', 'GOMODCACHE'], env=env, text=True).strip())
source = cache / (metadata['module'] + '@' + metadata['version'])
destination = root / 'target/reference-utls-record-size-legacy'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

for name, hashes in metadata['files'].items():
    if hashes['original'] is not None:
        assert digest(source / name) == hashes['original'], f'upstream source changed: {name}'
assert digest(source / 'LICENSE') == metadata['license_sha256']
assert digest(here / 'utls-fixture.patch') == metadata['patch_sha256']
if destination.exists():
    assert all(digest(destination / name) == hashes['patched'] for name, hashes in metadata['files'].items()), 'existing legacy reference differs; review before replacing'
else:
    shutil.copytree(source, destination)
    for path in destination.rglob('*'):
        if path.is_file():
            path.chmod(0o644)
    subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(here / 'utls-fixture.patch')], cwd=destination, check=True)
    assert all(digest(destination / name) == hashes['patched'] for name, hashes in metadata['files'].items())
if args.prepare_only:
    print(destination)
else:
    # A modfile beside the staged module permits both a main-tree checkout and
    # a stage/overlay checkout without changing the frozen go.mod replace line.
    modfile = here / '.fixture-build.mod'
    sumfile = here / '.fixture-build.sum'
    original_mod = (here / 'go.mod').read_text()
    expected = 'replace github.com/metacubex/utls => ../../../target/reference-utls-record-size-legacy'
    assert expected in original_mod
    modfile.write_text(original_mod.replace(expected, f'replace github.com/metacubex/utls => {json.dumps(str(destination))}'))
    shutil.copyfile(here / 'go.sum', sumfile)
    env.setdefault('AEROBOX_TLS_FIXTURES', str(root / 'crates/aerobox-crypto/tests/fixtures'))
    try:
        if args.test:
            subprocess.run(['go', 'test', '-mod=readonly', '-modfile=' + str(modfile), '-p=1', '-count=1', '-timeout=15m', '-v', '.'], cwd=here, env=env, check=True)
        program = root / 'target/reference-peers/record-size-legacy'
        program.parent.mkdir(exist_ok=True, parents=True)
        subprocess.run(['go', 'build', '-mod=readonly', '-modfile=' + str(modfile), '-p=1', '-trimpath', '-o', str(program), '.'], cwd=here, env=env, check=True)
        print(program)
    finally:
        modfile.unlink(missing_ok=True)
        sumfile.unlink(missing_ok=True)
