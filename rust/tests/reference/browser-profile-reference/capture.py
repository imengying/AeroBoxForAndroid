#!/usr/bin/env python3
"""Run only under scripts/run-bounded-build.py. New evidence stays outside sources."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path)
parser.add_argument('--output-dir', type=Path)
parser.add_argument('--profiles', default='chrome,android,edge,qq,firefox,safari,ios,360')
parser.add_argument('--test', action='store_true')
args = parser.parse_args()
root = args.root.resolve() if args.root else next(p for p in here.parents if (p / 'crates/aerobox-crypto/tests/fixtures').is_dir())
out = args.output_dir.resolve() if args.output_dir else root / 'target/browser-profile-reference-evidence'
out.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env.update(CGO_ENABLED='0', GOMAXPROCS='1', GOMEMLIMIT='256MiB', GOTOOLCHAIN='local', GOPROXY='off')
if args.test:
    subprocess.run(['go', 'test', '-mod=readonly', '-p=1', '-count=1', '-timeout=3m', '-v', '.'], cwd=here, env=env, check=True)
    subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(here), '-p', 'test_normalize.py', '-v'], env=env, check=True)
program = root / 'target/reference-peers/browser-profile-reference'
program.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(['go', 'build', '-mod=readonly', '-p=1', '-trimpath', '-o', str(program), '.'], cwd=here, env=env, check=True)
with (out / 'captures.json').open('w') as output:
    subprocess.run([str(program), '--profiles', args.profiles], stdout=output, env=env, check=True)
with (out / 'normalized-captures.json').open('w') as output:
    subprocess.run([sys.executable, str(here / 'normalize.py'), str(out / 'captures.json')], stdout=output, env=env, check=True)
values = json.loads((out / 'normalized-captures.json').read_text())
print(json.dumps({'evidence': str(out), 'cases': len(values), 'skipped': sum(bool(v.get('skipped_reason')) for v in values), 'scope': 'first-flight construction, not successful handshakes'}))
