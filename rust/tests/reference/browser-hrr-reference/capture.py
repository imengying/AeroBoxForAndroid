#!/usr/bin/env python3
"""Parent schedules this script under the shared bounded-build lock."""
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
parser.add_argument('--profiles', default='edge,qq')
parser.add_argument('--samples', type=int, default=16)
parser.add_argument('--test', action='store_true')
args = parser.parse_args()
root = args.root.resolve() if args.root else next(p for p in here.parents if (p / 'scripts/run-bounded-build.py').is_file())
out = args.output_dir.resolve() if args.output_dir else root / 'target/browser-hrr-reference-evidence'
out.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env.update(CGO_ENABLED='0', GOMAXPROCS='1', GOMEMLIMIT='256MiB', GOTOOLCHAIN='local', GOPROXY='off', PYTHONDONTWRITEBYTECODE='1')
if args.test:
    subprocess.run(['go', 'test', '-mod=readonly', '-p=1', '-count=1', '-timeout=3m', '-v', '.'], cwd=here, env=env, check=True)
    subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(here), '-p', 'test_analyze.py', '-v'], env=env, check=True)
program = root / 'target/reference-peers/browser-hrr-reference'
program.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(['go', 'build', '-mod=readonly', '-p=1', '-trimpath', '-o', str(program), '.'], cwd=here, env=env, check=True)
with (out / 'captures.json').open('w') as output:
    subprocess.run([str(program), '--profiles', args.profiles, '--samples', str(args.samples)], stdout=output, env=env, check=True)
with (out / 'validated-captures.json').open('w') as output:
    subprocess.run([sys.executable, str(here / 'analyze.py'), str(out / 'captures.json')], stdout=output, env=env, check=True)
values = json.loads((out / 'validated-captures.json').read_text())
print(json.dumps({'evidence': str(out), 'cases': len(values), 'skipped': sum(bool(v.get('skipped_reason')) for v in values),
                  'scope': 'two-flight HRR construction only; no authenticated handshake'}))
