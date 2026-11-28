#!/usr/bin/env python3
"""Prepare (never compile) pure-Rust internal failure tests from an overlaid source tree.

Ordinary rustls dev-dependencies select rcgen/aws-lc. Instead, copy its production
library and turn only the three relevant internal test modules into explicitly
selected integration test crates. Production Rust tokens are unchanged; cfg(test)
is disabled everywhere, including inside the included library, except the selected
module's outer gate. Rust's test harness still discovers #[test] inside that module.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import tomllib

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True, type=Path, help='validation tree containing final staged product sources')
parser.add_argument('--output', required=True, type=Path, help='new scratch harness directory; must not exist')
parser.add_argument('--overlay', type=Path, help='optional isolated files overlay; preparation only')
args = parser.parse_args()
root = args.root.resolve()
overlay = args.overlay.resolve() if args.overlay else None
out = args.output.resolve()
if out.exists():
    raise SystemExit('refusing to overwrite existing harness')
crate = root/'vendor/rustls/rustls'
meta = tomllib.loads((crate/'Cargo.toml').read_text())
workspace = tomllib.loads((root/'vendor/rustls/Cargo.toml').read_text())
selected = {'src/record_layer.rs': 'tests',
            'src/common_state.rs': 'encryption_failure_tests',
            'src/conn/unbuffered.rs': 'fatal_write_tests'}
out.mkdir(parents=True)
manifest = ['[package]', 'name = "rustls-encryption-failure-tests"', 'version = "0.0.0"',
            'edition = "2021"', 'autotests = false', 'autobenches = false',
            '[workspace]', 'resolver = "3"', '[lib]', 'path = "src/lib.rs"', 'test = false',
            '[features]', 'default = ["std", "tls12"]', 'std = ["webpki/std", "pki-types/std", "once_cell/std"]',
            'tls12 = []', 'custom-provider = []', '[dependencies]']

def value(item):
    if isinstance(item, str): return json.dumps(item)
    if isinstance(item, bool): return 'true' if item else 'false'
    if isinstance(item, list): return '['+', '.join(value(v) for v in item)+']'
    if isinstance(item, dict): return '{'+', '.join(f'{k} = {value(v)}' for k,v in item.items())+'}'
    raise TypeError(item)

for name, dep in meta['dependencies'].items():
    if isinstance(dep, dict) and dep.get('optional'):
        continue
    if isinstance(dep, dict) and dep.get('workspace'):
        inherited = workspace['workspace']['dependencies'][name]
        dep = {'version': inherited} if isinstance(inherited,str) else inherited.copy()
        dep.update({k:v for k,v in meta['dependencies'][name].items() if k != 'workspace'})
    manifest.append(f'{name} = {value(dep)}')
for source, module in selected.items():
    manifest.extend(['[[test]]', 'name = '+json.dumps(source.replace('src/','').replace('/','_').replace('.rs','')),
                     'path = '+json.dumps('unit-'+source.replace('src/','').replace('/','-')+'/lib.rs')])
manifest.extend(['[profile.dev]', 'debug = 1', 'incremental = false', '[profile.release]', 'debug = 0',
                 '[lints.rust]', 'unexpected_cfgs = "allow"'])
(out/'Cargo.toml').write_text('\n'.join(manifest)+'\n')
records=[]
# A non-test lib gives Cargo a normal target and contains no test-only dependencies.
for tree, selected_file in [('src',None)] + [('unit-'+p.replace('src/','').replace('/','-'),p) for p in selected]:
    for source in (crate/'src').rglob('*'):
        if not source.is_file(): continue
        if overlay and (overlay/source.relative_to(root)).is_file():
            source = overlay/source.relative_to(root)
        relative = source.relative_to((overlay/'vendor/rustls/rustls/src') if overlay and source.is_relative_to(overlay) else crate/'src')
        target = out/tree/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        if source.suffix != '.rs':
            shutil.copy2(source,target)
            continue
        original = source.read_text()
        # Only cfg attributes change; no implementation lines are substituted.
        text = re.sub(r'#\[cfg\((.*?)\)\]',
                      lambda m: '#[cfg('+re.sub(r'\btest\b','any()',m.group(1))+')]',
                      original, flags=re.S)
        if selected_file == 'src/'+str(relative):
            marker = '#[cfg(any())]\nmod '+selected[selected_file]+' {'
            assert text.count(marker)==1, (relative,marker)
            text = text.replace(marker,'mod '+selected[selected_file]+' {')
        target.write_text(text)
        records.append({'source':str(source), 'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                        'harness':str(target.relative_to(out)), 'harness_sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
(out/'source-mapping.json').write_text(json.dumps(records,indent=2)+'\n')
print(out/'Cargo.toml')
print('After preparation run Cargo under scripts/run-bounded-build.py:')
print('cargo generate-lockfile --offline --manifest-path '+str(out/'Cargo.toml'))
print('cargo tree --offline --locked --manifest-path '+str(out/'Cargo.toml')+' --edges normal,build --prefix none')
print('cargo test --offline --locked --manifest-path '+str(out/'Cargo.toml')+' --tests -- --test-threads=1')
print('cargo test --offline --locked --release --manifest-path '+str(out/'Cargo.toml')+' --tests -- --test-threads=1')
