#!/usr/bin/env python3
"""Compare every non-random record byte, with strict full 360 template checks."""
import json, sys
from normalize import normalize_wire

def cases(path):
    values=json.loads(open(path).read())
    out={}
    for case in values:
        if case['name']!='360' or 'skipped_reason' in case: continue
        assert not case.get('build_error') and not case.get('panic') and not case.get('validation_error')
        key=case['case']; assert key not in out
        wire=normalize_wire(bytes.fromhex(case['wire_hex']))
        assert wire['hello_version']=='0303' and wire['session_id_length']==32
        assert wire['ciphers']==['c00a','c014','0039','006b','0035','003d','c007','c009','c023','c011','c013','c027','0033','0067','0032','0005','0004','002f','003c','000a']
        out[key]=wire
    assert len(out)>=10
    return out

a,b=map(cases,sys.argv[1:3]);assert set(a)==set(b)
for key in a:
    assert a[key]==b[key], key
print(json.dumps({'phase':'360-full-wire-matched','cases':len(a)}))
