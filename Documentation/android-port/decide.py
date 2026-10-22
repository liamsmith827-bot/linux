#!/usr/bin/env python3
"""Record reviewed decisions supplied as a JSON file, without inferring them."""
import json
import sys
from inventory import HERE, render

rows = [json.loads(x) for x in (HERE / 'candidates.jsonl').read_text().splitlines()]
decisions = json.loads(open(sys.argv[1]).read())
for d in decisions:
    matches = [r for r in rows if r['commit'].startswith(d['commit'])]
    assert len(matches) == 1, d['commit']
    r = matches[0]
    for key in ('disposition', 'rationale', 'evidence', 'result_commits'):
        if key in d:
            r[key] = d[key]
with (HERE / 'candidates.jsonl').open('w') as f:
    for r in rows:
        f.write(json.dumps(r) + '\n')
render(rows)
