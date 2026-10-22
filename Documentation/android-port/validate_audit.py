#!/usr/bin/env python3
"""Check ledger coverage and evidence integrity, not semantic review quality."""
import argparse
import collections
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--previous-checkpoint', help='Optionally reject lost final decisions since this commit')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
D = Path(__file__).resolve().parent
ROOT = D.parents[1]
E = D/'evidence'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True)

def read(name):
    return json.loads((E/name).read_text())

rows = [json.loads(line) for line in (D/'candidates.jsonl').read_text().splitlines()]
byid = {r['commit']: r for r in rows}
expected = set(git('rev-list', ACK, '--not', LTS).splitlines())
assert len(rows) == len(byid) == len(expected) == 11731
assert set(byid) == expected
ancestors = set(git('rev-list', 'HEAD').splitlines())
progress = read('progress.json')
source = progress['source_head']
assert source in ancestors
assert not git('diff', '--name-only', source, 'HEAD', '--', '.', ':!Documentation/android-port')
assert not git('diff', '--name-only', 'HEAD', '--', '.', ':!Documentation/android-port')
for r in rows:
    assert r['rationale'] and r['evidence'] and r['disposition'] != 'pending', r['commit']
    assert r['code_review_head'] == source, r['commit']
    assert r['review_status'] in {'reviewed', 'draft-net-reconciliation'}
    assert set(r['result_commits']) <= ancestors, r['commit']
    if r['review_status'] == 'reviewed' and (r['disposition'].startswith(('adapted', 'partially-adapted')) or r['disposition'] == 'applied'):
        assert r['result_commits'], r['commit']
final = {r['commit'] for r in rows if r['review_status'] == 'reviewed'}
assert progress['candidate_count'] == len(rows)
assert progress['finalized_count'] == len(final)
assert progress['provisional_count'] == len(rows) - len(final)
assert progress['finalized_percent'] == round(100 * len(final) / len(rows), 2)
assert dict(collections.Counter(r['disposition'] for r in rows)) == read('decision-counts.json')

paths = read('path-review.json')
decisions = read('final-net-decisions.json')['decisions']
net = {d['commit']: d for d in decisions}
assert len(net) == len(decisions)
explicit = read('explicit-code-decisions.json')
kmi = read('explicit-kmi-decisions.json')
for records in (explicit, kmi):
    assert len(records) == len({d['commit'] for d in records})
    assert {d['commit'] for d in records} <= expected
assert not set(net) & {d['commit'] for d in explicit}
for r in rows:
    if r.get('final_net_review') and r['review_status'] == 'reviewed':
        d = net[r['commit']]
        assert set(d['path_witnesses']) == set(r['files']), r['commit']
        assert all(all(paths[path].get(k) == v for k, v in witness.items())
                   for path, witness in d['path_witnesses'].items()), r['commit']

# Explicitly pending feature selection must not become final via a path refresh.
pending = {'7a2a62c55dab', 'e35913a77139', '13fa503273ef', 'f24ebb94679f'}
for question in read('unresolved-feature-questions.json'):
    if 'remain provisional' in question['status'] or 'candidate remains provisional' in question['status']:
        pending.update(question.get('candidates', []))
for prefix in pending:
    matches = [r for sha, r in byid.items() if sha.startswith(prefix)]
    assert len(matches) == 1 and matches[0]['review_status'] == 'draft-net-reconciliation', prefix

merges = read('merge-hunk-examination.json')
index = read('merge-index.json')
merge_ids = {r['commit'] for r in rows if len(r['parents']) > 1}
assert merges['port'] == source
assert {m['commit'] for m in merges['merges']} == {m['commit'] for m in index} == merge_ids
assert len(merges['merges']) == len(index) == 2623
counts = merges['counts']
assert counts == {'hunks': 10450, 'merges': 2623, 'nonempty_merges': 511, 'empty_merges': 2112}
assert sum(len(f['hunks']) for m in merges['merges'] for f in m['files']) == counts['hunks']
stable = read('full-stable-overlaps.json')
assert stable['port'] == source
assert all(x.get('assessment') and x['status'].startswith('reviewed') for x in stable['overlaps'])

previous_count = None
if a.previous_checkpoint:
    old = [json.loads(line) for line in git('show', a.previous_checkpoint+':Documentation/android-port/candidates.jsonl').splitlines()]
    old_final = {r['commit'] for r in old if r['review_status'] == 'reviewed'}
    assert old_final <= final, sorted(old_final - final)
    previous_count = len(old_final)
result = {'source_head': source, 'candidate_count': len(rows), 'finalized_count': len(final),
          'provisional_count': len(rows)-len(final), 'merge_counts': counts,
          'assessed_stable_textual_overlaps': len(stable['overlaps']),
          'previous_checkpoint': a.previous_checkpoint, 'previous_finalized_count': previous_count,
          'scope': 'Inventory, ancestor IDs, current final-net witnesses, explicitly provisional questions, merge coverage and overlap-assessment presence. Does not certify semantic correctness or runtime compatibility.'}
a.output.write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
