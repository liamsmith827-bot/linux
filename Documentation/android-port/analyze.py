#!/usr/bin/env python3
"""Attach mechanically verifiable evidence; leave semantic questions pending."""
import collections
import json
from pathlib import Path
import re
import subprocess
from inventory import ACK, LTS, LINUX, HERE, git, render

rows = [json.loads(x) for x in (HERE / 'candidates.jsonl').read_text().splitlines()]
merges = {r['commit']: r for r in json.loads((HERE / 'evidence/merge-index.json').read_text())}
different = set(git(LINUX, 'diff', '--name-only', ACK, LTS).splitlines())

def patch_ids(name):
    result = collections.defaultdict(list)
    for line in (HERE / 'evidence' / name).read_text().splitlines():
        patch, commit = line.split()
        result[patch].append(commit)
    return result

ack_ids = {commit: patch for patch, commits in patch_ids('ack-patch-ids.txt').items() for commit in commits}
lts_ids = patch_ids('lts-patch-ids.txt')
for row in rows:
    sha = row['commit']
    if sha in merges:
        row['first_parent_file_count'] = len(row['files'])
        row['files'] = merges[sha]['files']
        row['file_semantics'] = 'remerge-resolution paths; parents are separately inventoried'
        row['evidence'] = ['evidence/merge-resolutions.patch: MERGE ' + sha]
        if not row['files']:
            row['disposition'] = 'merge-no-unique-resolution'
            row['rationale'] = ('Reconstructing this merge with git --remerge-diff produces no resolution delta. '
                                'No independent code to port; parent changes are assessed separately. '
                                'This does not claim that the merged parent changes are unnecessary.')
    else:
        row['file_semantics'] = 'parent-to-commit changed paths'
        patch = ack_ids.get(sha)
        if patch in lts_ids:
            row['upstream_patch_equivalents'] = lts_ids[patch]
            row['evidence'].append('stable patch-id ' + patch + ': ' + ', '.join(lts_ids[patch]))
            row['disposition'] = 'already-represented-upstream'
            row['rationale'] = ('An identical stable patch-id is present in the pinned 6.18.y history; '
                                'retain the LTS implementation and its subsequent fixes, without reapplying this patch.')
        elif row['files'] and not (set(row['files']) & different):
            row['disposition'] = 'superseded-identical-final-files'
            row['rationale'] = ('All paths changed by this commit have identical final content at the pinned ACK and LTS '
                                'tips (git diff --name-only ACK LTS). There is no remaining ACK code delta on these '
                                'paths to port. Retain the LTS files; this does not claim original patch identity.')
            row['evidence'].append('git diff --name-only ' + ACK + ' ' + LTS + ' -- [row files]: empty')

with (HERE / 'candidates.jsonl').open('w') as f:
    for row in rows:
        f.write(json.dumps(row) + '\n')
render(rows)
print(dict(collections.Counter(r['disposition'] for r in rows)))
