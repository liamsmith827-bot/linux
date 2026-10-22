#!/usr/bin/env python3
"""Record every remerge hunk and its literal relationship to the selected trees.

Literal presence is evidence for review, never a semantic equivalence verdict.
The remerge preimage includes conflict markers and is NOT either parent tree.
"""
import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])

def tree(ref):
    return {line.split('\t', 1)[1]: line.split('\t')[0].split()[2]
            for line in git('ls-tree', '-r', ref).decode().splitlines()}

trees = {key: tree(ref) for key, ref in [('ack', ACK), ('lts', LTS), ('port', 'HEAD')]}
paths = json.loads((D / 'evidence/path-review.json').read_text())
rows = {r['commit']: r for r in map(json.loads, (D / 'candidates.jsonl').read_text().splitlines())}
cache = {None: ''}
line_cache = {}

def contents(key, path):
    oid = trees[key].get(path)
    if oid not in cache:
        cache[oid] = git('cat-file', 'blob', oid).decode(errors='replace')
    return cache[oid]

def lines(key, path):
    lookup = (key, path)
    if lookup not in line_cache:
        line_cache[lookup] = set(contents(key, path).splitlines())
    return line_cache[lookup]

renames = {'drivers/net/wireless/virtual/mac80211_hwsim.c':
           'drivers/net/wireless/virtual/mac80211_hwsim_main.c',
           'rust/kernel/net/mod.rs': 'rust/kernel/net.rs'}
patch_text = (D / 'evidence/merge-resolutions.patch').read_text()
report = []
totals = collections.Counter()
for merge in re.split(r'^MERGE ', patch_text, flags=re.M)[1:]:
    sha = merge.split()[0]
    files = []
    for part in re.split(r'(?=^diff --git )', merge, flags=re.M)[1:]:
        match = re.match(r'diff --git a/(.+) b/(.+)\n', part)
        assert match, (sha, part[:100])
        old_path, path = match[1], match[2]
        assert path in paths, (sha, path)
        hunks = []
        for hunk in re.split(r'(?=^@@ )', part, flags=re.M)[1:]:
            header, _, body = hunk.partition('\n')
            # Keep the selected side of the remerge patch, including context.
            selected = ''.join(line[1:] for line in body.splitlines(keepends=True)
                               if line.startswith((' ', '+')))
            added = [line[1:] for line in body.splitlines() if line.startswith('+')]
            witness = {}
            for key in trees:
                candidate_paths = [path]
                if path in renames and key in ('ack', 'port'):
                    candidate_paths.append(renames[path])
                witness[key] = {
                    'selected_block_found_in': [p for p in candidate_paths
                                                if selected and selected in contents(key, p)],
                    'added_lines_found': sum(any(line in lines(key, p)
                                                 for p in candidate_paths)
                                             for line in added if line.strip()),
                }
            hunks.append({'header': header,
                          'remerge_hunk_sha256': hashlib.sha256(hunk.encode()).hexdigest(),
                          'selected_block_sha256': hashlib.sha256(selected.encode()).hexdigest(),
                          'nonblank_added_lines': sum(bool(line.strip()) for line in added),
                          'literal_witness': witness})
        files.append({'path': path, 'old_path': old_path, 'policy': paths[path]['policy'],
                      'specific_evidence': paths[path].get('specific_evidence'),
                      'result_commits': paths[path]['result_commits'], 'hunks': hunks,
                      'metadata_only_delta': not bool(hunks)})
        totals['hunks'] += len(hunks)
    covered = {p for f in files for p in (f['path'], f['old_path'])}
    assert set(rows[sha]['files']) <= covered, sha
    totals['merges'] += 1
    totals['nonempty_merges' if files else 'empty_merges'] += 1
    report.append({'commit': sha, 'files': files,
                   'disposition': rows[sha]['disposition']})
assert totals['merges'] == 2623 and totals['nonempty_merges'] == 511, totals
output = {'ack': ACK, 'lts': LTS, 'port': git('rev-parse', 'HEAD').decode().strip(),
          'method': __doc__, 'counts': dict(totals), 'merges': report}
(D / 'evidence/merge-hunk-examination.json').write_text(json.dumps(output, indent=2) + '\n')
print(dict(totals))
