#!/usr/bin/env python3
"""Collect whole-patch presence witnesses without changing the source or ledger.

A reverse-apply check against temporary indexes tests whether all post-change
hunks are present in a committed tree. It is not a proof of semantic equivalence,
runtime correctness, or necessity. Only single-parent candidates are checked;
merge resolutions have a separate remerge/hunk audit.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

D = Path(__file__).resolve().parent
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
HEAD = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
rows = [json.loads(l) for l in (D / 'candidates.jsonl').read_text().splitlines()]
rows = [r for r in rows if len(r['parents']) == 1 and
        r['review_status'] != 'reviewed' and r['files']]

with tempfile.TemporaryDirectory(prefix='ack-patch-presence-') as temp:
    envs = {}
    for name, ref in [('lts', LTS), ('port', HEAD)]:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temp) / name))
        subprocess.run(['git', 'read-tree', ref], env=env, check=True)
        envs[name] = env

    def check(row):
        patch = subprocess.check_output([
            'git', 'diff-tree', '--no-commit-id', '--no-ext-diff',
            '--binary', '--full-index', '-p', row['commit']])
        assert patch, row['commit']
        present = []
        for name, env in envs.items():
            result = subprocess.run([
                'git', 'apply', '--reverse', '--check', '--cached',
                '--whitespace=nowarn', '-'], input=patch, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                present.append(name)
        return dict(commit=row['commit'], patch_sha256=hashlib.sha256(patch).hexdigest(),
                    present_in=present)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(check, rows))

report = dict(lts=LTS, port=HEAD,
              method='git apply --reverse --check --cached against temporary indexes of the pinned trees; no source or index mutation',
              limits='Whole textual patch presence is not a semantic-equivalence or runtime proof. Absent witnesses do not mean a fix is absent; later refactors can change context.',
              results=results)
(D / 'evidence/whole-patch-presence.json').write_text(json.dumps(report, indent=2) + '\n')
print('Checked', len(results), 'single-parent candidates;',
      sum('lts' in r['present_in'] for r in results), 'LTS witnesses;',
      sum('port' in r['present_in'] for r in results), 'port witnesses')
