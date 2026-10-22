#!/usr/bin/env python3
"""Reproducible local input and ACK commit inventory; no network access."""
import concurrent.futures
import csv
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
LINUX = HERE.parents[1]
ROOT = LINUX.parent
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True)

def pin_project(item):
    root, project = item
    path = root / project
    return [project, git(path, 'rev-parse', 'HEAD').strip(),
            git(path, 'status', '--porcelain', '--untracked-files=no').strip(),
            git(path, 'config', '--get-regexp', r'^remote\..*\.url$').strip()]

def pins(root, name):
    projects = ['.repo/manifests', '.repo/repo'] + (root / '.repo/project.list').read_text().splitlines()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(pin_project, [(root, p) for p in projects]))
    with (HERE / 'inputs' / name).open('w') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(['path', 'commit', 'tracked_changes', 'configured_remotes'])
        w.writerows(rows)

def commit_info(line):
    sha, parents, subject = line.split('\t', 2)
    pp = parents.split()
    paths = git(LINUX, 'diff-tree', '--no-commit-id', '--name-only', '-r', pp[0], sha).splitlines()
    return dict(commit=sha, parents=pp, subject=subject, files=paths,
                disposition='pending', rationale='', evidence=[], result_commits=[])

def render(rows):
    columns = ['commit', 'parents', 'subject', 'files', 'disposition',
               'review_status', 'rationale', 'evidence', 'result_commits']
    with (HERE / 'candidates.tsv').open('w') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(columns)
        for r in rows:
            values = []
            for key in columns:
                value = r.get(key, 'pending' if key == 'review_status' else '')
                if isinstance(value, list):
                    value = '; '.join(value)
                values.append(value or '-')
            w.writerow(values)

if __name__ == '__main__':
    (HERE / 'inputs').mkdir(exist_ok=True)
    pins(ROOT / 'kernel_manifest-6.18', 'kernel-projects.tsv')
    pins(ROOT / 'grapheneos-17', 'grapheneos-projects.tsv')
    lines = git(LINUX, 'log', '--reverse', '--topo-order', '--format=%H%x09%P%x09%s', ACK, '--not', LTS).splitlines()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(commit_info, lines))
    with (HERE / 'candidates.jsonl').open('w') as f:
        for row in rows:
            f.write(json.dumps(row) + '\n')
    render(rows)
    print(f'Inventoried {len(rows)} candidates, {sum(len(r["parents"]) > 1 for r in rows)} merges')
