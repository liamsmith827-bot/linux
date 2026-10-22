#!/usr/bin/env python3
"""Analysis-only ACK normalization. Never modifies the destination Linux tree."""
import json
import re
import subprocess
from pathlib import Path
from inventory import HERE, ROOT

repo = ROOT / 'ack-port-analysis'
def run(*args, **kwargs):
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, **kwargs)

rows = json.loads((HERE / 'evidence/kmi-revert-candidates.json').read_text())
pending = rows[:]
done = []
while pending:
    progress = False
    for r in pending[:]:
        patch = run('show', '--format=', '--binary', r['commit']).stdout
        check = run('apply', '--reverse', '--check', input=patch)
        if check.returncode:
            r['reverse_failure'] = check.stderr.decode()
            continue
        apply = run('apply', '--reverse', input=patch)
        assert apply.returncode == 0, apply.stderr
        done.append(r['commit'])
        pending.remove(r)
        progress = True
    if not progress: break

log = {'reversed_abi_only_reverts':done, 'unresolved_abi_only_reverts':pending}
(HERE / 'evidence/ack-normalization.json').write_text(json.dumps(log,indent=2)+'\n')
print(f'Reversed {len(done)} exact ABI-only reverts; {len(pending)} require review')

# Strip only the binary-layout/versioning abstraction, preserving new fields.
# Vendor/OEM data is runtime module storage and is deliberately untouched.
paths = run('grep', '-l', '-E', 'ANDROID_(KABI|BACKPORT)_|android_kabi.h').stdout.decode().splitlines()
counts = {}
for name in paths:
    if name == 'include/linux/android_kabi.h': continue
    p = repo / name
    if p.suffix not in ['.h', '.c', '.rs']: continue
    s = p.read_text()
    s = re.sub(r'^#include <linux/android_kabi.h>\n', '', s, flags=re.M)
    # All current non-definition invocations have at most one nested level;
    # balanced parsing also handles function pointers and multiline declarations.
    pattern = r'\bANDROID_(?:KABI|BACKPORT)_\w+\('
    replacements = 0
    pos = 0
    while (m := re.search(pattern, s[pos:])):
        start = pos + m.start(); end = pos + m.end(); first = end
        macro = s[start:end-1]
        depth = 1
        args = []
        while depth:
            c = s[end]
            if c == '(' : depth += 1
            elif c == ')': depth -= 1
            elif c == ',' and depth == 1:
                args.append(s[first:end].strip()); first = end + 1
            end += 1
        args.append(s[first:end-1].strip())
        if macro in ['ANDROID_KABI_USE', 'ANDROID_BACKPORT_USE', 'ANDROID_KABI_IGNORE']:
            replacement = args[1]
        elif macro == 'ANDROID_KABI_REPLACE': replacement = args[2]
        elif macro == 'ANDROID_KABI_USE2': replacement = '; '.join(args[1:])
        elif macro in ['ANDROID_KABI_RESERVE','ANDROID_BACKPORT_RESERVE','ANDROID_KABI_DECLONLY',
                       'ANDROID_KABI_ENUMERATOR_IGNORE','ANDROID_KABI_ENUMERATOR_VALUE',
                       'ANDROID_KABI_BYTE_SIZE','ANDROID_KABI_TYPE_STRING']:
            replacement = ''
            if end < len(s) and s[end] == ';': end += 1
            # Remove the entire line if this was a standalone annotation.
            beginning = s.rfind('\n', 0, start) + 1
            trailing = s.find('\n', end)
            if trailing >= 0 and not s[beginning:start].strip() and not s[end:trailing].strip():
                start = beginning; end = trailing + 1
        else: raise ValueError((name, macro))
        s = s[:start] + replacement + s[end:]
        pos = start + len(replacement)
        replacements += 1
    p.write_text(s)
    counts[name] = replacements
log['removed_kabi_annotations'] = counts
(HERE / 'evidence/ack-normalization.json').write_text(json.dumps(log,indent=2)+'\n')
print(f'Removed binary KABI annotations from {len(counts)} files; retained runtime vendor data')
