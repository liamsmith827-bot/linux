#!/usr/bin/env python3
"""Exercise real Kbuild header export with isolated kernel/module output trees."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RESULT = ROOT / 'Documentation/android-port/evidence/external-uapi-check.json'
PREFIX = '/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */\n'
records = []

def run(cmd, expected=0):
    p = subprocess.run(cmd, text=True, capture_output=True)
    records.append(dict(command=cmd, exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr))
    assert (p.returncode == 0) == (expected == 0), records[-1]
    return p

def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(PREFIX + text)

with tempfile.TemporaryDirectory(prefix='android-uapi-check-') as tmp:
    d = Path(tmp)
    kernel = d / 'kernel'
    (kernel / 'scripts').mkdir(parents=True)
    run(['cc', '-O2', '-o', str(kernel / 'scripts/unifdef'), str(ROOT / 'scripts/unifdef.c')])
    sentinel = kernel / 'usr/include/audit/sentinel.h'
    put(sentinel, '#define KERNEL_OUTPUT_MUST_SURVIVE 1\n')
    original_sentinel = sentinel.read_bytes()
    for mode in ['separate-custom', 'separate-default', 'source-default']:
        src = d / (mode + '-src')
        out = src if mode == 'source-default' else d / (mode + '-out')
        install = d / 'custom-install' if mode == 'separate-custom' else out / 'usr'
        put(src / 'include/uapi/audit/public.h', '#define AUDIT_PUBLIC 4660\n#ifdef __KERNEL__\n#define AUDIT_PRIVATE 1\n#endif\n')
        put(src / 'arch/x86/include/uapi/asm/audit_arch.h', '#define AUDIT_ARCH 64\n')
        put(out / 'include/generated/uapi/audit/generated.h', '#define AUDIT_GENERATED 1\n')
        put(out / 'arch/x86/include/generated/uapi/asm/audit_generated.h', '#define AUDIT_ARCH_GENERATED 1\n')
        put(src / 'include/uapi/audit/precedence.h', '#define AUDIT_SOURCE_WINS 1\n')
        put(out / 'include/generated/uapi/audit/precedence.h', '#define AUDIT_GENERATED_LOSES 1\n')
        cmd = ['make', '-s', '-C', str(ROOT), 'O=' + str(kernel), 'M=' + str(src), 'ARCH=x86_64']
        if mode != 'source-default':
            cmd.append('MO=' + str(out))
        if mode == 'separate-custom':
            cmd.append('INSTALL_HDR_PATH=' + str(install))
        run(cmd + ['headers_install'])
        expected = {'audit/public.h', 'audit/generated.h', 'audit/precedence.h', 'asm/audit_arch.h', 'asm/audit_generated.h'}
        actual = {str(p.relative_to(install / 'include')) for p in (install / 'include').rglob('*.h')}
        assert actual == expected, (mode, actual)
        assert 'AUDIT_PUBLIC 4660' in (install / 'include/audit/public.h').read_text()
        assert 'AUDIT_PRIVATE' not in (install / 'include/audit/public.h').read_text()
        assert 'AUDIT_SOURCE_WINS' in (install / 'include/audit/precedence.h').read_text()
        assert 'AUDIT_GENERATED_LOSES' not in (install / 'include/audit/precedence.h').read_text()
        assert sentinel.read_bytes() == original_sentinel
        assert list((kernel / 'usr/include').rglob('*.h')) == [sentinel]
        records.append(dict(case=mode, exported=sorted(actual), kernel_output_unchanged=True, private_section_removed=True, source_precedence=True))
        # The normal sanitizer must still reject accidental CONFIG leakage.
        put(src / 'include/uapi/audit/bad.h', '#define BAD CONFIG_AUDIT_PRIVATE\n')
        p = run(cmd + ['headers_install'], expected=1)
        assert 'CONFIG_AUDIT_PRIVATE' in p.stderr and not (out / 'usr/include/audit/bad.h').exists()
    native = d / 'native-output'
    native_install = d / 'native-install'
    run(['make', '-s', '-C', str(ROOT), 'O=' + str(native), 'ARCH=x86_64', 'INSTALL_HDR_PATH=' + str(native_install), 'headers_install'])
    headers = {str(p.relative_to(native_install / 'include')) for p in (native_install / 'include').rglob('*.h')}
    assert {'linux/types.h', 'linux/wait.h', 'asm/unistd_64.h', 'linux/version.h'} <= headers
    assert not any(x.startswith('audit/') or 'audit_generated' in x for x in headers)
    records.append(dict(case='in-tree-kernel-export', header_count=len(headers), generated_arch_and_version_headers_present=True))

RESULT.write_text(json.dumps(dict(source_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    source_sha256={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ['Makefile', 'scripts/Makefile.headersinst', 'scripts/headers_install.sh', 'scripts/unifdef.c']},
    records=records, remote_resources_used=[], scope='Host Kbuild header-export tests only; no module loading or kernel runtime.'), indent=2) + '\n')
print('PASS: three external export layouts, kernel-output isolation, sanitization, source precedence and normal kernel headers')
