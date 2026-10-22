#!/usr/bin/env python3
"""Extract the SDK build-rule closure from the pinned ACK, for review."""
import ast
from pathlib import Path
from inventory import ACK, LINUX, git

src = git(LINUX, 'show', ACK + ':BUILD.bazel')
tree = ast.parse(src)
lines = src.splitlines(keepends=True)
targets = {}
variables = {}
always = []
for n in tree.body:
    if isinstance(n, ast.Assign):
        for t in n.targets:
            if isinstance(t, ast.Name): variables[t.id] = n
    elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
        call = n.value
        if isinstance(call.func, ast.Name) and call.func.id in ['load', 'package']:
            always.append(n)
        for k in call.keywords:
            if k.arg == 'name' and isinstance(k.value, ast.Constant):
                targets[k.value.value] = n

needed = set()
def visit(n):
    if n in needed: return
    needed.add(n)
    for x in ast.walk(n):
        if isinstance(x, ast.Name) and x.id in variables:
            visit(variables[x.id])
        if isinstance(x, ast.Constant) and isinstance(x.value, str):
            key = x.value.removeprefix(':')
            if key in targets:
                visit(targets[key])
            elif x.value.startswith(':'):
                for suffix in ['_x86_64', '_x86']:
                    if key.endswith(suffix) and key[:-len(suffix)] in targets:
                        visit(targets[key[:-len(suffix)]])

for key in ['kernel_x86_64', 'common_kernel_sources', 'pahole',
            'test_mappings_zip', 'tests_zip_x86_64']:
    visit(targets[key])
for n in always: needed.add(n)
out = src[:src.index('load(')]
out += '# SDK emulator build targets, adapted from the pinned ACK.\n\n'
for n in tree.body:
    if n in needed:
        out += ''.join(lines[n.lineno-1:n.end_lineno]) + '\n'

# Historical binary KMI and symbol trimming are not part of this port.
out = out.replace('    abi_definition_stg = "gki/x86_64/abi.stg",\n', '')
out = out.replace('    additional_kmi_symbol_lists = [":x86_64_additional_kmi_symbol_lists"],\n', '')
out = out.replace('    kmi_symbol_list = "gki/x86_64/symbols/base",\n', '')
out = out.replace('    kmi_enforced = True,', '    kmi_enforced = False,')
out = out.replace('    kmi_symbol_list_strict_mode = True,', '    kmi_symbol_list_strict_mode = False,')
out = out.replace('    trim_nonlisted_kmi = True,', '    trim_nonlisted_kmi = False,')
# No cross-architecture profiling data is needed to implement the SDK ABI.
out = out.replace('    clang_autofdo_profile = ":gki/aarch64/afdo/kernel.afdo",\n', '')
(LINUX / 'BUILD.bazel').write_text(out)
print(f'Extracted {len(needed)} build statements, {len(out.splitlines())} lines')

newpaths = ['bazel/abi.bzl', 'bazel/constants.scl', 'bazel/modules.bzl',
            'bazel/modules_private.bzl', 'modules.bzl',
            'arch/x86/configs/gki_defconfig', 'gki/x86_64/symbols/virtual_device']
newpaths += git(LINUX, 'ls-tree', '-r', '--name-only', ACK,
               'tools/testing/kunit/android', 'tools/testing/selftests/android').splitlines()
for path in newpaths:
    dest = LINUX / path
    assert not dest.exists(), path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(git(LINUX, 'show', ACK + ':' + path))
