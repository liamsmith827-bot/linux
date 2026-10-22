#!/usr/bin/env python3
"""Inspect generated x86_64 module tables without loading or booting anything.

Checks the real PREL32 protected-export table and every distributed module's
parallel symbol/flag/CRC counts. The old pointer-sized search is evaluated as
a negative control against the same names. This is artifact-level evidence,
not a test of kernel module loading or runtime enforcement.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct


def sections(path):
    with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        assert data[:6] == b'\x7fELF\x02\x01', path
        assert struct.unpack_from('<H', data, 18)[0] == 62, path
        offset = struct.unpack_from('<Q', data, 40)[0]
        size, count, names_index = struct.unpack_from('<HHH', data, 58)
        assert size == 64 and count and names_index < count, path
        headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size)
                   for i in range(count)]
        names = headers[names_index]
        strings = data[names[4]:names[4] + names[5]]
        result = {}
        for h in headers:
            end = strings.index(0, h[0])
            name = strings[h[0]:end].decode()
            if name in ('__kexporttab', '__ksymtab_strings', '__ksymtab',
                        '__kflagstab', '__kcrctab'):
                assert name not in result, (path, name)
                assert h[1] == 1 and h[2] & 2, (path, name, h)
                assert h[4] + h[5] <= len(data), path
                result[name] = {'address': h[3], 'size': h[5],
                                'data': data[h[4]:h[4] + h[5]]}
        return result


def lookup(names, name):
    lo, hi = 0, len(names)
    while lo < hi:
        mid = (lo + hi) // 2
        if names[mid] == name:
            return True
        if names[mid] < name:
            lo = mid + 1
        else:
            hi = mid
    return False


p = argparse.ArgumentParser(description=__doc__)
p.add_argument('workspace', type=Path)
p.add_argument('--run', required=True)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
root = args.workspace
config = (root / 'common_dist/kernel_x86_64_dot_config').read_text()
assert 'CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y\n' in config
assert 'CONFIG_MODVERSIONS=y\n' in config
assert 'CONFIG_MODULE_SIG_PROTECT=y\n' in config
tables = sections(root / 'common_dist/vmlinux')
protected, strings = tables['__kexporttab'], tables['__ksymtab_strings']
assert protected['size'] % 4 == 0
names = []
for i in range(0, protected['size'], 4):
    displacement = struct.unpack_from('<i', protected['data'], i)[0]
    position = protected['address'] + i + displacement - strings['address']
    assert 0 <= position < strings['size']
    end = strings['data'].index(0, position)
    names.append(strings['data'][position:end].decode())
assert names and names == sorted(names) and len(names) == len(set(names))
assert all(lookup(names, name) for name in names)
assert not lookup(names, '!android-port-negative-control!')
# The old loader divides the byte span by sizeof(char *) and advances 8 bytes.
old_names = names[0:2 * (len(names) // 2):2]
missed = [name for name in names if not lookup(old_names, name)]
assert missed, 'The old-stride negative control should miss protected symbols'
modules = sorted(root.glob('common_dist/*.ko')) + sorted(root.glob('virt_dist/*.ko'))
checks = {}
for module in modules:
    t = sections(module)
    syms = t.get('__ksymtab', {'size': 0})['size']
    assert syms % 12 == 0, module
    count = syms // 12
    flags = t.get('__kflagstab', {'data': b''})['data']
    crcs = t.get('__kcrctab', {'size': 0})['size']
    assert len(flags) == count and crcs == 4 * count, module
    assert all(flag & ~3 == 0 for flag in flags), module
    checks[str(module.relative_to(root))] = count
report = {
    'run': args.run,
    'scope': 'Generated ELF metadata and lookup arithmetic only; no module load or boot.',
    'protected_export_entry_size': 4,
    'old_pointer_stride': 8,
    'protected_export_count': len(names),
    'old_stride_missed_count': len(missed),
    'old_stride_missed_examples': missed[:12],
    'correct_stride_found_all': True,
    'negative_name_rejected': True,
    'protected_table_sha256': hashlib.sha256(protected['data']).hexdigest(),
    'protected_names_sha256': hashlib.sha256('\n'.join(names).encode()).hexdigest(),
    'module_symbol_counts': checks,
    'all_module_flags_and_crcs_match_symbol_counts': True,
}
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(f'{len(names)} protected exports; old stride misses {len(missed)}; '
      f'{len(modules)} module flag/CRC tables match.')
