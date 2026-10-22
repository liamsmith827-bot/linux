#!/usr/bin/env python3
"""Exercise extracted padding updates/splits with deterministic host interleavings.

Host ASan/UBSan shims reproduce the old two-writer count combination and force
the new compare-exchange retry against a native guard-flag update. Exhaustive
small-VMA split checks validate count conservation and bounds in both orders.
This is not a kernel concurrency or lock-order test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
baseline = 'd65b1b963b41a4833eab058c8f825742ba3b1614'
source = (root / 'mm/pgsize_migration.c').read_text()
old = subprocess.check_output(['git', 'show', baseline + ':mm/pgsize_migration.c'], cwd=root, text=True)

def function(text, name):
    start = text.index(name)
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

excerpts = [function(old, 'void vma_set_pad_pages(').replace('vma_set_pad_pages(', 'old_set_pad_pages(', 1),
            function(source, 'void vma_set_pad_pages('),
            function(source, 'static unsigned long __vma_pad_pages('),
            function(source, 'unsigned long vma_pad_pages('),
            function(source, 'void split_pad_vma(')]
inline = (root / 'include/linux/pgsize_migration_inline.h').read_text()
constants = '\n'.join(line for line in inline.splitlines() if line.startswith('#define VM_'))
shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
typedef unsigned long vm_flags_t;
#define BITS_PER_LONG 64
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define VM_MAYBE_GUARD (1UL << 11)
#define READ_ONCE(x) (x)
#define ACCESS_PRIVATE(p,field) ((p)->field)
struct vm_area_struct {
    unsigned long vm_start, vm_end;
    union { vm_flags_t vm_flags; vm_flags_t __vm_flags; };
};
static bool enabled = true, inject_old, inject_cas;
static int warnings, retries;
#define is_pgsize_migration_enabled() (enabled)
#define WARN_ON_ONCE(x) ((x) ? (++warnings, true) : false)
#define WARN_ON(x) WARN_ON_ONCE(x)
static unsigned long vma_pages(struct vm_area_struct *vma) {
    return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}
static void old_set_pad_pages(struct vm_area_struct *, unsigned long);
static void __vm_flags_mod(struct vm_area_struct *vma, vm_flags_t set, vm_flags_t clear) {
    vma->vm_flags = (vma->vm_flags | set) & ~clear;
    if (inject_old && clear == VM_PAD_MASK) {
        inject_old = false;
        old_set_pad_pages(vma, 1);
    }
}
static bool try_cmpxchg(vm_flags_t *ptr, vm_flags_t *expected, vm_flags_t desired) {
    if (inject_cas) {
        inject_cas = false;
        *ptr = (*ptr & ~VM_PAD_MASK) | (1UL << VM_PAD_SHIFT) | VM_MAYBE_GUARD;
    }
    if (*ptr != *expected) { *expected = *ptr; retries++; return false; }
    *ptr = desired; return true;
}
'''
checks = r'''
int main(void) {
    struct vm_area_struct vma = { .vm_end = 4 * PAGE_SIZE, .vm_flags = 3 };
    inject_old = true;
    old_set_pad_pages(&vma, 2);
    assert(vma_pad_pages(&vma) == 3); /* neither writer requested 3 */
    vma.vm_flags = 3; inject_cas = true;
    vma_set_pad_pages(&vma, 2);
    assert(retries == 1 && vma_pad_pages(&vma) == 2);
    assert((vma.vm_flags & ~VM_PAD_MASK) == (3 | VM_MAYBE_GUARD));
    vm_flags_t flags = vma.vm_flags;
    vma_set_pad_pages(&vma, 5);
    assert(warnings == 1 && vma.vm_flags == flags);
    vma_set_pad_pages(&vma, VM_TOTAL_PAD_PAGES + 1);
    assert(warnings == 2 && vma.vm_flags == flags);
    enabled = false;
    vma_set_pad_pages(&vma, 0);
    assert(vma.vm_flags == flags && vma_pad_pages(&vma) == 0);
    enabled = true; warnings = 0;
    unsigned int cases = 0;
    for (unsigned long total = 2; total <= 32; total++) {
        for (unsigned long pad = 0; pad <= VM_TOTAL_PAD_PAGES && pad <= total; pad++) {
            for (unsigned long cut = 1; cut < total; cut++) {
                for (int new_below = 0; new_below < 2; new_below++) {
                    vm_flags_t original = 3 | VM_MAYBE_GUARD | (pad << VM_PAD_SHIFT);
                    struct vm_area_struct low = { .vm_start = 0, .vm_end = cut * PAGE_SIZE,
                                                 .vm_flags = original };
                    struct vm_area_struct high = { .vm_start = cut * PAGE_SIZE,
                                                  .vm_end = total * PAGE_SIZE, .vm_flags = original };
                    if (new_below) split_pad_vma(&high, &low, cut * PAGE_SIZE, 1);
                    else split_pad_vma(&low, &high, cut * PAGE_SIZE, 0);
                    unsigned long low_pad = vma_pad_pages(&low), high_pad = vma_pad_pages(&high);
                    assert(low_pad + high_pad == pad);
                    assert(high_pad == (pad < total - cut ? pad : total - cut));
                    assert(low_pad <= vma_pages(&low) && high_pad <= vma_pages(&high));
                    assert((low.vm_flags & ~VM_PAD_MASK) == (3 | VM_MAYBE_GUARD));
                    assert((high.vm_flags & ~VM_PAD_MASK) == (3 | VM_MAYBE_GUARD));
                    cases++;
                }
            }
        }
    }
    assert(warnings == 0);
    printf("Padding flag interleavings and %u split cases passed; old combined-count control reproduced\n", cases);
}
'''
program = '#include <stdint.h>\n' + constants + '\n' + shim + ''.join(excerpts) + checks
# The prototype must match the original externally visible definition.
program = program.replace('static void old_set_pad_pages(struct vm_area_struct *, unsigned long);',
                          'void old_set_pad_pages(struct vm_area_struct *, unsigned long);')
with tempfile.TemporaryDirectory(prefix='padding-flags-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'
    src.write_text(program)
    options = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-parameter',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(['cc', *options, str(src), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout)
record = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'negative_control_commit': baseline,
    'excerpts_sha256': hashlib.sha256(''.join(excerpts).encode()).hexdigest(),
    'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
    'compiler_flags': options,
    'result': result.stdout.strip(),
    'scope': __doc__.strip(),
}
a.output.write_text(json.dumps(record, indent=2) + '\n')
print(record['result'])
