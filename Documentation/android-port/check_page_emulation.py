#!/usr/bin/env python3
"""Check extracted page-emulation code with host-side shims and negative controls.

Exercises parser state, EOF snapshots and folio cleanup, plus the real fault-bit
constants. This is not a kernel fault, mapping, boot, or concurrency test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
baseline = '0b7e6baa8c22e9fdaa86c6938377509fef6f937e'

def read(path, old=False):
    if old:
        return subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)
    return (root / path).read_text()

def parser_code(old=False):
    text = read('mm/page_size_compat.c', old)
    body = text.split('static int __init early_page_shift_compat(char *buf)', 1)[1].split('\nearly_param(', 1)[0]
    return 'static int ' + ('old_parser' if old else 'new_parser') + '(char *buf)' + body

def eof_code(old=False, locked=False):
    text = read('mm/filemap.c', old).split('vm_fault_t filemap_fault(struct vm_fault *vmf)', 1)[1]
    if locked:
        text = text.split('We must recheck i_size under page lock.', 1)[1]
    start = 'max_idx = DIV_ROUND_UP(i_size_read(inode), __PAGE_SIZE)' if old else 'size = i_size_read(inode);'
    body = text[text.index(start):].split('\n\tvmf->page =' if locked else '\n\ttrace_mm_filemap_fault(', 1)[0]
    name = ('old' if old else 'new') + ('_locked' if locked else '_entry')
    variables = 'pgoff_t max_idx;\n' + ('' if old else 'loff_t size;\n')
    variables += 'struct inode *inode = &mock_inode;\n'
    if locked:
        variables += 'struct folio *folio = &mock_folio;\n'
    return 'static unsigned int ' + name + '(unsigned long index, unsigned long emulated_page_size) {\n' + variables + body + '\nreturn 0;\n}\n'

def shared_guard_code(old=False):
    text = read('mm/memory.c', old).split('static vm_fault_t do_anonymous_page(', 1)[1]
    guard = text.split('/* File mapping without ->vm_ops ? */', 1)[1].split('/*', 1)[0]
    name = 'old_shared_guard' if old else 'new_shared_guard'
    return 'static unsigned int ' + name + '(struct vm_area_struct *vma) {\n' + guard + 'return 0;\n}\n'

def map_files_code():
    text = read('fs/proc/base.c')
    helper = 'static struct vm_area_struct *find_map_files_vma' + text.split('static struct vm_area_struct *find_map_files_vma', 1)[1].split('static int map_files_d_revalidate', 1)[0]
    native = read('include/linux/mm.h').split('static inline struct vm_area_struct *find_exact_vma', 1)[1].split('static inline bool range_in_vma', 1)[0]
    return helper + 'static inline struct vm_area_struct *find_exact_vma' + native

header = read('include/linux/mm_types.h')
flags = {name: int(value, 16) for name, value in re.findall(
    r'(VM_FAULT_\w+)\s*=\s*\(__force vm_fault_t\)(0x[0-9a-fA-F]+)', header)}
assert flags['VM_FAULT_NEED_ANONPAGE'] & flags['VM_FAULT_HINDEX_MASK'] == 0
assert len(set(flags.values())) == len(flags)
old_header = read('include/linux/mm_types.h', True)
old_flag = int(re.search(r'VM_FAULT_NEED_ANONPAGE\s*=\s*\(__force vm_fault_t\)(0x[0-9a-f]+)', old_header)[1], 16)
assert old_flag & flags['VM_FAULT_HINDEX_MASK']
max_shift = int(re.search(r'#define __MAX_PAGE_SHIFT\s+(\d+)', read('include/linux/page_size_compat_defs.h'))[1])
new_max = re.search(r'#define MAX_PAGE_SHIFT_COMPAT\s+(\S+)', read('mm/page_size_compat.c'))[1]
old_max = re.search(r'#define MAX_PAGE_SHIFT_COMPAT\s+(\S+)', read('mm/page_size_compat.c', True))[1]
shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096UL
#define MIN_PAGE_SHIFT_COMPAT (PAGE_SHIFT + 1)
#define ENOTSUPP 524
static int page_shift_compat;
static bool page_shift_compat_enabled;
static void static_branch_enable(bool *enabled) { *enabled = true; }
static int kstrtoint(const char *s, int base, int *value) {
    char *end; long parsed;
    errno = 0; parsed = strtol(s, &end, base);
    if (errno || parsed < INT_MIN || parsed > INT_MAX || end == s) return -EINVAL;
    if (*end == '\n') end++;
    if (*end) return -EINVAL;
    *value = parsed; return 0;
}
typedef unsigned long pgoff_t;
#define unlikely(x) (x)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define __PAGE_SIZE emulated_page_size
#define VM_FAULT_SIGBUS 2U
#define VM_FAULT_NEED_ANONPAGE 32768U
struct inode { int unused; };
#define VM_SHARED 8UL
struct vm_area_struct { unsigned long vm_flags; void *vm_ops;
    unsigned long vm_start, vm_end, padding; };
struct mm_struct { struct vm_area_struct *vma; };
#define VMA_PAD_START(vma) ((vma)->vm_end - (vma)->padding)
static struct vm_area_struct *vma_lookup(struct mm_struct *mm, unsigned long start) {
    struct vm_area_struct *vma = mm->vma;
    return vma && start >= vma->vm_start && start < vma->vm_end ? vma : NULL;
}
struct folio { int unused; };
static struct inode mock_inode;
static struct folio mock_folio;
static loff_t sizes[2];
static unsigned int reads, unlocks, puts_count;
static loff_t i_size_read(struct inode *inode) {
    (void)inode; assert(reads < 2); return sizes[reads++];
}
static void folio_unlock(struct folio *f) { (void)f; unlocks++; }
static void folio_put(struct folio *f) { (void)f; puts_count++; }
static void reset(loff_t first, loff_t second) {
    sizes[0] = first; sizes[1] = second; reads = unlocks = puts_count = 0;
}
'''
checks = r'''
int main(void) {
    page_shift_compat_enabled = false; page_shift_compat = 13;
    assert(new_parser("12") == -EINVAL && !page_shift_compat_enabled && page_shift_compat == 13);
    assert(new_parser("14") == 0 && page_shift_compat_enabled && page_shift_compat == 14);
    const char *bad[] = {"-1", "0", "12", "15", "16", "31", "2147483648", "bad"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        assert(new_parser((char *)bad[i]) == -EINVAL);
        assert(page_shift_compat == 14 && page_shift_compat_enabled);
    }
    assert(new_parser("13") == 0 && page_shift_compat == 13);
    assert(new_parser("14") == 0 && page_shift_compat == 14);
    assert(old_parser("-1") == -EINVAL && page_shift_compat == -1); /* negative control */
    reset(8192, 4096);
    assert(old_entry(1, PAGE_SIZE) == VM_FAULT_NEED_ANONPAGE && reads == 2);
    reset(8192, 4096);
    assert(new_entry(1, PAGE_SIZE) == 0 && reads == 1);
    reset(4096, 4096);
    assert(old_locked(1, 16384) == VM_FAULT_NEED_ANONPAGE && unlocks == 1 && puts_count == 0);
    reset(4096, 4096);
    assert(new_locked(1, 16384) == VM_FAULT_NEED_ANONPAGE && unlocks == 1 && puts_count == 1);
    for (loff_t size = 0; size <= 65536; size += 257) {
        for (unsigned long index = 0; index <= 17; index++) {
            reset(size, 0);
            unsigned int expected = index >= DIV_ROUND_UP(size, PAGE_SIZE) ? VM_FAULT_SIGBUS : 0;
            assert(new_entry(index, PAGE_SIZE) == expected && reads == 1);
        }
    }
    reset(1, 0); assert(new_entry(3, 16384) == VM_FAULT_NEED_ANONPAGE);
    reset(1, 0); assert(new_entry(4, 16384) == VM_FAULT_SIGBUS);
    struct vm_area_struct shared = { .vm_flags = VM_SHARED, .vm_ops = &mock_inode };
    assert(old_shared_guard(&shared) == 0);
    assert(new_shared_guard(&shared) == VM_FAULT_SIGBUS);
    shared.vm_flags = 0; assert(new_shared_guard(&shared) == 0);
    struct vm_area_struct padded = { .vm_start = 4096, .vm_end = 20480, .padding = 8192 };
    struct mm_struct mm = { &padded };
    assert(find_exact_vma(&mm, 4096, 12288) == NULL);
    assert(find_map_files_vma(&mm, 4096, 12288) == &padded);
    assert(find_map_files_vma(&mm, 4096, 20480) == &padded);
    assert(find_map_files_vma(&mm, 8192, 12288) == NULL);
    assert(find_map_files_vma(&mm, 4096, 16384) == NULL);
    assert(find_map_files_vma(&mm, 4096, 4096) == NULL);
    padded.padding = 16384;
    assert(find_map_files_vma(&mm, 4096, 4096) == NULL);
    assert(find_map_files_vma(&mm, 4096, 20480) == &padded);
    padded.padding = 0;
    assert(find_map_files_vma(&mm, 4096, 12288) == NULL);
    assert(find_map_files_vma(&mm, 4096, 20480) == &padded);
    mm.vma = NULL; assert(find_map_files_vma(&mm, 4096, 20480) == NULL);
    puts("Page emulation and proc range checks passed; old-code negative controls reproduced");
}
'''
excerpts = [parser_code(), parser_code(True), eof_code(), eof_code(True),
            eof_code(locked=True), eof_code(True, locked=True),
            shared_guard_code(), shared_guard_code(True), map_files_code()]
program = shim + f'\n#define __MAX_PAGE_SHIFT {max_shift}\n#define MAX_PAGE_SHIFT_COMPAT {new_max}\n'
program += excerpts[0] + f'\n#undef MAX_PAGE_SHIFT_COMPAT\n#define MAX_PAGE_SHIFT_COMPAT {old_max}\n'
program += ''.join(excerpts[1:]) + checks
with tempfile.TemporaryDirectory(prefix='page-emulation-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'
    src.write_text(program)
    options = ['-std=gnu11', '-Wall', '-Wextra', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(['cc', *options, str(src), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], check=True, text=True, capture_output=True, timeout=5)
record = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'negative_control_commit': baseline,
    'excerpts_sha256': hashlib.sha256(''.join(excerpts).encode()).hexdigest(),
    'fault_bits': flags,
    'maximum_emulated_page_shift': max_shift,
    'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
    'compiler_flags': options,
    'result': result.stdout.strip(),
    'scope': __doc__.strip(),
}
a.output.write_text(json.dumps(record, indent=2) + '\n')
print(record['result'])
