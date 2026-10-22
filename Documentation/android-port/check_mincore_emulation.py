#!/usr/bin/env python3
"""Execute extracted mincore syscall/aggregation code with host walk shims.

Checks 4/8/16 KiB page units, short lengths, VMA/chunk boundaries, holes,
buffer validation and error cleanup. Old source reproduces the missing-byte
failure. This does not execute kernel page walks, permissions or concurrency.
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
baseline = 'c476769367dd9ec44abeb0483606f530d43b18dc'
source = (root / 'mm/mincore.c').read_text()
old = subprocess.check_output(['git', 'show', baseline + ':mm/mincore.c'], cwd=root, text=True)

def function(text, name):
    start = text.index(name)
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

excerpts = [function(source, 'struct mincore_result {').rstrip() + ';\n',
            function(source, 'static unsigned long collapse_mincore_result('),
            function(source, 'SYSCALL_DEFINE3(mincore,'),
            function(old, 'static inline void __collapse_mincore_result('),
            function(old, 'SYSCALL_DEFINE3(mincore,').replace('SYSCALL_DEFINE3(mincore,',
                                                                   'SYSCALL_DEFINE3(old_mincore,', 1)]
shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
static unsigned int page_shift;
#define __PAGE_SHIFT page_shift
#define __PAGE_SIZE (1UL << page_shift)
#define __PAGE_MASK (~(__PAGE_SIZE - 1))
#define offset_in_page(n) ((n) & ~PAGE_MASK)
#define __offset_in_page(n) ((n) & ~__PAGE_MASK)
#define min(a,b) ((a) < (b) ? (a) : (b))
#define unlikely(x) (x)
#define __user
#define GFP_USER 0
#define __GFP_ZERO 1
#define SYSCALL_DEFINE3(name,t1,a1,t2,a2,t3,a3) static long name(t1 a1,t2 a2,t3 a3)
struct task { void *mm; };
static struct task task;
static struct task *current = &task;
static unsigned char output[8192];
static unsigned long vma_stride, hole, examined, returned, checked;
static unsigned int access_calls, allocations, attempts, fail_alloc;
static bool bad_range, bad_vec, copy_fault;
static unsigned long untagged_addr(unsigned long addr) { return addr; }
static bool access_ok(const void *p, size_t count) {
    if (++access_calls == 1) return !bad_range;
    assert(p == output); checked = count;
    return !bad_vec && count <= sizeof(output);
}
static unsigned long __get_free_page(int flags) {
    if (++attempts == fail_alloc) return 0;
    void *p = flags & __GFP_ZERO ? calloc(1, PAGE_SIZE) : malloc(PAGE_SIZE);
    assert(p); allocations++; return (unsigned long)p;
}
static void free_page(unsigned long p) { assert(allocations); allocations--; free((void *)p); }
static void mmap_read_lock(void *mm) { (void)mm; }
static void mmap_read_unlock(void *mm) { (void)mm; }
static unsigned char resident(unsigned long page) { return page % 7 == 3; }
static long do_mincore(unsigned long addr, unsigned long pages, unsigned char *vec) {
    unsigned long first = addr >> PAGE_SHIFT;
    if (first == hole) return -ENOMEM;
    unsigned long count = min(pages, vma_stride - first % vma_stride);
    if (first < hole && first + count > hole) count = hole - first;
    assert(count > 0 && count <= PAGE_SIZE);
    for (unsigned long i = 0; i < count; i++) vec[i] = resident(first + i);
    examined += count; return count;
}
static int copy_to_user(unsigned char *dst, const unsigned char *src, unsigned long len) {
    if (copy_fault && len) return 1;
    assert(dst >= output && dst + len <= output + sizeof(output));
    memcpy(dst, src, len); returned += len; return 0;
}
static void reset(unsigned int shift, unsigned long stride) {
    assert(allocations == 0);
    page_shift = shift; vma_stride = stride; hole = ULONG_MAX;
    examined = returned = checked = access_calls = attempts = fail_alloc = 0;
    bad_range = bad_vec = copy_fault = false; memset(output, 0xcc, sizeof(output));
}
'''
checks = r'''
int main(void) {
    const size_t lengths[] = {0, 1, 4095, 4096, 4097, 16383, 16384, 16385,
                              PAGE_SIZE * PAGE_SIZE - 1, PAGE_SIZE * PAGE_SIZE + 1};
    const unsigned long strides[] = {1, 2, 3, 5, 7, 4095, 4096, 8192};
    unsigned int cases = 0;
    for (unsigned int shift = 12; shift <= 14; shift++) {
        for (size_t s = 0; s < sizeof(strides)/sizeof(strides[0]); s++)
        for (size_t l = 0; l < sizeof(lengths)/sizeof(lengths[0]); l++) {
            reset(shift, strides[s]);
            unsigned long start = 3 * __PAGE_SIZE;
            unsigned long entries = (lengths[l] + __PAGE_SIZE - 1) / __PAGE_SIZE;
            assert(mincore(start, lengths[l], output) == 0);
            assert(checked == entries && returned == entries);
            assert(examined == entries * (__PAGE_SIZE / PAGE_SIZE));
            for (unsigned long i = 0; i < entries; i++) {
                unsigned char expected = 0;
                for (unsigned long page = (start + i * __PAGE_SIZE) / PAGE_SIZE;
                     page < (start + (i + 1) * __PAGE_SIZE) / PAGE_SIZE; page++)
                    expected |= resident(page);
                assert(output[i] == expected);
            }
            assert(output[entries] == 0xcc && allocations == 0); cases++;
        }
        reset(shift, 1); hole = 1;
        assert(mincore(0, 2 * __PAGE_SIZE, output) == -ENOMEM && allocations == 0);
        reset(shift, 1); bad_vec = true;
        assert(mincore(0, 1, output) == -EFAULT && allocations == 0);
        reset(shift, 1); bad_range = true;
        assert(mincore(0, 1, output) == -ENOMEM && allocations == 0);
        reset(shift, 1);
        assert(mincore(1, 1, output) == -EINVAL && allocations == 0);
        reset(shift, 1); fail_alloc = 1;
        assert(mincore(0, 1, output) == -EAGAIN && allocations == 0);
        if (shift > PAGE_SHIFT) {
            reset(shift, 1); fail_alloc = 2;
            assert(mincore(0, 1, output) == -EAGAIN && allocations == 0);
            reset(shift, 1);
            assert(old_mincore(0, 1, output) == 0 && returned == 0 && output[0] == 0xcc);
            reset(shift, 1);
            assert(old_mincore(0, __PAGE_SIZE, output) == 0 && returned == 0);
        }
        reset(shift, 1); copy_fault = true;
        assert(mincore(0, 1, output) == -EFAULT && allocations == 0);
    }
    printf("Mincore %u range/split cases and error paths passed; old missing-byte controls reproduced\n", cases);
}
'''
program = shim + ''.join(excerpts) + checks
with tempfile.TemporaryDirectory(prefix='mincore-emulation-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'
    src.write_text(program)
    options = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-sign-compare',
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
