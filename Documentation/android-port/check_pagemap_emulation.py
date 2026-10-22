#!/usr/bin/env python3
"""Run extracted pagemap readers with host shims, not a kernel/procfs test.

Checks native/emulated offsets, complete entries at task-size boundaries,
chunk crossings, seek errors, overflow-sized offsets, access masking and cleanup.
Pre-adaptation source provides negative controls. Page walking, locks, capability
and user-copy operations are simulated; this does not validate MM concurrency.
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
baseline = '20063c97d296302d8cbabf1c1b39daf3ebbe6b7b'

def read(path, old=False):
    if old:
        return subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)
    return (root / path).read_text()

def function(text, name):
    start = text.index(name)
    start = text.rfind('\n', 0, start) + 1
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

current = read('fs/proc/task_mmu.c')
old = read('fs/proc/task_mmu.c', True)
assert '.llseek\t\t= mem_lseek,' in current
assert '__is_emulated_pagemap_file' not in read('fs/read_write.c')
assert '__is_emulated_pagemap_file' not in read('include/linux/page_size_compat.h')
declarations = current[current.index('typedef struct {\n\tu64 pme;'):current.index('static int add_to_pagemap(')]
excerpts = [declarations, function(current, 'static inline void __collapse_pagemap_result('),
            function(current, 'static ssize_t pagemap_read('),
            function(old, 'static ssize_t pagemap_read(').replace('pagemap_read(', 'old_pagemap_read(', 1),
            function(read('fs/proc/base.c'), 'loff_t mem_lseek('),
            function(old, 'static loff_t __pagemap_lseek(')]
shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint64_t u64;
#define __user
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PMD_SIZE (1UL << 21)
#define PMD_MASK (~(PMD_SIZE - 1))
static unsigned int page_shift;
#define __PAGE_SHIFT page_shift
#define __PAGE_SIZE (1UL << __PAGE_SHIFT)
#define GENMASK_ULL(h,l) ((~0ULL << (l)) & (~0ULL >> (63 - (h))))
#define BIT_ULL(n) (1ULL << (n))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define min(a,b) ((a) < (b) ? (a) : (b))
#define min_t(t,a,b) min((t)(a),(t)(b))
#define unlikely(x) (x)
#define GFP_KERNEL 0
#define CAP_SYS_ADMIN 21
struct mm_struct { unsigned long task_size; int refs; bool alive; };
struct file { struct mm_struct *private_data; loff_t f_pos; };
static int init_user_ns, pagemap_ops, allocations, attempts, fail_alloc;
static int lock_calls, fail_lock;
static bool privileged, copy_fault;
static unsigned int walk_calls;
static unsigned long first_walk;
static bool mmget_not_zero(struct mm_struct *mm) {
    if (!mm->alive) return false;
    mm->refs++; return true;
}
static void mmput(struct mm_struct *mm) { assert(mm->refs == 1); mm->refs--; }
static bool file_ns_capable(struct file *f, int *ns, int cap) {
    (void)f; (void)ns; assert(cap == CAP_SYS_ADMIN); return privileged;
}
static void *kmalloc_array(size_t n, size_t size, int flags) {
    (void)flags;
    if (++attempts == fail_alloc) return NULL;
    void *p = malloc(n * size); assert(p); allocations++; return p;
}
static void *kcalloc(size_t n, size_t size, int flags) {
    void *p = kmalloc_array(n, size, flags); if (p) memset(p, 0, n * size); return p;
}
static void kfree(void *p) { if (p) { allocations--; free(p); } }
static int mmap_read_lock_killable(struct mm_struct *mm) {
    (void)mm; return ++lock_calls == fail_lock ? -EINTR : 0;
}
static void mmap_read_unlock(struct mm_struct *mm) { (void)mm; }
static unsigned long untagged_addr_remote(struct mm_struct *mm, unsigned long addr) {
    (void)mm; return addr;
}
static int copy_to_user(void *dst, const void *src, size_t len) {
    if (copy_fault) return 1;
    memcpy(dst, src, len); return 0;
}
static void force_successful_syscall_return(void) {}
'''
walker = r'''
static u64 page_value(unsigned long addr, bool pfn) {
    unsigned long index = addr >> PAGE_SHIFT;
    return PM_PRESENT | (index % 7 == 0 ? PM_SOFT_DIRTY : 0) |
           (pfn ? index + 256 : 0);
}
static int walk_page_range(struct mm_struct *mm, unsigned long start,
                          unsigned long end, const int *ops, struct pagemapread *pm) {
    (void)mm; (void)ops;
    if (!walk_calls++) first_walk = start;
    for (unsigned long addr = start; addr < end; addr += PAGE_SIZE) {
        assert(pm->pos < pm->len);
        pm->buffer[pm->pos++].pme = page_value(addr, pm->show_pfn);
    }
    return pm->pos == pm->len ? PM_END_OF_BUFFER : 0;
}
static void reset(void) {
    assert(allocations == 0);
    attempts = fail_alloc = lock_calls = fail_lock = 0;
    privileged = copy_fault = false; walk_calls = 0; first_walk = 0;
}
'''
checks = r'''
int main(void) {
    struct mm_struct mm = { .task_size = 32 * PMD_SIZE, .alive = true };
    struct file f = { .private_data = &mm };
    uint64_t buf[1024];
    for (page_shift = 12; page_shift <= 14; page_shift++) {
        for (int priv = 0; priv < 2; priv++) {
            reset(); privileged = priv;
            loff_t pos = (PMD_SIZE / __PAGE_SIZE - 1) * 8;
            unsigned long begin = (pos / 8) * __PAGE_SIZE;
            assert(pagemap_read(&f, (char *)buf, sizeof(buf), &pos) == sizeof(buf));
            assert(pos == (loff_t)((begin / __PAGE_SIZE) * 8 + sizeof(buf)));
            assert(first_walk == begin && walk_calls > 1);
            for (size_t i = 0; i < sizeof(buf)/sizeof(buf[0]); i++) {
                u64 expected = 0;
                for (unsigned long addr = begin + i * __PAGE_SIZE;
                     addr < begin + (i + 1) * __PAGE_SIZE; addr += PAGE_SIZE)
                    expected |= page_value(addr, priv && page_shift == PAGE_SHIFT);
                assert(buf[i] == expected);
            }
            assert(mm.refs == 0 && allocations == 0);
        }
        reset(); f.f_pos = 0;
        assert(mem_lseek(&f, 8, SEEK_SET) == 8);
        assert(pagemap_read(&f, (char *)buf, 8, &f.f_pos) == 8);
        assert(first_walk == __PAGE_SIZE && f.f_pos == 16);
        assert(mem_lseek(&f, -8, SEEK_CUR) == 8);
        assert(mem_lseek(&f, 8, SEEK_END) == -EINVAL && f.f_pos == 8);
        assert(__pagemap_lseek(&f, 8, SEEK_END) == (loff_t)(8 * (__PAGE_SIZE / PAGE_SIZE)));
        reset(); loff_t pos = 8;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == 8 && first_walk == __PAGE_SIZE);
        if (page_shift > PAGE_SHIFT) {
            reset(); pos = 8;
            assert(old_pagemap_read(&f, (char *)buf, 8, &pos) == 8);
            assert(first_walk == PAGE_SIZE); /* non-pread64 caller negative control */
        }
        reset(); mm.task_size = PMD_SIZE - PAGE_SIZE;
        pos = ((mm.task_size - 1) / __PAGE_SIZE) * 8;
        assert(pagemap_read(&f, (char *)buf, 16, &pos) == 8);
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == 0);
        if (page_shift > PAGE_SHIFT) {
            reset(); pos = (PMD_SIZE - __PAGE_SIZE) / PAGE_SIZE * 8;
            assert(old_pagemap_read(&f, (char *)buf, 16, &pos) ==
                   (loff_t)(8 - 8 / (__PAGE_SIZE / PAGE_SIZE))); /* short entry */
        }
        mm.task_size = 32 * PMD_SIZE;
        reset(); pos = LLONG_MAX & ~7LL;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == 0 && walk_calls == 0);
        reset(); pos = 1;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == -EINVAL);
        pos = 0; assert(pagemap_read(&f, (char *)buf, 7, &pos) == -EINVAL);
        assert(pagemap_read(&f, (char *)buf, 0, &pos) == 0);
        reset(); fail_alloc = 1;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == -ENOMEM);
        if (page_shift > PAGE_SHIFT) {
            reset(); fail_alloc = 2;
            assert(pagemap_read(&f, (char *)buf, 8, &pos) == -ENOMEM);
        }
        reset(); fail_lock = 1;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == -EINTR);
        reset(); fail_lock = 2;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == -EINTR);
        reset(); copy_fault = true;
        assert(pagemap_read(&f, (char *)buf, 8, &pos) == -EFAULT);
        assert(mm.refs == 0 && allocations == 0 && pos == 0);
    }
    puts("Extracted pagemap reader checks passed; old seek/offset/short-entry controls reproduced");
}
'''
program = shim + excerpts[0] + walker + ''.join(excerpts[1:]) + checks
with tempfile.TemporaryDirectory(prefix='pagemap-emulation-check-') as tmp:
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
