#!/usr/bin/env python3
"""Check extracted madvise/name bypass cleanup with host lock/refcount shims.

Reproduces old lock/reference leaks and checks ordinary, bypass, failure and
callback-retained-reference paths. No kernel locks or vendor callbacks run.
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
baseline = '5bc7751ba8de0b0edfa6b34bd5d8efd067e02a7d'
source = (root / 'mm/madvise.c').read_text()
old = subprocess.check_output(['git', 'show', baseline + ':mm/madvise.c'], cwd=root, text=True)

def function(text, name):
    start = text.index(name)
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

excerpts = [function(source, 'int do_madvise('), function(source, 'int set_anon_vma_name('),
            function(old, 'int do_madvise(').replace('do_madvise(', 'old_do_madvise(', 1),
            function(old, 'int set_anon_vma_name(').replace('set_anon_vma_name(', 'old_set_anon_vma_name(', 1)]
assert 'ssize_t ret = 0;' in function(source, 'SYSCALL_DEFINE5(process_madvise,')
shim = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __user
#define ANON_VMA_NAME_MAX_LEN 80
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(e) ((void *)(long)(e))
struct mm_struct { int unused; };
struct mmu_gather { int unused; };
struct madvise_behavior { struct mm_struct *mm; int behavior; struct mmu_gather *tlb; };
struct task { struct mm_struct *mm; };
static struct mm_struct mm;
static struct task task = { &mm }, *current = &task;
struct anon_vma_name { int refs; };
static struct anon_vma_name *last_name;
static bool skip, bypass, retained, alloc_fail, copy_fail;
static int locked, tlb_started, calls, names, lock_error, hook_error, native_error;
static bool madvise_should_skip(unsigned long start, size_t len, int behavior, int *error) {
    (void)start; (void)len; (void)behavior; *error = -EINVAL; return skip;
}
static int madvise_lock(struct madvise_behavior *b) {
    (void)b; if (lock_error) return lock_error; assert(!locked); locked++; return 0;
}
static void madvise_unlock(struct madvise_behavior *b) { (void)b; assert(locked == 1); locked--; }
static void trace_android_vh_mm_do_madvise_bypass(struct mm_struct *m, unsigned long start,
        size_t len, int behavior, int *error, bool *take) {
    (void)m; (void)start; (void)len; (void)behavior;
    *take = bypass; if (bypass) *error = hook_error;
}
static void madvise_init_tlb(struct madvise_behavior *b) { (void)b; assert(locked); tlb_started++; }
static int madvise_do_behavior(unsigned long start, size_t len, struct madvise_behavior *b) {
    (void)start; (void)len; (void)b; assert(locked && tlb_started == 1); calls++; return native_error;
}
static void madvise_finish_tlb(struct madvise_behavior *b) { (void)b; assert(tlb_started == 1); tlb_started--; }
static char *strndup_user(const char *s, size_t max) {
    (void)max; if (copy_fail) return ERR_PTR(-EFAULT); return strdup(s);
}
static bool is_valid_name_char(char c) { return c >= 0x20 && c <= 0x7e; }
static void kfree(void *p) { free(p); }
static struct anon_vma_name *anon_vma_name_alloc(const char *s) {
    (void)s; if (alloc_fail) return NULL;
    struct anon_vma_name *p = malloc(sizeof(*p)); assert(p);
    p->refs = 1; names++; last_name = p; return p;
}
static void anon_vma_name_put(struct anon_vma_name *p) {
    if (!p) return;
    assert(p->refs > 0);
    if (!--p->refs) { names--; free(p); last_name = NULL; }
}
static int madvise_set_anon_name(struct mm_struct *m, unsigned long addr, unsigned long size,
                                struct anon_vma_name *name) {
    (void)m; (void)addr; (void)size; (void)name; calls++; return native_error;
}
static void trace_android_rvh_pr_set_vma_name_bypass(struct mm_struct *m, unsigned long addr,
        unsigned long size, struct anon_vma_name *name, int *error, bool *take) {
    (void)m; (void)addr; (void)size; *take = bypass;
    if (bypass) *error = hook_error;
    if (retained && name) name->refs++;
}
static void reset(void) {
    assert(locked == 0 && names == 0 && tlb_started == 0);
    skip = bypass = retained = alloc_fail = copy_fail = false;
    calls = lock_error = hook_error = native_error = 0;
}
'''
checks = r'''
int main(void) {
    for (int take = 0; take < 2; take++)
    for (int failure = 0; failure < 2; failure++) {
        reset(); bypass = take; hook_error = failure ? -EPERM : 0;
        native_error = failure ? -ENOMEM : 0;
        assert(do_madvise(&mm, 0, 4096, 0) == (take ? hook_error : native_error));
        assert(!locked && !tlb_started && calls == !take);
        reset(); bypass = take; hook_error = failure ? -EPERM : 0;
        native_error = failure ? -ENOMEM : 0;
        assert(set_anon_vma_name(0, 4096, "name") == (take ? hook_error : native_error));
        assert(names == 0 && calls == !take);
    }
    reset(); skip = true;
    assert(do_madvise(&mm, 0, 4096, 0) == -EINVAL && !locked && !calls);
    reset(); lock_error = -EINTR;
    assert(do_madvise(&mm, 0, 4096, 0) == -EINTR && !locked && !calls);
    reset(); bypass = true;
    assert(old_do_madvise(&mm, 0, 4096, 0) == 0 && locked == 1 && !tlb_started);
    locked = 0; /* Release the simulated leaked lock. */
    reset(); bypass = true;
    assert(old_set_anon_vma_name(0, 4096, "name") == 0 && names == 1);
    anon_vma_name_put(last_name);
    reset(); bypass = retained = true;
    assert(set_anon_vma_name(0, 4096, "name") == 0 && names == 1 && last_name->refs == 1);
    anon_vma_name_put(last_name);
    reset(); bypass = true;
    assert(set_anon_vma_name(0, 4096, NULL) == 0 && names == 0);
    reset(); alloc_fail = true;
    assert(set_anon_vma_name(0, 4096, "name") == -ENOMEM && names == 0);
    reset(); copy_fail = true;
    assert(set_anon_vma_name(0, 4096, "name") == -EFAULT && names == 0);
    reset(); assert(set_anon_vma_name(0, 4096, "bad\n") == -EINVAL && names == 0);
    puts("Madvise bypass lock/refcount cleanup passed; old leaks reproduced");
}
'''
program = shim + ''.join(excerpts) + checks
with tempfile.TemporaryDirectory(prefix='madvise-bypass-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'
    src.write_text(program)
    options = ['-std=gnu11', '-Wall', '-Wextra', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
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
