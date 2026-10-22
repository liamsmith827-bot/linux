#!/usr/bin/env python3
"""Check extracted stack setup/randomization under host allocation/lock shims.

Checks 4/8/16 KiB, native-page accounting and setup failure cleanup. Exhaustively
checks x86 random-mask inputs against native mmap-layout reserved span. Old
controls reproduce under-accounting and random offsets beyond that span.
No kernel mapping, randomness quality or runtime ASLR test is performed.
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
baseline = 'b39eeed468efb77aaa5154d7aea538f428c3d8c0'

def function(text, name):
    start = text.index(name)
    begin = text.index('{', start)
    depth, end = 1, begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

excerpts = []
for path, name in [('mm/vma_exec.c', 'int create_init_stack_vma('),
                   ('mm/util.c', 'unsigned long randomize_stack_top(')]:
    current = (root / path).read_text()
    old = subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)
    excerpts += [function(current, name), function(old, name)]
    fname = 'create_init_stack_vma' if 'vma_exec' in path else 'randomize_stack_top'
    excerpts[-1] = excerpts[-1].replace(fname + '(', 'old_' + fname + '(', 1)
# Check the actual x86 gap helper, including its native PAGE_SHIFT.
excerpts.append(function((root / 'arch/x86/mm/mmap.c').read_text(), 'static unsigned long stack_maxrandom_size('))
shim = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
static unsigned int page_shift = 12;
#define __PAGE_SHIFT page_shift
#define __PAGE_SIZE (1UL << page_shift)
#define __PAGE_MASK (~(__PAGE_SIZE - 1))
#define __PAGE_ALIGN(x) (((x) + __PAGE_SIZE - 1) & __PAGE_MASK)
#define PF_RANDOMIZE 1
#define STACK_TOP_MAX (1UL << 47)
#define VM_STACK_FLAGS 2
#define VM_STACK_INCOMPLETE_SETUP 4
#define VM_SOFTDIRTY 8
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)
struct mm_struct { unsigned long stack_vm, total_vm; };
struct vm_area_struct { unsigned long vm_start, vm_end, vm_flags, vm_page_prot; };
struct task { unsigned int flags; };
static struct task task, *current = &task;
static bool ia32;
#define __STACK_RND_MASK(is32bit) ((is32bit) ? 0x7ffUL : 0x3fffffUL)
#define STACK_RND_MASK __STACK_RND_MASK(ia32)
static unsigned long task_size_32bit(void) { return 1UL << 32; }
static unsigned long random_bits;
static unsigned long get_random_long(void) { return random_bits; }
static int fault, locked, allocated, ksm_live;
static struct vm_area_struct *vm_area_alloc(struct mm_struct *mm) {
    (void)mm; if (fault == 1) return NULL;
    struct vm_area_struct *vma = calloc(1, sizeof(*vma)); assert(vma); allocated++;
    return vma;
}
static void vm_area_free(struct vm_area_struct *vma) { assert(allocated); allocated--; free(vma); }
static void vma_set_anonymous(struct vm_area_struct *vma) { (void)vma; }
static int mmap_write_lock_killable(struct mm_struct *mm) {
    (void)mm; if (fault == 2) return -EINTR; assert(!locked); locked++; return 0;
}
static void mmap_write_unlock(struct mm_struct *mm) { (void)mm; assert(locked == 1); locked--; }
static int ksm_execve(struct mm_struct *mm) {
    (void)mm; if (fault == 3) return -ENOMEM; assert(!ksm_live); ksm_live++; return 0;
}
static void ksm_exit(struct mm_struct *mm) { (void)mm; assert(ksm_live == 1); ksm_live--; }
static void vm_flags_init(struct vm_area_struct *vma, unsigned long flags) { vma->vm_flags = flags; }
static unsigned long vm_get_page_prot(unsigned long flags) { return flags; }
static int insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma) {
    (void)mm; assert(locked && ksm_live && vma->vm_start < vma->vm_end);
    return fault == 4 ? -ENOMEM : 0;
}
static unsigned long vma_pages(struct vm_area_struct *vma) {
    return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}
'''
checks = r'''
int main(void) {
    unsigned long tested = 0;
    for (page_shift = 12; page_shift <= 14; page_shift++) {
        for (fault = 0; fault <= 4; fault++) {
            struct mm_struct mm = { 0 };
            struct vm_area_struct *vma = NULL;
            unsigned long top = 0;
            int ret = create_init_stack_vma(&mm, &vma, &top);
            if (fault) {
                assert(ret == (fault == 2 ? -EINTR : -ENOMEM));
                assert(!allocated && !ksm_live && !locked);
                assert(!mm.total_vm && !mm.stack_vm);
            } else {
                assert(ret == 0 && !locked && allocated == 1 && ksm_live == 1);
                assert(mm.stack_vm == vma_pages(vma) && mm.total_vm == vma_pages(vma));
                assert(top == STACK_TOP_MAX - sizeof(void *));
                assert(!(vma->vm_start & ~__PAGE_MASK));
                /* Native-page unmap accounting must not underflow. */
                mm.total_vm -= vma_pages(vma); mm.stack_vm -= vma_pages(vma);
                assert(!mm.total_vm && !mm.stack_vm);
                vm_area_free(vma); ksm_exit(&mm);
            }
        }
        fault = 0;
        struct mm_struct oldmm = { 0 };
        struct vm_area_struct *oldvma = NULL;
        unsigned long oldtop;
        assert(old_create_init_stack_vma(&oldmm, &oldvma, &oldtop) == 0);
        assert((oldmm.total_vm != vma_pages(oldvma)) == (page_shift > 12));
        vm_area_free(oldvma); ksm_exit(&oldmm);
        for (int mode = 0; mode < 2; mode++) {
            ia32 = mode;
            unsigned long top = ia32 ? (1UL << 32) : (1UL << 47);
            current->flags = PF_RANDOMIZE;
            unsigned long reserved = stack_maxrandom_size(top);
            for (random_bits = 0; random_bits <= STACK_RND_MASK; random_bits++) {
                unsigned long result = randomize_stack_top(top);
                assert(result <= top && top - result <= reserved);
                assert(!(result & ~__PAGE_MASK));
                assert(top - result == ((random_bits << PAGE_SHIFT) & __PAGE_MASK));
                tested++;
            }
            random_bits = STACK_RND_MASK;
            assert((top - old_randomize_stack_top(top) > reserved) == (page_shift > 12));
            current->flags = 0;
            assert(randomize_stack_top(top - 1) == top);
        }
    }
    printf("Stack setup/error cleanup passed; %lu random offsets checked; old mismatches reproduced\n", tested);
}
'''
program = shim + ''.join(excerpts) + checks
with tempfile.TemporaryDirectory(prefix='stack-emulation-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'
    src.write_text(program)
    options = ['-std=gnu11', '-O1', '-Wall', '-Wextra', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(['cc', *options, str(src), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout)
record = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'negative_control_commit': baseline,
    'excerpts_sha256': hashlib.sha256(''.join(excerpts).encode()).hexdigest(),
    'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
    'compiler_flags': options, 'result': result.stdout.strip(), 'scope': __doc__.strip(),
}
a.output.write_text(json.dumps(record, indent=2) + '\n')
print(record['result'])
