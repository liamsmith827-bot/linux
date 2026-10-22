#!/usr/bin/env python3
"""Check extracted vDSO time-namespace address against the kernel fault layout.

Host shims model page insertion and configuration. Checks both native and x86
maximum-page spacing; no kernel namespace, timing or vDSO execution is tested.
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
baseline = '2b8ae3b1fce2'

def function(text, name):
    start = text.index(name); end = text.index('{', start) + 1; depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}'); end += 1
    return text[start:end] + '\n'

header = (root / 'include/vdso/datapage.h').read_text()
spacing = header.split('#ifdef CONFIG_X86_64', 1)[1].split('#ifndef __ASSEMBLY__', 1)[0]
spacing = '#ifdef CONFIG_X86_64' + spacing
spacing = spacing.replace('#include <linux/page_size_compat_defs.h>', '')
layout = header[header.index('#define VDSO_ARCH_DATA_SIZE'):header.index('};', header.index('enum vdso_pages')) + 2]
name = 'const struct vdso_time_data *__arch_get_vdso_u_timens_data('
current = function((root / 'lib/vdso/gettimeofday.c').read_text(), name)
old = function(subprocess.check_output(['git', 'show', baseline + ':lib/vdso/gettimeofday.c'], cwd=root, text=True), name).replace('__arch_get_vdso_u_timens_data(', 'old_get_timens_data(', 1)
fault = function((root / 'lib/vdso/datastore.c').read_text(), 'static vm_fault_t vvar_fault(')
shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define __MAX_PAGE_SIZE 16384
#define ALIGN(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define IS_ENABLED(x) (x)
#define CONFIG_GENERIC_GETTIMEOFDAY 1
#define CONFIG_VDSO_GETRANDOM 1
#define CONFIG_ARCH_HAS_VDSO_ARCH_DATA 1
static bool time_ns;
#define CONFIG_TIME_NS time_ns
#define VM_FAULT_SIGBUS 1
#define VM_FAULT_ERROR 1
#define unlikely(x) (x)
#define __pa_symbol(p) ((uintptr_t)(p))
#define __phys_to_pfn(p) ((p) >> PAGE_SHIFT)
typedef int vm_fault_t;
struct vdso_time_data { unsigned char placeholder[128]; };
struct vdso_arch_data { unsigned char placeholder[32]; };
struct vdso_time_data *vdso_k_time_data = (void *)(0x100UL << PAGE_SHIFT);
static void *vdso_k_rng_data = (void *)(0x200UL << PAGE_SHIFT);
static void *vdso_k_arch_data = (void *)(0x300UL << PAGE_SHIFT);
struct page { unsigned long pfn; };
static struct page ns_page = { 0x400 };
static unsigned long page_to_pfn(struct page *page) { return page->pfn; }
struct vm_special_mapping { int unused; };
struct vm_area_struct { int unused; };
struct vm_fault { unsigned long pgoff, address; };
static unsigned long addresses[2], pfns[2];
static int insertions, fail;
static struct page *find_timens_vvar_page(struct vm_area_struct *vma) {
    (void)vma; return time_ns ? &ns_page : NULL;
}
static int vmf_insert_pfn(struct vm_area_struct *vma, unsigned long addr, unsigned long pfn) {
    (void)vma; assert(insertions < 2); addresses[insertions] = addr; pfns[insertions++] = pfn;
    return fail ? VM_FAULT_ERROR : 0;
}
'''
checks = r'''
int main(void) {
    unsigned long base = 0x1000000UL;
    struct vm_area_struct vma;
    unsigned long selected = (uintptr_t)__arch_get_vdso_u_timens_data((void *)base);
    assert(selected == base + VDSO_TIMENS_PAGE_OFFSET * PAGE_SIZE);
    for (int enabled = 0; enabled < 2; enabled++) {
        time_ns = enabled; insertions = fail = 0;
        struct vm_fault vmf = { VDSO_TIME_PAGE_OFFSET, base };
        assert(vvar_fault(NULL, &vma, &vmf) == 0);
        assert(insertions == (time_ns ? 2 : 1));
        if (time_ns) {
            assert(addresses[0] == selected && pfns[0] == 0x100);
            assert(addresses[1] == base && pfns[1] == 0x400);
        } else assert(addresses[0] == base && pfns[0] == 0x100);
        vmf.pgoff = VDSO_TIMENS_PAGE_OFFSET; vmf.address = selected; insertions = 0;
        assert(vvar_fault(NULL, &vma, &vmf) == (time_ns ? 0 : VM_FAULT_SIGBUS));
        if (time_ns) assert(insertions == 1 && pfns[0] == 0x100);
    }
    time_ns = true; insertions = 0; fail = 1;
    struct vm_fault vmf = { 0, base };
    assert(vvar_fault(NULL, &vma, &vmf) == VM_FAULT_ERROR && insertions == 1);
    fail = 0; insertions = 0;
    unsigned long old_addr = (uintptr_t)old_get_timens_data((void *)base);
    vmf.address = old_addr; vmf.pgoff = (old_addr - base) >> PAGE_SHIFT;
    assert(vvar_fault(NULL, &vma, &vmf) == (VDSO_TIMENS_PAGE_OFFSET == 1 ? 0 : VM_FAULT_SIGBUS));
    puts("vDSO namespace lookup matches kernel insertion; old-spacing control checked");
}
'''
program = shim + spacing + layout + '\n' + current + old + fault + checks
results = []
with tempfile.TemporaryDirectory(prefix='vdso-spacing-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'; src.write_text(program)
    options = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    for mode in [[], ['-DCONFIG_X86_64=1']]:
        subprocess.run(['cc', *options, *mode, str(src), '-o', str(binary)], check=True)
        r = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15)
        if r.returncode: raise SystemExit(r.stderr or r.stdout)
        results.append({'configuration': 'x86_64' if mode else 'native spacing', 'result': r.stdout.strip()})
record = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
          'negative_control_commit': subprocess.check_output(['git', 'rev-parse', baseline], cwd=root, text=True).strip(),
          'program_sha256': hashlib.sha256(program.encode()).hexdigest(), 'compiler_flags': options,
          'results': results, 'scope': __doc__.strip()}
a.output.write_text(json.dumps(record, indent=2) + '\n')
print(results)
