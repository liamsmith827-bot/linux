#!/usr/bin/env python3
"""Check extracted unmapped-area functions with a host interval/iterator shim.

The shim models free gaps, limits and adjacent stack guards; it does not execute
the Maple Tree, a kernel mmap syscall, or concurrent VMA updates. Old-source
controls must reproduce upward rounding beyond the chosen top-down gap.
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
baseline = '110e353eded3771d163bc8c4f13aa29a9bfaff1d'
path = 'mm/vma.c'
source = (root / path).read_text()
old = subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)

def function(text, name):
    start = text.index('unsigned long ' + name + '(')
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

excerpts = []
for text, prefix in [(source, ''), (old, 'old_')]:
    for name in ['unmapped_area', 'unmapped_area_topdown']:
        excerpts.append(function(text, name).replace(name + '(', prefix + name + '(', 1))

shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
static unsigned int page_shift = PAGE_SHIFT;
#define __PAGE_SHIFT page_shift
#define __PAGE_SIZE (1UL << __PAGE_SHIFT)
#define __PAGE_ALIGN(x) (((x) + __PAGE_SIZE - 1) & ~(__PAGE_SIZE - 1))
#define __PAGE_ALIGN_DOWN(x) ((x) & ~(__PAGE_SIZE - 1))
#define __PAGE_SIZE_ROUND_UP_ADJ(x) ((x) + __PAGE_SIZE - PAGE_SIZE)
#define VM_STARTGAP_FLAGS 1UL
struct vm_unmapped_area_info {
    unsigned long length, align_mask, align_offset, start_gap, low_limit, high_limit;
};
struct vm_area_struct {unsigned long vm_start,vm_end,vm_flags,start_guard,end_guard;};
struct vma_iterator {unsigned long start,end; int left,right;};
#define VMA_ITERATOR(name,mm,start) struct vma_iterator name = {0}
static unsigned long mmap_min_addr = PAGE_SIZE;
static struct vm_area_struct areas[3];
static unsigned int nr_areas, searches;
static unsigned long max(unsigned long a,unsigned long b) {return a>b?a:b;}
static unsigned long min(unsigned long a,unsigned long b) {return a<b?a:b;}
static int search(struct vma_iterator *it,unsigned long low,unsigned long high,
                  unsigned long length,bool topdown) {
    assert(++searches < 20);
    if (high < low || high - low < length) return -ENOMEM;
    for (unsigned int k=0;k<=nr_areas;k++) {
        unsigned int i = topdown ? nr_areas-k : k;
        unsigned long begin = max(low,i ? areas[i-1].vm_end : 0);
        unsigned long end = min(high,i<nr_areas ? areas[i].vm_start : ULONG_MAX);
        if (end<begin || end-begin<length) continue;
        it->start=topdown?end-length:begin;
        it->end=topdown?end:begin+length;
        it->left=(int)i-1;it->right=i<nr_areas?(int)i:-1;
        return 0;
    }
    return -ENOMEM;
}
static int vma_iter_area_highest(struct vma_iterator *it,unsigned long a,unsigned long b,unsigned long n) {return search(it,a,b,n,true);}
static int vma_iter_area_lowest(struct vma_iterator *it,unsigned long a,unsigned long b,unsigned long n) {return search(it,a,b,n,false);}
static unsigned long vma_iter_addr(struct vma_iterator *it) {return it->start;}
static unsigned long vma_iter_end(struct vma_iterator *it) {return it->end;}
static struct vm_area_struct *vma_next(struct vma_iterator *it) {return it->right<0?NULL:&areas[it->right];}
static struct vm_area_struct *vma_prev(struct vma_iterator *it) {return it->left<0?NULL:&areas[it->left];}
static void vma_iter_reset(struct vma_iterator *it) {(void)it;}
static unsigned long vm_start_gap(struct vm_area_struct *v) {return v->vm_start-v->start_guard;}
static unsigned long vm_end_gap(struct vm_area_struct *v) {return v->vm_end+v->end_guard;}
'''

tests = r'''
static unsigned long run(struct vm_unmapped_area_info *i,bool top,bool old) {
    searches=0;
    if (old) return top?old_unmapped_area_topdown(i):old_unmapped_area(i);
    return top?unmapped_area_topdown(i):unmapped_area(i);
}
static bool valid(unsigned long addr,struct vm_unmapped_area_info *i) {
    if (addr == (unsigned long)-ENOMEM) return true;
    if (addr < max(i->low_limit,mmap_min_addr) || addr > i->high_limit ||
        i->length > i->high_limit-addr || addr%__PAGE_SIZE) return false;
    for (unsigned int k=0;k<nr_areas;k++)
        if (addr < vm_end_gap(&areas[k]) && addr+i->length > vm_start_gap(&areas[k])) return false;
    return true;
}
int main(void) {
    unsigned long cases=0, old_bad=0;
    for (page_shift=12;page_shift<=14;page_shift++)
    for (unsigned int edge=0;edge<16;edge++)
    for (unsigned int guard=0;guard<3;guard++)
    for (unsigned int pages=1;pages<=8;pages++)
    for (unsigned int alignment=0;alignment<3;alignment++)
    for (unsigned int offset=0;offset<4;offset++)
    for (unsigned int top=0;top<2;top++) {
        struct vm_unmapped_area_info i = {
            .length=pages*__PAGE_SIZE,.low_limit=0x10000,.high_limit=0x90000,
            .align_mask=alignment ? ((1UL<<(alignment+15))-1) : 0,
            .align_offset=offset*__PAGE_SIZE,
        };
        nr_areas=2;
        areas[0]=(struct vm_area_struct){.vm_start=0x10000,.vm_end=0x20000+edge*PAGE_SIZE,
            .end_guard=guard==1?2*PAGE_SIZE:0};
        areas[1]=(struct vm_area_struct){.vm_start=0x70000+edge*PAGE_SIZE,.vm_end=0x90000,
            .vm_flags=guard==2?VM_STARTGAP_FLAGS:0,.start_guard=guard==2?2*PAGE_SIZE:0};
        unsigned long addr=run(&i,top,false), prev=run(&i,top,true);
        assert(valid(addr,&i));
        if (!valid(prev,&i)) old_bad++;
        if (page_shift==12) assert(addr==prev);
        if (addr!=(unsigned long)-ENOMEM)
            assert(((addr-i.align_offset)&i.align_mask)==0);
        cases++;
    }
    assert(old_bad>0);
    page_shift=14;nr_areas=0;
    struct vm_unmapped_area_info i={.length=0x4000,.low_limit=0x1000,.high_limit=0x21000};
    unsigned long addr=run(&i,true,false), prev=run(&i,true,true);
    assert(addr==0x1c000 && prev==0x20000 && valid(addr,&i) && !valid(prev,&i));
    i.length=ULONG_MAX-0x1000;
    assert(run(&i,true,false)==(unsigned long)-ENOMEM);
    assert(run(&i,false,false)==(unsigned long)-ENOMEM);
    printf("%lu interval/guard/alignment cases passed; %lu old-source failures; native 4 KiB matches; limit and overflow controls passed\n",cases,old_bad);
}
'''

with tempfile.TemporaryDirectory(prefix='ack-unmapped-area-') as t:
    c = Path(t) / 'check.c'
    binary = Path(t) / 'check'
    c.write_text(shim + '\n'.join(excerpts) + tests)
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', str(c), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
report = {
    'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'baseline': baseline,
    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
    'extracted_functions': ['unmapped_area', 'unmapped_area_topdown'],
    'result': result.stdout.strip(),
    'limits': 'Host interval/iterator shim with UBSan; no real Maple Tree, kernel syscall, VMA concurrency or emulator runtime tested.',
}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(report['result'])
