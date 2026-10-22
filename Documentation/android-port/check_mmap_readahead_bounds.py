#!/usr/bin/env python3
"""Exercise complete mmap readahead functions with host VMA/I/O shims.

Check faults in data, padding and all-padding split VMAs, executable/readaround/
sequential/THP paths, asynchronous markers and the optional boundary switch.
Old-source controls demonstrate unsigned length underflow and padding prefetch.
This does not perform actual faults, disk I/O, kernel locking or emulator boot.
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
baseline = '3ea7a304b5dc436d878053200c03609b692c6006'
path = 'mm/filemap.c'
current = (root / path).read_text()
old = subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)

def function(text, signature):
    start = text.index(signature)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

excerpts = []
for text, prefix in [(current, ''), (old, 'old_')]:
    for name in ['do_sync_mmap_readahead', 'do_async_mmap_readahead']:
        body = function(text, 'static struct file *' + name + '(')
        excerpts.append(body.replace(name, prefix + name, 1))

shim = r'''
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define CONFIG_TRANSPARENT_HUGEPAGE 1
#define HPAGE_PMD_ORDER 9
#define HPAGE_PMD_NR 512UL
#define MAX_PAGECACHE_ORDER 10
#define VM_EXEC 1
#define VM_RAND_READ 2
#define VM_SEQ_READ 4
#define VM_HUGEPAGE 8
#define MMAP_LOTSAMISS 100
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define likely(x) (x)
#define round_down(x,n) ((x)&~((n)-1))
#define round_up(x,n) (((x)+(n)-1)&~((n)-1))
#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
typedef unsigned long pgoff_t;
typedef unsigned long vm_flags_t;
struct file_ra_state { unsigned long start,size,async_size,ra_pages; unsigned int order; unsigned short mmap_miss; };
struct address_space { int unused; };
struct file { struct file_ra_state f_ra; struct address_space *f_mapping; void *f_inode; };
struct vm_area_struct { struct file *vm_file; vm_flags_t vm_flags; unsigned long vm_pgoff, data_pages; };
struct vm_fault { struct vm_area_struct *vma; unsigned long pgoff; };
struct folio { bool locked, readahead; };
struct readahead_control { unsigned long _index,_max_index; };
#define DEFINE_READAHEAD(n,f,r,m,i) struct readahead_control n = {._index=(i),._max_index=ULONG_MAX}
static bool boundary, skip_hook, drop_lock;
static unsigned int calls, data_reads, unlocks, path_kind;
static unsigned long issued_size, issued_index, issued_max;
static bool is_vma_readahead_boundary_enabled(void) {return boundary;}
static unsigned long vma_data_pages(struct vm_area_struct *v) {data_reads++;return v->data_pages;}
static unsigned int exec_folio_order(void) {return 0;}
static struct file *maybe_unlock_mmap_for_io(struct vm_fault *v,struct file *p) {
    (void)p;unlocks++;return drop_lock?v->vma->vm_file:NULL;
}
static bool folio_test_locked(struct folio *f) {return f->locked;}
static bool folio_test_readahead(struct folio *f) {return f->readahead;}
static void trace_android_vh_do_sync_mmap_readahead(struct vm_fault *v,bool *s) {(void)v;*s=skip_hook;}
static void trace_android_vh_do_async_mmap_readahead(struct vm_fault *v,struct folio *f,bool *s) {(void)v;(void)f;*s=skip_hook;}
#define trace_android_vh_page_cache_readahead_start(...) ((void)0)
#define trace_android_vh_page_cache_readahead_end(...) ((void)0)
#define trace_android_vh_tune_mmap_readaround(...) ((void)0)
#define trace_android_vh_page_cache_read(...) ((void)0)
#define trace_android_vh_customize_ractl(...) ((void)0)
static void record(struct readahead_control *r,unsigned long size,int kind) {
    calls++;issued_size=size;issued_index=r->_index;issued_max=r->_max_index;path_kind=kind;
}
static void page_cache_ra_order(struct readahead_control *r,struct file_ra_state *ra) {record(r,ra->size,1);}
static void page_cache_sync_ra(struct readahead_control *r,unsigned long n) {record(r,n,2);}
static void page_cache_async_ra(struct readahead_control *r,struct folio *f,unsigned long n) {(void)f;record(r,n,3);}
'''

tests = r'''
static struct address_space mapping;
static struct file file;
static struct vm_area_struct vma;
static struct vm_fault vmf;
static struct folio folio;
static void setup(unsigned long flags,unsigned long data,unsigned long index,bool bound) {
    file=(struct file){.f_ra={.ra_pages=16},.f_mapping=&mapping};
    vma=(struct vm_area_struct){.vm_file=&file,.vm_flags=flags,.vm_pgoff=100,.data_pages=data};
    vmf=(struct vm_fault){.vma=&vma,.pgoff=index};
    folio=(struct folio){.readahead=true};
    boundary=bound;skip_hook=drop_lock=false;calls=data_reads=unlocks=path_kind=0;
    issued_size=issued_index=issued_max=0;
}
int main(void) {
    unsigned long modes[]={VM_EXEC,0,VM_SEQ_READ,VM_HUGEPAGE,VM_EXEC|VM_RAND_READ};
    for(int b=0;b<2;b++)for(unsigned int m=0;m<sizeof(modes)/sizeof(*modes);m++) {
        /* Both a mixed VMA's padding and a split padding-only VMA. */
        for(int all=0;all<2;all++) {
            setup(modes[m],all?0:4,106,b);
            assert(do_sync_mmap_readahead(&vmf)==NULL);
            assert(!calls && !unlocks && data_reads==1);
            setup(modes[m],all?0:4,106,b);
            assert(do_async_mmap_readahead(&vmf,&folio)==NULL);
            assert(!calls && !unlocks);
        }
        setup(modes[m],4,102,b);drop_lock=true;
        assert(do_sync_mmap_readahead(&vmf)==&file);
        assert(calls==1 && unlocks==1 && data_reads==1);
        assert(issued_max==(b?103:ULONG_MAX));
        if(modes[m]&VM_EXEC)assert(issued_index==102 && issued_size==2);
        if(modes[m]==VM_SEQ_READ)assert(path_kind==2);
        if(modes[m]==VM_HUGEPAGE)assert(issued_size==2*HPAGE_PMD_NR);
        setup(0,4,102,b);drop_lock=true;
        assert(do_async_mmap_readahead(&vmf,&folio)==&file);
        assert(calls==1 && path_kind==3 && data_reads==1 && issued_max==(b?103:ULONG_MAX));
        setup(VM_EXEC,4,106,b);
        old_do_sync_mmap_readahead(&vmf);
        assert(calls==1 && issued_size>ULONG_MAX/2); /* underflow */
        setup(0,4,106,b);
        old_do_async_mmap_readahead(&vmf,&folio);
        assert(calls==1); /* prefetch attempt from padding */
    }
    setup(VM_EXEC,8,102,false);skip_hook=true;
    assert(!do_sync_mmap_readahead(&vmf) && !calls && !data_reads);
    assert(!do_async_mmap_readahead(&vmf,&folio) && !calls && !data_reads);
    setup(VM_RAND_READ,8,102,true);
    assert(!do_sync_mmap_readahead(&vmf) && !calls);
    assert(!do_async_mmap_readahead(&vmf,&folio) && !calls);
    setup(0,8,102,true);folio.readahead=false;
    assert(!do_async_mmap_readahead(&vmf,&folio) && !calls && !data_reads);
    setup(0,8,102,true);file.f_ra.ra_pages=0;
    assert(!do_sync_mmap_readahead(&vmf) && !calls);
    assert(!do_async_mmap_readahead(&vmf,&folio) && !calls);
    setup(VM_EXEC,0,0,true);vma.vm_pgoff=0;
    assert(!do_sync_mmap_readahead(&vmf) && !calls);
    assert(!do_async_mmap_readahead(&vmf,&folio) && !calls);
    puts("PASS: data/padding/split, boundary off/on, exec/seq/THP/async, old underflow controls");
}
'''
source = shim + '\n'.join(excerpts) + tests
with tempfile.TemporaryDirectory(prefix='mmap-ra-check-') as temp:
    c = Path(temp) / 'check.c'
    binary = Path(temp) / 'check'
    c.write_text(source)
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    str(c), '-o', str(binary)], check=True)
    result = subprocess.check_output([str(binary)], text=True).strip()
report = {'status': 'passed', 'scope': __doc__, 'baseline': baseline,
          'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
          'source_blob': subprocess.check_output(['git', 'hash-object', path], cwd=root, text=True).strip(),
          'harness_sha256': hashlib.sha256(source.encode()).hexdigest(),
          'result': result, 'remote_resources_used': []}
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(result)
