#!/usr/bin/env python3
"""Exercise extracted filemap hook paths with host teardown and callback shims.

Covers full generic_perform_write plus mmap-readahead and mapped-folio hook
blocks. Simulated write_end, fault-lock release and folio unlock free objects;
old-source controls must report ASan heap-use-after-free. No kernel race, actual
filesystem I/O, registered module or emulator is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[2]; baseline='745944398038'
current=(root/'mm/filemap.c').read_text()
old=subprocess.check_output(['git','show',baseline+':mm/filemap.c'],cwd=root,text=True)
def function(text,name):
    start=text.index(name);end=text.index('{',start)+1;depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]+'\n'
excerpts=[]
for tag,source in [('',current),('old_',old)]:
    excerpts.append(function(source,'ssize_t generic_perform_write(').replace('generic_perform_write(',tag+'generic_perform_write(',1))
    tail=function(source,'static struct file *do_sync_mmap_readahead(')
    tail=tail[tail.rindex('\tfpin = maybe_unlock_mmap_for_io'):]
    excerpts.append('static struct file *'+tag+'readahead_hook(struct vm_fault *vmf, struct file *file) {\nstruct file_ra_state *ra = &file->f_ra; struct readahead_control ractl = {0}; struct file *fpin = NULL;\n'+tail)
    body=function(source,'vm_fault_t filemap_map_pages(')
    marker='\t\tif (trace_android_vh_filemap_folio_mapped_enabled())' if not tag else '\t\tfolio_unlock(folio);\n\t\ttrace_android_vh_filemap_folio_mapped'
    block=body[body.index(marker):body.index('\n\t} while')]
    excerpts.append('static void '+tag+'mapped_hook(struct folio *folio) {\n'+block+'\n}\n')
shim=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define unlikely(x) (x)
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
typedef unsigned long pgoff_t;
struct folio { pgoff_t index; int refs; };
struct address_space; struct kiocb;
struct address_space_operations {
    int (*write_begin)(struct kiocb *,struct address_space *,loff_t,size_t,struct folio **,void **);
    int (*write_end)(struct kiocb *,struct address_space *,loff_t,size_t,size_t,struct folio *,void *);
};
struct address_space { const struct address_space_operations *a_ops; };
struct file_ra_state { unsigned long ra_pages,start,size,async_size; };
struct file { struct address_space *f_mapping; void *f_inode; struct file_ra_state f_ra; };
struct kiocb { struct file *ki_filp; loff_t ki_pos; unsigned int ki_flags; };
struct iov_iter { size_t left; };
struct vm_area_struct { int magic; };
struct vm_fault { struct vm_area_struct *vma; pgoff_t pgoff; };
struct readahead_control { pgoff_t _index; };
static bool fatal,begin_failure,end_failure,partial,drop_lock,enabled=true;
static unsigned int stats_calls,mapped_calls,custom_calls,null_vmas;
static pgoff_t expected_index;
static struct file pinned;
static unsigned long mapping_max_folio_size(struct address_space *m) { (void)m; return PAGE_SIZE; }
static size_t iov_iter_count(struct iov_iter *i) { return i->left; }
static void iov_iter_revert(struct iov_iter *i,size_t n) { i->left+=n; }
static void *current_task;
#define current current_task
static bool fatal_signal_pending(void *task) { (void)task; return fatal; }
static void balance_dirty_pages_ratelimited(struct address_space *m) { (void)m; }
static size_t offset_in_folio(struct folio *f,loff_t pos) { (void)f; return pos%PAGE_SIZE; }
static size_t folio_size(struct folio *f) { (void)f; return PAGE_SIZE; }
static bool mapping_writably_mapped(struct address_space *m) { (void)m; return false; }
static void flush_dcache_folio(struct folio *f) { assert(f->refs>0); }
static size_t copy_folio_from_iter_atomic(struct folio *f,size_t offset,size_t bytes,struct iov_iter *i) {
    (void)f; (void)offset; assert(i->left>=bytes); i->left-=bytes; return bytes;
}
static size_t fault_in_iov_iter_readable(struct iov_iter *i,size_t n) { (void)i; (void)n; return 0; }
static void cond_resched(void) {}
static void trace_android_vh_adjust_iocb_flags(struct file *f,loff_t pos,size_t n,unsigned int *flags) {
    (void)f;(void)pos;(void)n;(void)flags;
}
static void trace_android_vh_io_statistics(struct address_space *m,pgoff_t index,int n,bool write,bool direct) {
    (void)m;(void)n;(void)write;(void)direct; assert(index==expected_index);stats_calls++;
}
static int begin(struct kiocb *iocb,struct address_space *m,loff_t pos,size_t n,struct folio **f,void **data) {
    (void)iocb;(void)m;(void)n;(void)data;if(begin_failure)return -ENOMEM;
    *f=malloc(sizeof(**f));assert(*f);**f=(struct folio){.index=pos>>PAGE_SHIFT,.refs=1};
    expected_index=(*f)->index;return 0;
}
static int end(struct kiocb *iocb,struct address_space *m,loff_t pos,size_t n,size_t copied,struct folio *f,void *data) {
    (void)iocb;(void)m;(void)pos;(void)n;(void)data;free(f);
    if(end_failure)return -EIO;
    return (int)(partial ? min(copied,2) : copied);
}
static struct file *maybe_unlock_mmap_for_io(struct vm_fault *vmf,struct file *fpin) {
    if(drop_lock){free(vmf->vma);return &pinned;}return fpin;
}
static void trace_android_vh_tune_mmap_readaround(unsigned long n,pgoff_t p,unsigned long *start,unsigned long *size,unsigned long *async) {
    (void)n;(void)p;(void)start;(void)size;(void)async;
}
static void trace_android_vh_page_cache_read(void *inode,unsigned long start,unsigned long size) {(void)inode;(void)start;(void)size;}
static void trace_android_vh_page_cache_readahead_start(struct file *f,pgoff_t p,unsigned long n,bool sync) {(void)f;(void)p;(void)n;(void)sync;}
static void trace_android_vh_page_cache_readahead_end(struct file *f,pgoff_t p) {(void)f;(void)p;}
static void trace_android_vh_customize_ractl(struct readahead_control *r,struct file_ra_state *ra,struct vm_area_struct *v,bool async) {
    (void)r;(void)ra;(void)async;custom_calls++;
    if(v)assert(v->magic==123);else null_vmas++;
}
static void page_cache_ra_order(struct readahead_control *r,struct file_ra_state *ra) {(void)r;(void)ra;}
static bool trace_android_vh_filemap_folio_mapped_enabled(void) {return enabled;}
static void folio_get(struct folio *f) {assert(f->refs>0);f->refs++;}
static void folio_put(struct folio *f) {assert(f->refs>0);if(!--f->refs)free(f);}
static void folio_unlock(struct folio *f) {folio_put(f); /* Simulated cache truncation once unlocked. */}
static void trace_android_vh_filemap_folio_mapped(struct folio *f) {assert(f->refs>0);mapped_calls++;}
'''
checks=r'''
int main(int argc,char **argv) {
    struct address_space_operations ops={begin,end};struct address_space mapping={&ops};
    struct file file={.f_mapping=&mapping};struct kiocb iocb={.ki_filp=&file,.ki_pos=4094};
    struct iov_iter iter={.left=14};
    if(argc>1 && !strcmp(argv[1],"old-write")){old_generic_perform_write(&iocb,&iter);return 0;}
    if(argc>1 && !strcmp(argv[1],"old-vma")){
        struct vm_area_struct *v=malloc(sizeof(*v));v->magic=123;
        struct vm_fault vmf={.vma=v};drop_lock=true;old_readahead_hook(&vmf,&file);return 0;
    }
    if(argc>1 && !strcmp(argv[1],"old-folio")){
        struct folio *f=malloc(sizeof(*f));*f=(struct folio){.refs=1};old_mapped_hook(f);return 0;
    }
    for(int mode=0;mode<5;mode++){
        fatal=mode==1;begin_failure=mode==2;end_failure=mode==3;partial=mode==4;
        iter.left=14;iocb.ki_pos=4094;stats_calls=0;
        ssize_t ret=generic_perform_write(&iocb,&iter);
        if(mode>=1 && mode<=3){assert(ret==(mode==1?-EINTR:mode==2?-ENOMEM:-EIO));assert(!stats_calls && iocb.ki_pos==4094);}
        else {assert(ret==14 && !iter.left && stats_calls && iocb.ki_pos==4108);}
    }
    for(int drop=0;drop<2;drop++){
        struct vm_area_struct *v=malloc(sizeof(*v));v->magic=123;
        struct vm_fault vmf={.vma=v};drop_lock=drop;custom_calls=null_vmas=0;
        assert(readahead_hook(&vmf,&file)==(drop?&pinned:NULL));
        assert(custom_calls==1 && null_vmas==(unsigned int)drop);
        if(!drop)free(v);
    }
    for(int on=0;on<2;on++){
        struct folio *f=malloc(sizeof(*f));*f=(struct folio){.refs=1};
        enabled=on;mapped_calls=0;mapped_hook(f);assert(mapped_calls==(unsigned int)on);
    }
    puts("Filemap hook lifetime checks passed with simulated teardown");
}
'''
program=shim+''.join(excerpts)+checks
with tempfile.TemporaryDirectory(prefix='filemap-hook-lifetime-check-') as tmp:
    src=Path(tmp)/'check.c';binary=Path(tmp)/'check';src.write_text(program)
    flags=['-std=gnu11','-Wall','-Wextra','-Wno-sign-compare','-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run(['cc',*flags,str(src),'-o',str(binary)],check=True)
    r=subprocess.run([str(binary)],text=True,capture_output=True,timeout=15)
    if r.returncode:raise SystemExit(r.stderr or r.stdout)
    controls=[]
    for mode in ['old-write','old-vma','old-folio']:
        bad=subprocess.run([str(binary),mode],text=True,capture_output=True,timeout=15)
        assert bad.returncode and 'heap-use-after-free' in bad.stderr,(mode,bad.stderr)
        controls.append({'mode':mode,'asan_heap_use_after_free':True})
record={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'negative_control_commit':subprocess.check_output(['git','rev-parse',baseline],cwd=root,text=True).strip(),
        'excerpts_sha256':hashlib.sha256(''.join(excerpts).encode()).hexdigest(),'compiler_flags':flags,
        'result':r.stdout.strip(),'negative_controls':controls,'scope':__doc__.strip()}
a.output.write_text(json.dumps(record,indent=2)+'\n');print(record['result']);print(controls)
