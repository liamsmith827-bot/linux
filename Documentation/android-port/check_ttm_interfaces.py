#!/usr/bin/env python3
"""Host checks of extracted TTM allocation/initialization and backup control flow."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
PRE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef unsigned int gfp_t;
typedef unsigned long pgoff_t;
typedef long long s64;
#define BIT(n) (1U << (n))
#define PAGE_SIZE 4096
#define GFP_KERNEL BIT(0)
#define __GFP_NOMEMALLOC BIT(1)
#define __GFP_NORETRY BIT(2)
#define __GFP_NOWARN BIT(3)
#define __GFP_THISNODE BIT(4)
#define __GFP_DIRECT_RECLAIM BIT(5)
#define DMA_ATTR_FORCE_CONTIGUOUS BIT(0)
#define DMA_ATTR_NO_WARN BIT(1)
#define TTM_NUM_CACHING_TYPES 3
#define NR_PAGE_ORDERS 12
struct page { unsigned long private; };
struct device { int unused; };
struct ttm_pool_type { unsigned initialized; };
struct ttm_pool { struct device *dev; int nid; unsigned alloc_flags;
    struct { struct ttm_pool_type orders[NR_PAGE_ORDERS]; } caching[3]; };
struct ttm_pool_dma { unsigned long addr, vaddr; };
static struct page page;
static char dma_buffer[4096] __attribute__((aligned(4096)));
static unsigned warning, seen_gfp, seen_order, seen_attr, calls, hook_calls;
static unsigned hook_flags, fail_stage;
#define WARN_ON(v) (warning += !!(v))
static struct ttm_pool_type *ttm_pool_select_type(struct ttm_pool *p, unsigned c, unsigned o) {
    return &p->caching[c].orders[o];
}
static void ttm_pool_type_init(struct ttm_pool_type *t, struct ttm_pool *p, unsigned c, unsigned o) {
    assert(t == &p->caching[c].orders[o]); t->initialized++;
}
static void trace_android_vh_ttm_pool_alloc_page_flags(unsigned order, gfp_t *gfp) {
    hook_calls++; *gfp |= hook_flags;
}
static struct page *alloc_pages_node(int nid, gfp_t gfp, unsigned order) {
    assert(nid == 7); calls++; seen_gfp=gfp; seen_order=order;
    return fail_stage==1 ? NULL : &page;
}
static void *kmalloc(size_t size, unsigned flags) {
    return fail_stage==2 ? NULL : malloc(size);
}
static void kfree(void *p) { free(p); }
static void *dma_alloc_attrs(struct device *dev, unsigned long size, unsigned long *addr,
                            unsigned gfp, unsigned attr) {
    assert(dev); calls++; seen_gfp=gfp; seen_attr=attr;
    assert(size==(1UL<<seen_order)*PAGE_SIZE); *addr=0x1000;
    return fail_stage==3 ? NULL : dma_buffer;
}
static bool is_vmalloc_addr(void *p) { return false; }
static struct page *vmalloc_to_page(void *p) { return &page; }
static struct page *virt_to_page(void *p) { return &page; }
'''
ALLOC_MAIN = r'''
int main(void) {
    struct device dev;
    unsigned count=0, warnings_wrong=0;
    for(unsigned flags=0;flags<2048;flags++) {
        struct ttm_pool pool={.dev=&dev,.nid=7,.alloc_flags=flags};
        assert(ttm_pool_uses_dma_alloc(&pool)==!!(flags & BIT(8)));
        assert(ttm_pool_uses_dma32(&pool)==!!(flags & BIT(9)));
        assert(ttm_pool_beneficial_order(&pool)==(flags&255));
        for(unsigned order=0;order<12;order++) for(unsigned hook=0;hook<2;hook++) {
            fail_stage=0; calls=hook_calls=0; seen_order=order;
            hook_flags=hook ? __GFP_DIRECT_RECLAIM : 0;
            struct page *p=ttm_pool_alloc_page(&pool,GFP_KERNEL|__GFP_DIRECT_RECLAIM,order);
            assert(p && calls==1 && hook_calls==1);
            unsigned expected=GFP_KERNEL|__GFP_DIRECT_RECLAIM;
            if(order) expected|=__GFP_NOMEMALLOC|__GFP_NORETRY|__GFP_NOWARN|__GFP_THISNODE;
            if((flags&255) && order>(flags&255)) expected&=~__GFP_DIRECT_RECLAIM;
            assert(seen_gfp==expected);
            if(flags&BIT(8)) {
                struct ttm_pool_dma *dma=(void *)p->private;
                assert(dma->vaddr==((unsigned long)dma_buffer|order));
                assert(seen_attr==(DMA_ATTR_FORCE_CONTIGUOUS|(order ? DMA_ATTR_NO_WARN : 0)));
                free(dma);
            } else assert(p->private==order);
            count++;
        }
    }
    for(unsigned old=0;old<2;old++) for(unsigned dma=0;dma<2;dma++) for(unsigned present=0;present<2;present++) {
        struct ttm_pool pool={.alloc_flags=old?BIT(8):0}; warning=0;
        ttm_pool_init(&pool,present?&dev:NULL,7,dma?BIT(8):0);
        warnings_wrong += warning!=(!present&&dma);
        if(PORT) assert(warning==(!present&&dma));
        assert(pool.alloc_flags==(dma?BIT(8):0) && pool.dev==(present?&dev:NULL) && pool.nid==7);
        for(unsigned c=0;c<3;c++) for(unsigned o=0;o<12;o++) assert(pool.caching[c].orders[o].initialized==1);
        count++;
    }
    for(unsigned failure=1;failure<=3;failure++) {
        struct ttm_pool pool={.dev=&dev,.nid=7,.alloc_flags=failure==1?0:BIT(8)};
        fail_stage=failure;seen_order=2;
        assert(!ttm_pool_alloc_page(&pool,GFP_KERNEL,2));count++;
    }
    printf("{\"cases\":%u,\"wrong_initialization_warnings\":%u}\n",count,warnings_wrong);
}
'''
BACKUP_PRE = r'''
#define AOP_WRITEPAGE_ACTIVATE 0x80000
struct address_space { int unused; };
struct file { struct address_space *f_mapping; };
struct folio { unsigned locked, mapped, writeback; };
static struct folio folio;
static struct page source_page;
static int read_error, write_result;
static unsigned dirty_ok, unlock_errors, locks, unlocks, writes, put_count, copies;
#define IS_ERR(p) ((intptr_t)(p)<0)
#define PTR_ERR(p) ((intptr_t)(p))
static struct folio *shmem_read_folio_gfp(struct address_space *m,pgoff_t i,gfp_t g) {
    return read_error ? (void *)(intptr_t)read_error : &folio;
}
static void folio_mark_accessed(struct folio *f) {}
static void folio_lock(struct folio *f) { assert(!f->locked);f->locked=1;locks++; }
static void folio_mark_dirty(struct folio *f) {}
static struct page *folio_file_page(struct folio *f,pgoff_t i) { return &page; }
static void copy_highpage(struct page *to,struct page *from) { assert(from==&source_page);copies++; }
static unsigned long ttm_backup_shmem_idx_to_handle(pgoff_t i) { return i+1; }
static bool folio_mapped(struct folio *f) { return f->mapped; }
static bool folio_clear_dirty_for_io(struct folio *f) { return dirty_ok; }
static void folio_set_reclaim(struct folio *f) {}
static bool folio_test_writeback(struct folio *f) { return f->writeback; }
static void folio_clear_reclaim(struct folio *f) {}
static void folio_unlock(struct folio *f) {
    unlock_errors+=!f->locked;f->locked=0;unlocks++;
}
/* Contract checked against pinned shmem_writeout and swap_writeout sources. */
static int shmem_writeout(struct folio *f,void *plug,void *list) {
    assert(f->locked);writes++;
    if(write_result!=AOP_WRITEPAGE_ACTIVATE) folio_unlock(f);
    return write_result;
}
static void folio_put(struct folio *f) { assert(!f->locked);put_count++; }
'''
BACKUP_MAIN = r'''
int main(void) {
    struct address_space mapping;struct file backup={.f_mapping=&mapping};
    int returns[]={0,AOP_WRITEPAGE_ACTIVATE,-EIO,-ENOMEM};
    unsigned count=0,total_errors=0;
    for(unsigned w=0;w<2;w++) for(unsigned m=0;m<2;m++) for(unsigned d=0;d<2;d++)
    for(unsigned r=0;r<4;r++) for(unsigned wb=0;wb<2;wb++) {
        folio=(struct folio){.mapped=m,.writeback=wb};
        read_error=0;write_result=returns[r];dirty_ok=d;
        unlock_errors=locks=unlocks=writes=put_count=copies=0;
        assert(ttm_backup_backup_page(&backup,&source_page,w,7,0,0)==8);
        assert(locks==1 && put_count==1 && copies==1 && writes==(w&&!m&&d));
        if(PORT) assert(unlocks==1 && !unlock_errors);
        total_errors+=unlock_errors;count++;
    }
    read_error=-ENOMEM;locks=put_count=copies=0;
    assert(ttm_backup_backup_page(&backup,&source_page,true,7,0,0)==-ENOMEM);
    assert(!locks&&!put_count&&!copies);count++;
    printf("{\"cases\":%u,\"double_unlocks\":%u}\n",count,total_errors);
}
'''

def source(ref, path):
    return (ROOT/path).read_text() if ref is None else subprocess.check_output(
        ['git','show',ref+':'+path],cwd=ROOT,text=True)

def run(tmp,label,body,main,port):
    src=Path(tmp)/(label+'.c');exe=src.with_suffix('')
    src.write_text(PRE+body+main)
    subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer','-fno-pie','-no-pie','-DPORT='+str(int(port)),
                    str(src),'-o',str(exe)],check=True,capture_output=True,text=True)
    result=subprocess.run([str(exe)],check=True,capture_output=True,text=True)
    assert not result.stderr,result.stderr
    return dict(extracted_sha256=hashlib.sha256(body.encode()).hexdigest(),**json.loads(result.stdout))

def main():
    results={}
    with tempfile.TemporaryDirectory(prefix='ttm-interfaces-') as tmp:
        for label,ref in [('port',None),('ack_control',ACK)]:
            flags=source(ref,'include/drm/ttm/ttm_allocation.h')
            helpers=source(ref,'drivers/gpu/drm/ttm/ttm_pool_internal.h')
            pool=source(ref,'drivers/gpu/drm/ttm/ttm_pool.c')
            body=flags+'\n'+''.join(function(helpers,n) for n in
                ['ttm_pool_uses_dma_alloc','ttm_pool_uses_dma32','ttm_pool_beneficial_order'])
            body+=''.join(function(pool,n) for n in ['ttm_pool_alloc_page','ttm_pool_init'])
            results['allocation_'+label]=run(tmp,'alloc_'+label,body,ALLOC_MAIN,ref is None)
        for label,ref in [('port',None),('lts_control',LTS)]:
            body=BACKUP_PRE+"s64\n"+function(source(ref,'drivers/gpu/drm/ttm/ttm_backup.c'),'ttm_backup_backup_page')
            results['backup_'+label]=run(tmp,'backup_'+label,body,BACKUP_MAIN,ref is None)
    assert results['allocation_ack_control']['wrong_initialization_warnings']==2
    assert results['backup_lts_control']['double_unlocks']>0
    print(json.dumps(dict(results=results,limitations='Extracted C functions with allocator, pool and writeout shims under ASan/UBSan. No real GPU, DMA, reclaim, swap I/O, KUnit execution or concurrency is verified. The backup writer shim models the locally reviewed writeout lock contract.'),indent=2))

if __name__=='__main__':main()
