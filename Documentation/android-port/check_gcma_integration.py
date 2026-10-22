#!/usr/bin/env python3
"""Check GCMA teardown and CMA guards with extracted source and host shims.

Models background eviction at hash-unlock boundaries, reference ownership and
lock order. Exercises full CMA allocation/range functions with mocked bitmaps,
migration and IRQ state. Checks the extracted GCMA discard reschedule condition.
Old-source controls expose teardown UAF, null dereference, rejected native flags,
atomic retry sleep and IRQ-state loss. No real kernel allocator, RCU or race runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[2]
baseline='05ae9392c7c8cc0c314662828698a04db2f2ca8d'
def function(t,name):
    start=t.index(name);end=t.index('{',start)+1;depth=1
    while depth:
        depth+=(t[end]=='{')-(t[end]=='}');end+=1
    return t[start:end]+'\n'
parts=[]
for prefix in ['', 'old_']:
    sources={f:(root/f).read_text() if not prefix else subprocess.check_output(
        ['git','show',baseline+':'+f],cwd=root,text=True) for f in ['mm/gcma.c','mm/cma.c']}
    names=['gcma_cc_invalidate_fs','cma_debug_show_areas','cma_range_alloc','__cma_alloc']
    signatures=['static void gcma_cc_invalidate_fs(', 'static void cma_debug_show_areas(',
                'static int cma_range_alloc(', 'struct page *__cma_alloc(']
    for name,signature in zip(names,signatures):
        body=function(sources['mm/gcma.c' if name.startswith('gcma') else 'mm/cma.c'],signature)
        if prefix:
            for n in names:body=body.replace(n+'(',prefix+n+'(')
        parts.append(body)
    discard=function(sources['mm/gcma.c'],'static void __gcma_discard_range(')
    condition=re.search(r'if \((!\(\+\+scanned.*)\) \{',discard)[1]
    parts.append('static bool '+prefix+'discard_yields(gfp_t gfp) { unsigned long scanned=XA_CHECK_SCHED-1; return '+condition+'; }\n')

shim=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned int gfp_t;
typedef unsigned long u64;
#define __GFP_DIRECT_RECLAIM 1U
#define GFP_KERNEL 7U
#define GFP_ATOMIC 8U
#define __GFP_NOWARN 16U
#define __GFP_NORETRY 32U
#define __GFP_COMP 64U
#define XA_CHECK_SCHED 64
#define WARN_ON_ONCE(c) (c)
#define VM_BUG_ON(c) assert(!(c))
#define pr_info(...) ((void)0)
#define pr_cont(...) ((void)0)
#define pr_debug(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
static bool irq_off,evict_on_unlock,evict_old;
static unsigned int live,refs_taken,reschedules,sleeps;
static bool gfpflags_allow_blocking(gfp_t g) {return !!(g&__GFP_DIRECT_RECLAIM);}
static bool irqs_disabled(void) {return irq_off;}
static void cond_resched(void) {reschedules++;}
struct cleancache_filekey { int key; };
struct gcma_inode;
struct hlist_node { struct gcma_inode *next; };
struct gcma_inode { struct hlist_node hash; struct cleancache_filekey key; int refs; bool hashed; };
struct hlist_head { struct gcma_inode *first; };
struct gcma_fs { int hash_lock; struct hlist_head inode_hash[1]; };
static struct gcma_fs *registered;
static int gcma_fs_lock,gcma_fs_idr;
static void put_gcma_inode(struct gcma_inode *n) {assert(n->refs>0);if(!--n->refs){free(n);live--;}}
static bool get_gcma_inode(struct gcma_inode *n) {assert(n->refs>0);n->refs++;refs_taken++;return true;}
static void evict_all(void) {
    while(registered->inode_hash[0].first) {
        struct gcma_inode *n=registered->inode_hash[0].first;
        registered->inode_hash[0].first=n->hash.next;n->hashed=false;put_gcma_inode(n);
    }
}
static void lock(int *l) {assert(!*l);*l=1;}
static void unlock(int *l) {
    assert(*l);*l=0;
    if(registered && l==&registered->hash_lock && evict_on_unlock){evict_on_unlock=false;evict_all();}
}
#define spin_lock_irqsave(l,f) do {(f)=irq_off;irq_off=true;lock(l);}while(0)
#define spin_unlock_irqrestore(l,f) do {unlock(l);irq_off=(f);}while(0)
#define spin_lock_irq(l) do {irq_off=true;lock(l);}while(0)
#define spin_unlock_irq(l) do {unlock(l);irq_off=false;}while(0)
#define spin_lock(l) lock(l)
#define spin_unlock(l) unlock(l)
#define HASH_SIZE(h) 1
#define hash_for_each(h,c,n,member) for((c)=0,(n)=(h)[0].first;(n);(n)=(n)->member.next)
static bool old_iteration(void) {if(evict_old){evict_old=false;evict_all();}return true;}
#define hash_for_each_safe(h,c,tmp,n,member) for((c)=0,(n)=(h)[0].first;(n) && ((tmp)=(struct hlist_node *)(n)->member.next,old_iteration());(n)=(struct gcma_inode *)(tmp))
static bool hlist_empty(struct hlist_head *h) {return !h->first;}
static struct gcma_fs *find_gcma_fs(int id) {return id==1?registered:NULL;}
static void gcma_erase_all_pages(struct gcma_inode *n) {
    assert(n->refs>0 && registered && !registered->hash_lock);
    if(n->hashed){assert(registered->inode_hash[0].first==n);registered->inode_hash[0].first=n->hash.next;n->hashed=false;put_gcma_inode(n);}
}
static void __gcma_cc_invalidate_inode(struct gcma_fs *fs,struct cleancache_filekey *key) {
    int value=key->key; /* Deliberately dereference the old unpinned key. */
    struct gcma_inode *n=fs->inode_hash[0].first;
    if(n && n->key.key==value){get_gcma_inode(n);gcma_erase_all_pages(n);put_gcma_inode(n);}
}
static void synchronize_rcu(void) {}
static void idr_remove(int *idr,int id) {(void)idr;assert(id==1);registered=NULL;}
#define kfree(p) free(p)
static void setup_fs(unsigned int count) {
    registered=calloc(1,sizeof(*registered));assert(registered);refs_taken=reschedules=0;
    for(unsigned int i=0;i<count;i++) {
        struct gcma_inode *n=calloc(1,sizeof(*n));assert(n);live++;
        n->refs=1;n->hashed=true;n->key.key=i;n->hash.next=registered->inode_hash[0].first;
        registered->inode_hash[0].first=n;
    }
}
struct page { unsigned long pfn; };
struct cma_memrange { unsigned long base_pfn,count; unsigned long *bitmap; };
struct cma { const char *name; unsigned long count,available_count; unsigned int order_per_bit;
    int lock,alloc_mutex,nranges; bool gcma; struct cma_memrange ranges[1]; };
static struct page pages[8];
static bool fragmented,fatal,incompatible;
static unsigned int migrated,allocated,cleared;
static unsigned long cma_bitmap_aligned_mask(struct cma *c,unsigned int o) {(void)c;(void)o;return 0;}
static unsigned long cma_bitmap_aligned_offset(struct cma *c,struct cma_memrange *r,unsigned int o) {(void)c;(void)r;(void)o;return 0;}
static unsigned long cma_bitmap_maxno(struct cma *c,struct cma_memrange *r) {(void)c;return r->count;}
static unsigned long cma_bitmap_pages_to_bits(struct cma *c,unsigned long n) {(void)c;return n;}
static unsigned long bitmap_find_next_zero_area_off(unsigned long *b,unsigned long max,unsigned long start,unsigned long n,unsigned long mask,unsigned long off) {
    (void)b;(void)n;(void)mask;(void)off;return fragmented?max:start;
}
static void bitmap_set(unsigned long *b,unsigned long start,unsigned long n) {(void)b;(void)start;(void)n;}
static struct page *pfn_to_page(unsigned long pfn) {assert(pfn<8);pages[pfn].pfn=pfn;return &pages[pfn];}
static unsigned long page_to_pfn(struct page *p) {return p->pfn;}
static bool page_range_contiguous(struct page *p,unsigned long n) {(void)n;if(incompatible && !p->pfn)return false;return true;}
static void gcma_alloc_range(unsigned long s,unsigned long e,gfp_t g) {(void)s;(void)e;(void)g;allocated++;}
static void mutex_lock(int *l) {assert(!irq_off);lock(l);}
static void mutex_unlock(int *l) {unlock(l);}
#define ACR_FLAGS_CMA 0
static int alloc_contig_range(unsigned long s,unsigned long e,int flags,gfp_t g) {(void)s;(void)e;(void)flags;(void)g;migrated++;return 0;}
static void cma_clear_bitmap(struct cma *c,struct cma_memrange *r,unsigned long pfn,unsigned long n) {(void)r;(void)pfn;c->available_count+=n;cleared++;}
static int current;
static bool fatal_signal_pending(int task) {(void)task;return fatal;}
static unsigned long msecs_to_jiffies(unsigned long ms) {return ms;}
static void schedule_timeout_killable(unsigned long n) {assert(n==100);sleeps++;}
#define for_each_clear_bitrange(start,end,bitmap,nbits) for((start)=0,(end)=(nbits);(start)<(nbits);(start)=(end))
static void page_kasan_tag_reset(struct page *p) {(void)p;}
#define trace_android_vh_cma_alloc_retry(...) ((void)0)
#define trace_cma_alloc_busy_retry(...) ((void)0)
#define trace_android_vh_cma_alloc_bypass(...) ((void)0)
#define trace_cma_alloc_start(...) ((void)0)
#define trace_android_vh_cma_alloc_lat_start(...) ((void)0)
#define trace_cma_alloc_finish(...) ((void)0)
#define trace_android_vh_cma_alloc_end(...) ((void)0)
#define trace_android_vh_cma_alloc_lat_end(...) ((void)0)
#define count_vm_event(...) ((void)0)
#define cma_sysfs_account_success_pages(...) ((void)0)
#define cma_sysfs_account_fail_pages(...) ((void)0)
static void setup_cma(struct cma *c,bool gcma) {
    *c=(struct cma){.name="test",.count=8,.available_count=8,.gcma=gcma,.nranges=1,.ranges={{.count=8}}};
    fragmented=fatal=incompatible=irq_off=false;sleeps=migrated=allocated=cleared=0;
}
'''
checks=r'''
int main(int argc,char **argv) {
    if(argc>1 && !strcmp(argv[1],"old-unmount")) {setup_fs(2);evict_old=true;old_gcma_cc_invalidate_fs(1);return 0;}
    if(argc>1 && !strcmp(argv[1],"old-null")) {old___cma_alloc(NULL,1,0,GFP_KERNEL);return 0;}
    for(unsigned int n=0;n<12;n++)for(int evict=0;evict<2;evict++) {
        setup_fs(n);evict_on_unlock=evict;gcma_cc_invalidate_fs(1);
        assert(!registered && !live && !irq_off && refs_taken==(evict && n?1:n));
    }
    gcma_cc_invalidate_fs(3);
    struct cma c;setup_cma(&c,false);
    assert(!__cma_alloc(NULL,1,0,GFP_KERNEL));c.count=0;assert(!__cma_alloc(&c,1,0,GFP_KERNEL));
    setup_cma(&c,false);assert(__cma_alloc(&c,1,0,GFP_KERNEL|__GFP_COMP) && migrated==1);
    setup_cma(&c,false);assert(!old___cma_alloc(&c,1,0,GFP_KERNEL|__GFP_COMP) && !migrated);
    for(unsigned int extra=0;extra<4;extra++)for(int off=0;off<2;off++)for(int full=0;full<2;full++) {
        gfp_t g=GFP_ATOMIC | (extra&1?__GFP_NOWARN:0) | (extra&2?__GFP_NORETRY:0);
        setup_cma(&c,true);irq_off=off;fragmented=full;
        assert((__cma_alloc(&c,1,0,g)!=NULL)==!full);
        assert(irq_off==off && !sleeps && !discard_yields(g));
    }
    setup_cma(&c,true);fragmented=true;assert(!__cma_alloc(&c,1,0,GFP_KERNEL));assert(sleeps==1);
    setup_cma(&c,true);incompatible=true;assert(__cma_alloc(&c,1,0,GFP_ATOMIC));
    setup_cma(&c,true);c.available_count=0;irq_off=true;assert(!__cma_alloc(&c,1,0,GFP_ATOMIC));assert(irq_off && !sleeps);
    setup_cma(&c,true);assert(!__cma_alloc(&c,1,0,GFP_ATOMIC|__GFP_COMP));
    setup_cma(&c,true);fragmented=true;assert(!old___cma_alloc(&c,1,0,GFP_ATOMIC));assert(sleeps==1);
    setup_cma(&c,true);irq_off=true;assert(old___cma_alloc(&c,1,0,GFP_ATOMIC));assert(!irq_off);
    assert(old_discard_yields(GFP_ATOMIC|__GFP_NOWARN));
    assert(discard_yields(GFP_KERNEL) && !discard_yields(GFP_ATOMIC));
    puts("GCMA teardown references and CMA native/atomic contract checks passed; old guard, sleep and IRQ controls reproduced");
}
'''
with tempfile.TemporaryDirectory(prefix='gcma-integration-') as tmp:
    src=Path(tmp)/'check.c';binary=Path(tmp)/'check';src.write_text(shim+''.join(parts)+checks)
    flags=['-std=gnu11','-Wall','-Wextra','-Wno-unused-variable','-Wno-unused-parameter',
           '-Wno-unused-function','-Wno-sign-compare','-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run(['cc',*flags,str(src),'-o',str(binary)],check=True)
    result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
    if result.returncode:raise SystemExit(result.stderr or result.stdout)
    controls=[]
    for mode,expected in [('old-unmount','heap-use-after-free'),('old-null','null pointer')]:
        old=subprocess.run([str(binary),mode],capture_output=True,text=True,timeout=15)
        assert old.returncode and expected in old.stderr,(mode,old.stderr)
        controls.append({'mode':mode,'sanitizer_finding':expected})
record={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'negative_control_commit':baseline,'excerpts_sha256':hashlib.sha256(''.join(parts).encode()).hexdigest(),
        'compiler_flags':flags,'result':result.stdout.strip(),'negative_controls':controls,'scope':__doc__.strip()}
a.output.write_text(json.dumps(record,indent=2)+'\n');print(record['result']);print(controls)
