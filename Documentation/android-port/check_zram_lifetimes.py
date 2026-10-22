#!/usr/bin/env python3
"""Exercise extracted zram error/slot/completion functions with host shims."""
import argparse, hashlib, json, re, subprocess, tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[2];baseline='3acc3712548b5f8b8f0f5c52133ae8b46ddb8495'
def function(text,name):
    m=re.search(r'^[\w ][^\n]*\b'+name+r'\([^;{]*\)\n\{',text,re.M)
    assert m,name
    end=m.end();depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[m.start():end]+'\n'
shim=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define PAGE_SIZE 4096
#define GFP_NOIO 0
#define IS_ENABLED(x) 1
#define WARN_ON_ONCE(x) (x)
#define CONFIG_ZRAM_TRACK_ENTRY_ACTIME 1
#define CAP_SYS_NICE 23
#define ZRAM_ANDROID_IOC_PROCESS_RANGE_WRITEBACK 2
#define guard(x) no_guard
static void no_guard(void *p) {(void)p;}
typedef int atomic_t;
#define atomic64_inc(p) (++*(p))
#define atomic64_dec(p) (--*(p))
#define atomic64_sub(n,p) (*(p)-=(n))
#define atomic64_add(n,p) (*(p)+=(n))
#define atomic_set(p,n) (*(p)=(n))
static int atomic_xchg(int *p,int n) {int old=*p;*p=n;return old;}
struct xarray { unsigned long value; };
struct page { char bytes[PAGE_SIZE]; };
struct bio { int bi_opf,remaining; struct { unsigned long bi_sector; } bi_iter;
    void *bi_private; void (*bi_end_io)(struct bio *); };
struct stats { long bd_reads,huge_pages,compr_data_size,pages_stored,same_pages; };
struct zram { void *bdev,*backing_dev,*mem_pool; int init_lock,initialized,pp_in_progress;
    struct stats stats; struct { struct { u32 ac_time; } attr; } table[1];
    unsigned flags,size,prio; unsigned long handle; struct xarray prefetch_cache; };
struct zram_rb_req { struct zram *zram; u32 index; unsigned long blk_idx;
    struct bio *bio,*parent; };
static unsigned malloc_calls,free_calls,submits,request_fail,bio_fail;
static void *kmalloc(size_t n,int flags) {(void)flags;malloc_calls++;return request_fail?NULL:malloc(n);}
static void kfree(void *p) {if(p)free_calls++;free(p);}
static struct bio *bio_alloc(void *bdev,unsigned nr,int op,int flags) {
    (void)bdev;(void)nr;(void)op;(void)flags;return bio_fail?NULL:calloc(1,sizeof(struct bio));
}
static void __bio_add_page(struct bio *b,struct page *p,int n,int off) {(void)b;(void)p;assert(n==PAGE_SIZE&&!off);}
static void bio_inc_remaining(struct bio *p) {p->remaining++;}
static void zram_async_read_endio(struct bio *b) {
    struct zram_rb_req *r=b->bi_private;r->parent->remaining--;kfree(r);free(b);
}
static void submit_bio(struct bio *b) {submits++;assert(b->bi_iter.bi_sector==11*8);b->bi_end_io(b);}
static int read_from_bdev_sync(struct zram *z,struct page *p,u32 i,unsigned long b) {(void)z;(void)p;(void)i;(void)b;return -EIO;}
enum {ZRAM_IDLE,ZRAM_INCOMPRESSIBLE,ZRAM_PP_SLOT,ZRAM_HUGE,ZRAM_WB,ZRAM_SAME};
static bool test_slot_flag(struct zram *z,u32 i,int f) {assert(!i);return z->flags&(1U<<f);}
static void clear_slot_flag(struct zram *z,u32 i,int f) {assert(!i);z->flags&=~(1U<<f);}
static void set_slot_flag(struct zram *z,u32 i,int f) {assert(!i);z->flags|=1U<<f;}
static unsigned long get_slot_handle(struct zram *z,u32 i) {assert(!i);return z->handle;}
static void set_slot_handle(struct zram *z,u32 i,unsigned long h) {assert(!i);z->handle=h;}
static unsigned get_slot_size(struct zram *z,u32 i) {assert(!i);return z->size;}
static void set_slot_size(struct zram *z,u32 i,unsigned n) {assert(!i);z->size=n;}
static void set_slot_comp_priority(struct zram *z,u32 i,unsigned n) {assert(!i);z->prio=n;}
static unsigned released_blocks,freed_objects,slot_locks;
static void zram_release_bdev_block(struct zram *z,unsigned long b) {(void)z;assert(b==19);released_blocks++;}
static void zs_free(void *pool,unsigned long h) {(void)pool;assert(h==55);freed_objects++;}
static void slot_lock(struct zram *z,u32 i) {(void)z;assert(!i);slot_locks++;}
static void slot_unlock(struct zram *z,u32 i) {(void)z;assert(!i&&slot_locks);slot_locks--;}
static void *xa_erase(struct xarray *x,u32 i) {assert(!i);void *v=(void *)(uintptr_t)x->value;x->value=0;return v;}
static bool xa_is_value(void *v) {return (uintptr_t)v&1;}
static unsigned long xa_to_value(void *v) {return (uintptr_t)v>>1;}
struct zram_android_ioc_process_range_writeback {u64 pidfd,start_addr,size,next_addr,written_bytes;};
struct zram_pp_ctl {int dummy;};
struct zram_wb_ctl {u64 processed_bytes;};
static struct zram_pp_ctl pp;
static struct zram_wb_ctl wb;
static int permission,fail_pp,fail_wb,scan_error,write_error;
static unsigned released_pp,released_wb,scans,writes;
static bool capable(int cap) {assert(cap==CAP_SYS_NICE);return permission;}
static bool init_done(struct zram *z) {return z->initialized;}
static struct zram_pp_ctl *init_pp_ctl(void) {return fail_pp?NULL:&pp;}
static struct zram_wb_ctl *init_wb_ctl(struct zram *z) {(void)z;wb.processed_bytes=0;return fail_wb?NULL:&wb;}
static void release_pp_ctl(struct zram *z,struct zram_pp_ctl *p) {(void)z;assert(p==&pp);released_pp++;}
static void release_wb_ctl(struct zram_wb_ctl *w) {assert(w==&wb);released_wb++;}
static int zram_ioctl_process_scan(struct zram *z,unsigned cmd,u64 pidfd,
    struct zram_android_ioc_process_range_writeback *r,struct zram_pp_ctl *p) {
    (void)z;assert(cmd==2&&pidfd==7&&p==&pp);scans++;
    if(!scan_error)r->next_addr=8192;return scan_error;
}
static int zram_writeback_slots(struct zram *z,struct zram_pp_ctl *p,struct zram_wb_ctl *w) {
    (void)z;assert(p==&pp&&w==&wb);writes++;w->processed_bytes=4096;return write_error;
}
'''
test=r'''
int main(void) {
 unsigned cases=0,failures=0;
 for(unsigned fail=0;fail<3;fail++) {
  struct zram z={0};struct bio parent={.remaining=1};struct page page;
  malloc_calls=free_calls=submits=0;request_fail=fail==1;bio_fail=fail==2;
  int ret=read_from_bdev(&z,&page,0,11,&parent);
  failures+=ret!=(fail?-ENOMEM:0);
  assert(parent.remaining==1 && submits==!fail && malloc_calls==1);
  assert(free_calls==(fail!=1));cases++;
 }
 for(unsigned kind=0;kind<4;kind++)for(unsigned cached=0;cached<2;cached++) {
  struct zram z={0};z.handle=kind==3?0:55;z.size=kind==3?0:123;
  z.flags=kind==1?1U<<ZRAM_HUGE:kind==2?1U<<ZRAM_SAME:0;
  z.stats.huge_pages=kind==1;z.stats.same_pages=kind==2;z.stats.pages_stored=kind!=3;
  z.stats.compr_data_size=kind<2?123:0;z.prefetch_cache.value=cached?(19UL<<1)|1:0;
  released_blocks=freed_objects=0;
  slot_free(&z,0);
  failures+=z.prefetch_cache.value!=0 || released_blocks!=cached;
  assert(freed_objects==(kind<2));assert(!z.stats.huge_pages&&!z.stats.same_pages&&!z.stats.pages_stored);
  assert(!z.stats.compr_data_size);cases++;
 }
 {struct zram z={.handle=55,.size=123,.stats={.pages_stored=1,.compr_data_size=123},.prefetch_cache={.value=(19UL<<1)|1}};
  released_blocks=freed_objects=0;write_same_filled_page(&z,0x1122,0);
  failures+=z.prefetch_cache.value!=0||released_blocks!=1;
  assert(z.handle==0x1122&&z.stats.same_pages==1&&z.stats.pages_stored==1&&!slot_locks);cases++;
 }
 int errors[]={-EPERM,-EINVAL,-ENODEV,-EAGAIN,-ENOMEM,-ENOMEM,-ESRCH,-EIO,0};
 for(unsigned stage=0;stage<9;stage++) {
  struct zram z={.initialized=stage!=1,.backing_dev=stage==2?NULL:(void *)1,.pp_in_progress=stage==3};
  struct zram_android_ioc_process_range_writeback r={.pidfd=7,.start_addr=4096,.size=9000,.next_addr=0xfeed,.written_bytes=0xbeef};
  permission=stage!=0;fail_pp=stage==4;fail_wb=stage==5;scan_error=stage==6?-ESRCH:0;write_error=stage==7?-EIO:0;
  scans=writes=released_pp=released_wb=0;
  assert(zram_ioctl_process_writeback(&z,&r)==errors[stage]);
  failures+=r.written_bytes!=(stage>=7?4096:0)||r.next_addr!=(stage>=7?8192:0);
  assert(r.pidfd==7&&r.start_addr==4096&&r.size==9000);
  assert(z.pp_in_progress==(stage==3));assert(released_pp==(stage>=5)&&released_wb==(stage>=6));
  assert(scans==(stage>=6)&&writes==(stage>=7));cases++;
 }
 printf("{\"cases\":%u,\"failures\":%u}\n",cases,failures);return 0;
}
'''
# Pause the last notifier after decrementing but before waking/completing. The
# old wait predicate already permits return in this interval. The completion
# predicate remains false until notification has acquired/released its lock.
completion_shim=r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <sched.h>
typedef atomic_int atomic_t;
struct completion {pthread_mutex_t lock;bool done;};
struct zram_prefetch_ctl {atomic_t num_inflight;struct completion *done;int done_wait;};
static atomic_bool paused,proceed;
static bool atomic_dec_and_test(atomic_t *n) {
 bool last=atomic_fetch_sub(n,1)==1;
 if(last){atomic_store(&paused,true);while(!atomic_load(&proceed))sched_yield();}return last;
}
static void complete(struct completion *d) {pthread_mutex_lock(&d->lock);d->done=true;pthread_mutex_unlock(&d->lock);}
static void wake_up(int *wait) {(void)wait;}
'''
completion_test=r'''
static void *notifier(void *p) {PUT(p);return NULL;}
int main(void) {
 struct completion done={.lock=PTHREAD_MUTEX_INITIALIZER};
 struct zram_prefetch_ctl p={.num_inflight=1,.done=&done};
 pthread_t t;assert(!pthread_create(&t,NULL,notifier,&p));
 while(!atomic_load(&paused))sched_yield();
 bool old_predicate=atomic_load(&p.num_inflight)==0;
 pthread_mutex_lock(&done.lock);bool completed=done.done;pthread_mutex_unlock(&done.lock);
 assert(old_predicate&&!completed);
 atomic_store(&proceed,true);assert(!pthread_join(t,NULL));
 assert(done.done==NEW);
 printf("{\"last_decrement_precedes_notification\":true,\"completion_requires_notification\":%s}\n",NEW?"true":"false");
 return 0;
}
'''
results={}
with tempfile.TemporaryDirectory(prefix='sdk-zram-check-') as tmp:
 tmp=Path(tmp)
 for version in ('current','old'):
  texts={p:((root/p).read_text() if version=='current' else subprocess.check_output(['git','show',baseline+':'+p],cwd=root,text=True)) for p in ['drivers/block/zram/zram_drv.c','drivers/block/zram/zram_ioctl.c']}
  drv=texts['drivers/block/zram/zram_drv.c'];ioctl=texts['drivers/block/zram/zram_ioctl.c']
  extracted=''.join(function(drv,n) for n in ['read_from_bdev_async','read_from_bdev','zram_prefetch_cache_pop','zram_prefetch_cache_drop','slot_free','write_same_filled_page'])+function(ioctl,'zram_ioctl_process_writeback')
  for suite,code in [('errors_and_slots',shim+extracted+test),('completion',completion_shim+function(drv,'zram_prefetch_put' if version=='current' else 'zram_prefetch_dec_and_wake')+completion_test.replace('PUT','zram_prefetch_put' if version=='current' else 'zram_prefetch_dec_and_wake').replace('NEW','1' if version=='current' else '0'))]:
   src,exe=tmp/'test.c',tmp/'test';src.write_text(code)
   subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-misleading-indentation','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread',str(src),'-o',str(exe)],check=True)
   r=json.loads(subprocess.check_output([str(exe)],text=True,timeout=10))
   if suite=='errors_and_slots':assert r['failures']==(0 if version=='current' else 14),(version,r)
   r['extracted_source_sha256']=hashlib.sha256(code.encode()).hexdigest();results[version+'_'+suite]=r
report={'baseline':baseline,'results':results,'scope':'Actual extracted read-dispatch, slot cleanup/overwrite, writeback ioctl and last-notifier functions with host allocation/bio/xarray/locking shims. Deterministic pause after last counter decrement reproduces old premature-return interval. No real block I/O, kernel RCU, page-table walks or emulator execution.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
