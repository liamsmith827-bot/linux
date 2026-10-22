#!/usr/bin/env python3
"""Exercise extracted inode-record publication and bitmap control flow."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
def function(src,name):
    m=re.search(r'^.*\b'+name+r'\([^;{]*\)\n\{',src,re.M)
    assert m,name
    i,depth=m.end(),1
    while depth:
        depth+=(src[i]=='{')-(src[i]=='}');i+=1
    return src[m.start():i]+'\n'
sources={p:(ROOT/p).read_text() for p in ['fs/f2fs/checkpoint.c','fs/f2fs/inode.c']}
body='\n'.join(function(sources['fs/f2fs/checkpoint.c'],n) for n in [
    '__set_ino_bitmap','__clear_ino_bitmap','f2fs_wait_for_inode_record',
    '__f2fs_add_ino_entry','f2fs_add_ino_entry','f2fs_remove_ino_entry',
    'f2fs_exist_written_data','f2fs_release_ino_entry'])
body+='\n'+ '\n'.join(function(sources['fs/f2fs/inode.c'],n) for n in [
    'f2fs_record_inode_state','f2fs_evict_inode_work'])
evict=function(sources['fs/f2fs/inode.c'],'f2fs_post_evict_inode')
a=evict.index('\tif (!inode->i_nlink)');b=evict.index('skip_record:',a)
body+='\nstatic void submit_record(struct inode *inode)\n{\n'+ \
      '\tstruct f2fs_sb_info *sbi=inode->sbi;\n\tunsigned int record_bits=0;\n'+ \
      evict[a:b]+'skip_record:;\n}\n'
work=re.search(r'struct evict_inode_work \{.*?\n\};',sources['fs/f2fs/inode.c'],re.S).group()
iget=function(sources['fs/f2fs/inode.c'],'f2fs_iget')
a=iget.index('\t/*\n\t * iget_locked() waits');b=iget.index('\tunlock_new_inode',a)
body+='\nstatic void publish_reloaded_inode(struct inode *inode)\n{\n'+ \
      '\tstruct f2fs_sb_info *sbi=inode->sbi;\n\tunsigned long ino=inode->i_ino;\n'+iget[a:b]+'}\n'
prefix=r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
typedef unsigned nid_t;
enum { ORPHAN_INO, FLUSH_INO, APPEND_INO, UPDATE_INO, TRANS_DIR_INO, XATTR_DIR_INO, MAX_INO_ENTRY };
enum { FI_APPEND_WRITE=7, FI_UPDATE_WRITE=9 };
#define INO_BITS_PER_SLOT (sizeof(unsigned long)*8-1)
#define INO_SLOT_INDEX(ino) ((ino)/INO_BITS_PER_SLOT)
#define INO_BIT_OFFSET(ino) ((ino)%INO_BITS_PER_SLOT)
#define BIT(i) (1UL<<(i))
#define GFP_NOFS 1
#define __GFP_NOFAIL 2
#define unlikely(x) (x)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
struct work_struct { void (*fn)(struct work_struct *); };
struct list_head { int unused; };
struct ino_entry { struct list_head list; nid_t ino; };
struct tree { struct { unsigned long index; void *entry; } slots[64]; };
struct inode_management { struct tree ino_root; unsigned long ino_num; int ino_lock; struct list_head ino_list; };
struct workqueue { struct work_struct *items[64]; int count; };
struct f2fs_sb_info { struct inode_management im[MAX_INO_ENTRY]; struct workqueue *evict_wq; };
struct inode { struct f2fs_sb_info *sbi; nid_t i_ino; int i_nlink; unsigned long flags; };
static unsigned cases,assertions,failures;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
    if(failures<8) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
static int allocations,frees,preload;
static bool kswapd;
static void *evict_inode_work_pool,*ino_entry_slab;
static void spin_lock(int *p) { CHECK(!(*p)++); }
static void spin_unlock(int *p) { CHECK(--(*p)==0); }
static void f2fs_bug_on(struct f2fs_sb_info *s,bool b) { CHECK(!b); }
static int radix_tree_preload(int flags) { CHECK(!preload++);return 0; }
static void radix_tree_preload_end(void) { CHECK(--preload==0); }
static void **radix_tree_lookup_slot(struct tree *t,unsigned long index) {
    for(int i=0;i<64;i++) if(t->slots[i].entry && t->slots[i].index==index) return &t->slots[i].entry;
    return NULL;
}
static void *radix_tree_lookup(struct tree *t,unsigned long i) { void **p=radix_tree_lookup_slot(t,i);return p?*p:NULL; }
static void *radix_tree_deref_slot_protected(void **p,int *lock) { CHECK(*lock==1);return *p; }
static void radix_tree_replace_slot(struct tree *t,void **p,void *v) { *p=v; }
static int radix_tree_insert(struct tree *t,unsigned long index,void *v) {
    CHECK(!radix_tree_lookup(t,index));
    for(int i=0;i<64;i++) if(!t->slots[i].entry) {
        t->slots[i].index=index;t->slots[i].entry=v;return 0;
    }
    abort();
}
static void radix_tree_delete(struct tree *t,unsigned long index) { void **p=radix_tree_lookup_slot(t,index);if(p)*p=NULL; }
static void *xa_mk_value(unsigned long v) { return (void *)((v<<1)|1); }
static unsigned long xa_to_value(void *v) { return (uintptr_t)v>>1; }
static void xa_destroy(struct tree *t) { memset(t,0,sizeof(*t)); }
#define list_for_each_entry_safe(e,tmp,h,m) for((e)=NULL,(tmp)=NULL;(e)!=NULL;)
static void list_del(struct list_head *h) { CHECK(false); }
static void kmem_cache_free(void *s,void *p) { CHECK(false); }
static void __add_ino_entry(struct f2fs_sb_info *s,nid_t i,unsigned d,int t) { CHECK(false); }
static void __remove_ino_entry(struct f2fs_sb_info *s,nid_t i,int t) { CHECK(false); }
static bool is_inode_flag_set(struct inode *i,int f) { return i->flags & BIT(f); }
static bool current_is_kswapd(void) { return kswapd; }
/* Every tested inode is an ordinary inode, not an internal mount inode. */
static bool is_meta_ino(struct f2fs_sb_info *s,unsigned long ino) { return false; }
#define INIT_WORK(w,f) ((w)->fn=(f))
static void queue_work(struct workqueue *q,struct work_struct *w) { CHECK(q->count<64);q->items[q->count++]=w; }
static void flush_workqueue(struct workqueue *q) {
    while(q->count) { struct work_struct *w=q->items[--q->count];w->fn(w); }
}
'''
prefix+=work+r'''
static void *mempool_alloc(void *pool,int flags) { allocations++;return calloc(1,sizeof(struct evict_inode_work)); }
static void mempool_free(void *p,void *pool) { frees++;free(p); }
'''
suffix=r'''
int main(void) {
    unsigned inos[]={0,1,62,63,64,125,126,0xfffffffeU,0xffffffffU};
    for(unsigned j=0;j<sizeof(inos)/sizeof(*inos);j++)
    for(int flags=0;flags<4;flags++) for(int links=0;links<2;links++)
    for(int mode=0;mode<2;mode++) for(int operation=0;operation<3;operation++) {
        struct workqueue q={0};struct f2fs_sb_info s={.evict_wq=&q};
        struct inode inode={.sbi=&s,.i_ino=inos[j],.i_nlink=links,
            .flags=(flags&1?BIT(FI_APPEND_WRITE):0)|(flags&2?BIT(FI_UPDATE_WRITE):0)};
        kswapd=mode;allocations=frees=0;
        /* Duplicate records must remain one set member/count. */
        submit_record(&inode);submit_record(&inode);
        bool append=links && (flags&1), update=links && (flags&2);
        if(operation==0) {
            CHECK(f2fs_exist_written_data(&s,inode.i_ino,APPEND_INO)==append);
            CHECK(f2fs_exist_written_data(&s,inode.i_ino,UPDATE_INO)==update);
            CHECK(s.im[APPEND_INO].ino_num==append && s.im[UPDATE_INO].ino_num==update);
        } else if(operation==1) {
            /* VFS waits for old eviction; f2fs_iget publishes its records. */
            publish_reloaded_inode(&inode);
            f2fs_remove_ino_entry(&s,inode.i_ino,APPEND_INO);
            flush_workqueue(&q);
            CHECK(!f2fs_exist_written_data(&s,inode.i_ino,APPEND_INO));
            CHECK(f2fs_exist_written_data(&s,inode.i_ino,UPDATE_INO)==update);
            CHECK(!s.im[APPEND_INO].ino_num);
        } else {
            f2fs_release_ino_entry(&s,false);flush_workqueue(&q);
            CHECK(!f2fs_exist_written_data(&s,inode.i_ino,APPEND_INO));
            CHECK(!f2fs_exist_written_data(&s,inode.i_ino,UPDATE_INO));
        }
        f2fs_release_ino_entry(&s,true);flush_workqueue(&q);
        for(int i=APPEND_INO;i<MAX_INO_ENTRY;i++) CHECK(!s.im[i].ino_num);
        CHECK(!preload && allocations==frees && !q.count);cases++;
    }
    /* Neighbouring bits must survive clearing a different inode in a slot. */
    for(int type=APPEND_INO;type<MAX_INO_ENTRY;type++) {
        struct workqueue q={0};struct f2fs_sb_info s={.evict_wq=&q};
        for(unsigned i=0;i<127;i++) f2fs_add_ino_entry(&s,i,type);
        CHECK(s.im[type].ino_num==127);
        for(unsigned i=0;i<127;i+=2) f2fs_remove_ino_entry(&s,i,type);
        CHECK(s.im[type].ino_num==63);
        for(unsigned i=0;i<127;i++) CHECK(f2fs_exist_written_data(&s,i,type)==!!(i&1));
        f2fs_release_ino_entry(&s,true);CHECK(!s.im[type].ino_num);cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-inode-records-') as tmp:
    variants={'port':body,
              'ack_lost_append_control':body.replace('record_bits |= BIT(', 'record_bits = BIT('),
              'missing_publication_barrier_control':body.replace('flush_workqueue(sbi->evict_wq);',';'),
              'ack_uncounted_bitmap_control':body.replace('im->ino_num++;',';')}
    results={}
    for name,code in variants.items():
        c,exe=Path(tmp)/(name+'.c'),Path(tmp)/name;c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter',
                        '-Wno-unused-but-set-variable','-fsanitize=undefined','-fno-sanitize-recover=all',
                        str(c),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (r.returncode==0)==(name=='port'),(name,r.stdout,r.stderr)
        results[name]={'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
report={'scope':__doc__+' Captures actual post-eviction record block and new-inode publication barrier; deletion follows modeled VFS eviction/reload ordering. Fake radix tree/workqueue and empty orphan/flush lists. No real kernel allocation, RCU, locking, concurrency, fsync or storage.',
        'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'results':results}
(D/'evidence/f2fs-inode-records-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip());print('All three negative controls rejected')
