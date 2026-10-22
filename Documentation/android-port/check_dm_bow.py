#!/usr/bin/env python3
"""Execute extracted dm-bow constructor, teardown and map paths with fault-injection shims."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
s=(D.parents[1]/'drivers/md/dm-bow.c').read_text()
def function(name):
 m=re.search(r'^.*\b'+name+r'\([^;{}]*\)\n\{',s,re.M);assert m,name
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
body='\n'.join(function(n) for n in ['dm_bow_dtr','dm_bow_ctr','bow_write','queue_write','remap_unless_illegal_trim','dm_bow_map'])
prefix=r'''
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
static unsigned cases,checks,failures;
#define CHECK(x) (++checks, (x)?0:(++failures,0))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define DMERR(...) ((void)0)
#define likely(x) (x)
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define BLK_STS_OK 0
#define BLK_STS_IOERR 10
#define BLK_STS_NOSPC 11
#define SECTOR_SHIFT 9
#define SECTOR_SIZE 512
#define DM_MAPIO_KILL 4
#define GFP_KERNEL 0
#define GFP_NOIO 0
#define GFP_NOWAIT 1
#define __GFP_NORETRY 0
#define __GFP_NOMEMALLOC 0
#define __GFP_NOWARN 0
#define WQ_CPU_INTENSIVE 0
#define WQ_MEM_RECLAIM 0
#define WQ_UNBOUND 0
#define READ 0
#define WRITE 1
#define BLK_STS_RESOURCE 9
#define BLK_STS_NOTSUPP 1
#define DM_MAPIO_SUBMITTED 0
#define DM_MAPIO_REMAPPED 1
struct mutex {int initialized,held;};
static void mutex_init(struct mutex *m){m->initialized=1;}
static void mutex_lock(struct mutex *m){CHECK(m->initialized && !m->held);m->held=1;}
static void mutex_unlock(struct mutex *m){CHECK(m->initialized && m->held);m->held=0;}
static void mutex_destroy(struct mutex *m){CHECK(m->initialized && !m->held);m->initialized=0;}
struct rb_node {struct rb_node *left,*rb_left,*parent;};
struct rb_root {struct rb_node *rb_node;};
#define RB_ROOT ((struct rb_root){0})
static struct rb_node *rb_first(struct rb_root *r){struct rb_node *n=r->rb_node;if(n && n->rb_left)n=n->rb_left;return n;}
static void rb_link_node(struct rb_node *n,struct rb_node *p,struct rb_node **l){n->parent=p;*l=n;}
static void rb_insert_color(struct rb_node *n,struct rb_root *r){}
static void rb_erase(struct rb_node *n,struct rb_root *r){if(n->parent)n->parent->rb_left=NULL;else r->rb_node=NULL;}
struct list_head {int initialized;};
#define INIT_LIST_HEAD(p) ((p)->initialized=1)
struct completion {int initialized,done;};
static void init_completion(struct completion *c){c->initialized=1;}
struct kobject {int state_initialized;struct completion *c;};
struct dm_kobject_holder {struct kobject kobj;struct completion completion;};
static int order,sysfs_removed,wq_destroyed,bufio_destroyed;
static void kobject_put(struct kobject *k){CHECK(!order);sysfs_removed=++order;k->c->done=1;}
static struct completion *dm_get_completion_from_kobject(struct kobject *k){return k->c;}
static void wait_for_completion(struct completion *c){CHECK(c->initialized && c->done);}
struct block_device {int x;};
struct dm_dev {struct block_device *bdev;};
static struct block_device bdev;
static struct dm_dev device={.bdev=&bdev};
struct queue {struct {unsigned logical_block_size;} limits;};
static struct queue queue={.limits={512}};
static struct queue *bdev_get_queue(struct block_device *b){return &queue;}
struct bow_range {struct rb_node node;uint64_t sector;int type;};
enum {UNCHANGED,TOP};
enum state {TRIM,CHECKPOINT,COMMITTED};
struct log_sector {uint64_t sector0;};
struct bow_context {struct dm_dev *dev;unsigned block_size,block_shift;struct log_sector *log_sector;void *workqueue,*bufio;struct mutex state_lock,ranges_lock;struct rb_root ranges;struct dm_kobject_holder kobj_holder;struct list_head trimmed_list;int state;bool forward_trims,failed;};
struct dm_target {const char *error;void *private,*table;unsigned num_flush_bios,num_discard_bios;uint64_t len;bool discards_supported;};
static int allocations,fail_at,live,dev_refs,device_fail,options_fail;
static void *kzalloc(size_t n,int g){if(++allocations==fail_at)return NULL;void *p=calloc(1,n);CHECK(p);live++;return p;}
#define kmalloc kzalloc
static void kfree(void *p){if(p){live--;free(p);}}
static int dm_table_get_mode(void *t){return 0;}
static int dm_get_device(struct dm_target *t,const char *p,int m,struct dm_dev **d){if(device_fail)return -ENODEV;*d=&device;dev_refs++;return 0;}
static void dm_put_device(struct dm_target *t,struct dm_dev *d){CHECK(d==&device && dev_refs==1);CHECK(!live || (!((struct bow_context *)t->private)->workqueue || wq_destroyed));dev_refs--;}
static int dm_bow_ctr_optional(struct dm_target *t,unsigned c,char **v){return options_fail?-EINVAL:0;}
static int ilog2(unsigned v){return 31-__builtin_clz(v);}
static void *dm_bufio_client_create(struct block_device *b,unsigned z,int a,int c,void *d,void *e,int f){void *p=kzalloc(1,0);return p?p:ERR_PTR(-ENOMEM);}
static void dm_bufio_client_destroy(void *b){CHECK(!sysfs_removed || wq_destroyed);bufio_destroyed=++order;kfree(b);}
static void *alloc_ordered_workqueue(const char *n,int f){return kzalloc(1,0);}
static int num_online_cpus(void){return 2;}
static void destroy_workqueue(void *w){CHECK(!bufio_destroyed);wq_destroyed=++order;kfree(w);}
struct work_struct {void (*fn)(struct work_struct *);};
struct bvec_iter {unsigned bi_size;uint64_t bi_sector;};
struct bio {struct bvec_iter bi_iter;int op,bi_status,ended;struct block_device *dev;};
struct write_work {struct work_struct work;struct bow_context *bc;struct bio *bio;};
enum {REQ_OP_READ,REQ_OP_WRITE,REQ_OP_DISCARD};
#define bio_op(b) ((b)->op)
#define bio_data_dir(b) ((b)->op==REQ_OP_READ?READ:WRITE)
#define atomic_read(p) (*(p))
#define INIT_WORK(p,f) ((p)->fn=(f))
static int queued,trims,untrims,prepared,submitted,io_fail,prepare_fail;
static uint64_t sectors[16];
static unsigned sizes[16];
static void bio_endio(struct bio *b){b->ended++;CHECK(b->ended==1);}
static void bio_set_dev(struct bio *b,struct block_device *d){b->dev=d;}
static void queue_work(void *q,struct work_struct *w){queued++;w->fn(w);}
static int add_trim(struct bow_context *c,struct bio *b){trims++;return prepare_fail?BLK_STS_RESOURCE:BLK_STS_OK;}
static int remove_trim(struct bow_context *c,struct bio *b){untrims++;return prepare_fail?BLK_STS_RESOURCE:BLK_STS_OK;}
static unsigned fs_bio_set;
static uint64_t dm_target_offset(struct dm_target *t,uint64_t sector){return sector;}
static int errno_to_blk_status(int e){return e==-ENOMEM?BLK_STS_RESOURCE:e?BLK_STS_IOERR:0;}
static struct bio *bio_alloc_clone(struct block_device *d,struct bio *src,int g,unsigned *bs){struct bio *b=kzalloc(sizeof(*b),0);if(b){*b=*src;b->dev=d;b->ended=0;}return b;}
static void bio_put(struct bio *b){kfree(b);}
static struct bio *bio_split(struct bio *b,int sectors,int g,unsigned *bs){CHECK(g==GFP_NOWAIT);struct bio *first=bio_alloc_clone(b->dev,b,g,bs);if(first){first->bi_iter.bi_size=sectors*512;b->bi_iter.bi_size-=sectors*512;b->bi_iter.bi_sector+=sectors;}return first?first:ERR_PTR(-ENOMEM);}
static int submit_bio_wait(struct bio *b){CHECK(b->dev==&bdev);CHECK(submitted<16);sectors[submitted]=b->bi_iter.bi_sector;sizes[submitted]=b->bi_iter.bi_size;submitted++;return submitted==io_fail?-EIO:0;}
static int prepare_one_range(struct bow_context *c,struct bvec_iter *it){CHECK(c->ranges_lock.held);prepared++;if(it->bi_size>512)it->bi_size=512;c->log_sector->sector0=72;return prepare_fail?BLK_STS_NOSPC:BLK_STS_OK;}
'''
main=r'''
static void reset(void){allocations=live=dev_refs=order=sysfs_removed=wq_destroyed=bufio_destroyed=0;}
int main(void){
 for(int fault=0;fault<=6;fault++)for(int df=0;df<2;df++)for(int of=0;of<2;of++)for(int published=0;published<2;published++){
  reset();fail_at=fault;device_fail=df;options_fail=of;
  struct dm_target t={.len=800};char *args[]={"dev","0"};
  int ret=dm_bow_ctr(&t,2,args);
  CHECK((ret==0)==(!fault && !df && !of));
  if(!ret){struct bow_context *c=t.private;CHECK(dev_refs==1 && live==6 && c->block_size==512 && c->block_shift==9);if(published){c->kobj_holder.kobj.state_initialized=1;c->kobj_holder.kobj.c=&c->kobj_holder.completion;}dm_bow_dtr(&t);if(published)CHECK(sysfs_removed<wq_destroyed && wq_destroyed<bufio_destroyed);}
  CHECK(!live && !dev_refs);cases++;
 }
 for(int state=TRIM;state<=COMMITTED;state++)for(int op=0;op<=REQ_OP_DISCARD;op++)for(int sec=0;sec<2;sec++)for(int size=0;size<4;size++)for(int forward=0;forward<2;forward++)for(int oom=0;oom<4;oom++)for(int broken=0;broken<2;broken++){
  reset();fail_at=oom;queued=trims=untrims=prepared=submitted=io_fail=prepare_fail=0;
  struct log_sector log={.sector0=64};
  struct bow_context c={.dev=&device,.state=state,.forward_trims=forward,.failed=broken,.block_size=512,.log_sector=&log};mutex_init(&c.state_lock);mutex_init(&c.ranges_lock);
  struct dm_target t={.private=&c};struct bio b={.bi_iter={.bi_size=size*512,.bi_sector=sec*8},.op=op};
  int ret=dm_bow_map(&t,&b);
  bool fast=state==COMMITTED || (op==REQ_OP_READ && sec && size);
  bool split=state==CHECKPOINT && !sec && size>1 && op!=REQ_OP_DISCARD;
  bool failure=oom && (!fast && (oom<=2 || split));
  if(broken)CHECK(ret==DM_MAPIO_KILL && !queued && !submitted && !b.ended);
  else if(fast){
   if(op==REQ_OP_DISCARD && !forward)CHECK(ret==DM_MAPIO_SUBMITTED && b.ended && b.bi_status==BLK_STS_NOTSUPP);
   else CHECK(ret==DM_MAPIO_REMAPPED && b.dev==&bdev && !b.ended);
  }else{
   CHECK(ret==DM_MAPIO_SUBMITTED && b.ended==1 && !b.dev && b.bi_iter.bi_sector==(uint64_t)sec*8 && b.bi_iter.bi_size==(unsigned)size*512);
   CHECK(b.bi_status==(failure?BLK_STS_RESOURCE:BLK_STS_OK));
   if(failure)CHECK(!submitted);
   else if(size && op==REQ_OP_DISCARD)CHECK(!submitted);
   else {CHECK(submitted==(split?2:1));if(state==CHECKPOINT && !sec && size)CHECK(sectors[0]==(unsigned)(split && op==REQ_OP_WRITE?72:64));}
  }
  CHECK(!c.state_lock.held && !c.ranges_lock.held && !live);cases++;
 }
 /* I/O failures block further checkpoint use; ordinary backup-space exhaustion can commit. */
 for(int error=0;error<3;error++)for(int op=0;op<2;op++){
  reset();fail_at=0;queued=trims=untrims=prepared=submitted=0;prepare_fail=error==2;io_fail=error==1?1:0;
  struct log_sector log={.sector0=64};struct bow_context c={.dev=&device,.state=CHECKPOINT,.block_size=512,.log_sector=&log};mutex_init(&c.state_lock);mutex_init(&c.ranges_lock);
  struct bio b={.bi_iter={.bi_size=1024,.bi_sector=0},.op=op};struct dm_target t={.private=&c};
  CHECK(dm_bow_map(&t,&b)==DM_MAPIO_SUBMITTED && b.ended==1);
  int want=error==1?BLK_STS_IOERR:error==2 && op==REQ_OP_WRITE?BLK_STS_NOSPC:0;
  CHECK(b.bi_status==want && c.failed==(error==1) && !live);cases++;
 }
 printf("%u %u %u\n",cases,checks,failures);return !!failures;
}
'''
controls={
 'uninitialized_constructor_cleanup':body.replace('mutex_init(&bc->ranges_lock);',''),
 'log_allocation_false_success':body.replace('ti->error = "Cannot allocate log sector";\n\t\tret = -ENOMEM;','ti->error = "Cannot allocate log sector";'),
 'leaked_device_reference':body.replace('dm_put_device(ti, bc->dev);','(void)bc->dev;'),
 'queue_oom_invalid_map_return':body.replace('bio->bi_status = BLK_STS_RESOURCE;\n\t\tbio_endio(bio);\n\t\treturn DM_MAPIO_SUBMITTED;','return -ENOMEM;'),
 'split_error_pointer':body.replace('if (IS_ERR(first))','if (!first)'),
 'sector_zero_discard':body.replace('if (bio_op(clone) == REQ_OP_DISCARD)\n\t\tgoto out;', 'if (bio_op(clone) == REQ_OP_DISCARD && clone->bi_iter.bi_sector)\n\t\tgoto out;'),
 'wrong_live_sector_after_tail':body.replace('first->bi_iter.bi_sector = bc->log_sector->sector0;', 'first->bi_iter.bi_sector = 64;'),
 'ignore_lower_io_error':body.replace('ret = errno_to_blk_status(submit_bio_wait(first));', 'submit_bio_wait(first); ret = 0;'),
}
with tempfile.TemporaryDirectory(prefix='dm-bow-check-') as tmp:
 t=Path(tmp)
 def run(name,b,expected):
  p=t/(name+'.c');exe=t/name;p.write_text(prefix+b+main)
  r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],capture_output=True,text=True)
  assert r.returncode==0,r.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True)
  assert (r.returncode==0)==expected,(name,r.stdout,r.stderr)
  return r.stdout
 output=run('current',body,True)
 for n,b in controls.items():assert b!=body,n;run(n,b,False)
counts=list(map(int,output.split()))
report={'cases':counts[0],'assertions':counts[1],'failures':counts[2],'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'negative_controls_rejected':list(controls),'scope':__doc__+' Allocation, lifetime, map ownership and discard outcomes are modeled. Lower submission and completion are simulated; actual range preparation is shimmed. Does not test real block I/O, kernel locking, checkpoint durability or concurrent teardown.'}
(D/'evidence/dm-bow-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
