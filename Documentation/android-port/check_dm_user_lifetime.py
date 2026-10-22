#!/usr/bin/env python3
"""Exercise extracted dm-user message/timeout ownership with deterministic callback interleavings."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
s=(D.parents[1]/'drivers/md/dm-user.c').read_text()
def function(n):
 m=re.search(r'^.*\b'+n+r'\([^;{}]*\)\n\{',s,re.M);assert m,n
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
body='\n'.join(function(n) for n in ['message_kill','is_user_space_thread_present','process_delayed_work','enqueue_delayed_work','msg_get_map','msg_get_to_user','target_release','target_put'])
prefix=r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
static unsigned checks,cases,failures;
#define CHECK(x) (++checks,(x)?0:(failures++,0))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define unlikely(x) (x)
#define pr_err(...) ((void)0)
#define GFP_NOWAIT 1
#define GFP_NOIO 2
#define BLK_STS_IOERR 10
struct list_head {struct list_head *next,*prev;};
#define INIT_LIST_HEAD(p) ((p)->next=(p)->prev=(p))
static bool list_empty(struct list_head *p){return p->next==p;}
static void list_add_tail(struct list_head *p,struct list_head *h){p->next=h;p->prev=h->prev;h->prev->next=p;h->prev=p;}
static void list_del_init(struct list_head *p){p->next->prev=p->prev;p->prev->next=p->next;INIT_LIST_HEAD(p);}
#define list_entry(p,t,m) container_of(p,t,m)
#define list_first_entry(h,t,m) list_entry((h)->next,t,m)
#define list_for_each_safe(p,n,h) for((p)=(h)->next,(n)=(p)->next;(p)!=(h);(p)=(n),(n)=(p)->next)
struct mutex {int held;};
static void mutex_lock(struct mutex *m){CHECK(!m->held);m->held=1;}
static void mutex_unlock(struct mutex *m){CHECK(m->held);m->held=0;}
static void mutex_destroy(struct mutex *m){CHECK(!m->held);}
#define lockdep_assert_held(m) CHECK((m)->held)
struct kref {int count;};
static int kref_read(struct kref *r){return r->count;}
static int kref_put(struct kref *r,void (*release)(struct kref *)){CHECK(r->count>0);if(!--r->count){release(r);return 1;}return 0;}
struct work_struct {void (*fn)(struct work_struct *);};
struct delayed_work {struct work_struct work;int initialized,pending;unsigned long delay;};
#define delayed_work_pending(w) ((w)->pending)
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
#define INIT_DELAYED_WORK(w,f) ((w)->initialized=1,(w)->work.fn=(f))
static int system_wq;
static unsigned daemon_timeout_msec=4000;
#define msecs_to_jiffies(v) (v)
static bool mod_delayed_work(int q,struct delayed_work *w,unsigned long d){CHECK(w->initialized);bool old=w->pending;w->pending=1;w->delay=d;return old;}
struct bio {int bi_status,ended;struct {unsigned long long bi_sector;} bi_iter;};
static void bio_endio(struct bio *b){CHECK(!b->ended);b->ended++;}
struct target;
struct message {struct {uint64_t seq;} msg;struct bio *bio;struct list_head to_user,from_user;struct delayed_work work;struct target *t;int live;};
typedef struct {int initialized,exited;} mempool_t;
struct target {struct mutex lock;struct kref references;int dm_destroyed;bool daemon_terminated;struct list_head to_user;mempool_t message_pool;uint64_t next_seq_to_map;struct {void *name;} miscdev;};
static struct message slots[32];static struct bio bios[32];static int allocated,pool_fail,freed_messages,freed_names,freed_targets,interleave;
static void *mempool_alloc(mempool_t *p,int flags){CHECK(p->initialized && !p->exited);CHECK(flags==GFP_NOWAIT);if(pool_fail)return NULL;CHECK(allocated<32);struct message *m=&slots[allocated];*m=(struct message){.live=1,.bio=&bios[allocated]};allocated++;return m;}
static void mempool_free(struct message *m,mempool_t *p){CHECK(m->live && !p->exited);m->live=0;freed_messages++;}
static void mempool_exit(mempool_t *p){CHECK(!p->exited);p->exited=1;for(int i=0;i<allocated;i++)CHECK(!slots[i].live);}
static void kfree(void *p){if(p==(void *)1)freed_names++;else freed_targets++;}
static void run_work(struct message *m){CHECK(m->live && m->work.initialized);m->work.pending=0;m->work.work.fn(&m->work.work);}
static bool cancel_delayed_work_sync(struct delayed_work *w){
 struct message *m=container_of(w,struct message,work);CHECK(m->live && !m->t->lock.held);bool pending=w->pending;
 /* A callback already dispatched before cancellation can run while its caller waits. */
 if(interleave&1)run_work(m);
 if(interleave&2)for(int i=0;i<allocated;i++)if(&slots[i]!=m && slots[i].live && slots[i].work.pending)run_work(&slots[i]);
 w->pending=0;return pending && !(interleave&1);
}
'''
main=r'''
static struct target make_target(int channels,int destroyed){
 memset(slots,0,sizeof(slots));memset(bios,0,sizeof(bios));allocated=freed_messages=freed_names=freed_targets=pool_fail=0;
 return (struct target){.references={channels+!destroyed},.dm_destroyed=destroyed,.message_pool={.initialized=1},.miscdev={.name=(void *)1}};
}
static struct message *make_message(struct target *t,int delay){struct message *m=msg_get_map(t);CHECK(m);m->t=t;list_add_tail(&m->to_user,&t->to_user);if(delay)enqueue_delayed_work(m,true);return m;}
int main(void){
 /* Check channel existence before and after the DM-owned reference disappears. */
 for(int d=0;d<2;d++)for(int ch=0;ch<4;ch++){struct target t=make_target(ch,d);mutex_lock(&t.lock);CHECK(is_user_space_thread_present(&t)==!!ch);mutex_unlock(&t.lock);cases++;}
 /* Exhausted reserves must return to the map requeue path, never wait under target lock. */
 {struct target t=make_target(0,0);mutex_lock(&t.lock);pool_fail=1;CHECK(msg_get_map(&t)==NULL && !allocated && !t.next_seq_to_map);mutex_unlock(&t.lock);cases++;}
 /* Release may race with callbacks for the selected and every following message. */
 for(int n=0;n<8;n++)for(int mode=0;mode<4;mode++)for(int delayed=0;delayed<2;delayed++){
  struct target t=make_target(0,1);INIT_LIST_HEAD(&t.to_user);interleave=mode;mutex_lock(&t.lock);
  for(int i=0;i<n;i++)make_message(&t,delayed);
  target_release(&t.references);
  CHECK(freed_messages==n && freed_names==1 && freed_targets==1 && !t.lock.held && list_empty(&t.to_user));
  for(int i=0;i<n;i++)CHECK(bios[i].ended==1 && bios[i].bi_status==BLK_STS_IOERR);cases++;
 }
 /* A timed-out request taken by a channel cannot also be freed by its callback. */
 for(int d=0;d<2;d++)for(int ch=1;ch<4;ch++)for(int mode=0;mode<4;mode++){
  struct target t=make_target(ch,d);INIT_LIST_HEAD(&t.to_user);interleave=mode;mutex_lock(&t.lock);
  struct message *first=make_message(&t,1);make_message(&t,1);struct message *got=msg_get_to_user(&t);
  CHECK(got==first && first->live && !first->work.pending && !first->bio->ended && list_empty(&first->to_user));
  message_kill(first,&t.message_pool);t.references.count=0;target_release(&t.references);CHECK(freed_messages==2);cases++;
 }
 /* A timer that observed a daemon must rearm on last-close, including a previously pending timer. */
 for(int completed=0;completed<2;completed++)for(int pending=0;pending<2;pending++){
  struct target t=make_target(1,0);INIT_LIST_HEAD(&t.to_user);interleave=0;mutex_lock(&t.lock);
  struct message *m=make_message(&t,1);
  if(completed){mutex_unlock(&t.lock);run_work(m);mutex_lock(&t.lock);CHECK(m->live && !m->bio->ended);}
  if(pending)enqueue_delayed_work(m,true);
  target_put(&t);CHECK(m->work.pending && !m->work.delay && t.daemon_terminated && !t.lock.held);
  run_work(m);CHECK(!m->live && m->bio->ended==1 && list_empty(&t.to_user));
  mutex_lock(&t.lock);t.dm_destroyed=1;target_put(&t);CHECK(freed_names==1 && freed_targets==1);cases++;
 }
 /* Last-close rearms a callback already dispatched but waiting for the target lock. */
 {struct target t=make_target(1,0);INIT_LIST_HEAD(&t.to_user);interleave=0;mutex_lock(&t.lock);
  struct message *m=make_message(&t,1);m->work.pending=0;
  target_put(&t);CHECK(m->work.pending && !m->work.delay);
  process_delayed_work(&m->work.work);CHECK(m->live && !m->bio->ended && m->work.pending);
  run_work(m);CHECK(!m->live && m->bio->ended==1 && list_empty(&t.to_user));
  mutex_lock(&t.lock);t.dm_destroyed=1;target_put(&t);cases++;
 }
 printf("%u %u %u\n",cases,checks,failures);return !!failures;
}
'''
controls={
 'free_rearmed_running_work':body.replace('delayed_work_pending(&msg->work) ||\n\t    ',''),
 'release_without_claim':body.replace('list_del_init(&m->to_user);\n\t\tmutex_unlock','/* no claim */\n\t\tmutex_unlock'),
 'callback_ignores_claim':body.replace('list_empty(&msg->to_user) || ',''),
 'missing_name_release':body.replace('kfree(t->miscdev.name);',''),
 'blocking_pool_allocation':body.replace('GFP_NOWAIT','GFP_NOIO'),
 'channel_count_assumes_dm_reference':body.replace('> !t->dm_destroyed','> 1'),
 'do_not_rearm_finished_work':body.replace('enqueue_delayed_work(m, false);','if (m->work.pending)\n\t\t\t\t\tenqueue_delayed_work(m, false);'),
}
with tempfile.TemporaryDirectory(prefix='dm-user-check-') as tmp:
 t=Path(tmp)
 def run(name,b,expected):
  p=t/(name+'.c');exe=t/name;p.write_text(prefix+b+main)
  r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=5)
  assert (r.returncode==0)==expected,(name,r.stdout,r.stderr)
  return r.stdout
 output=run('current',body,True)
 for n,b in controls.items():
  assert b!=body,n
  try:run(n,b,False)
  except subprocess.TimeoutExpired:
   assert n=='release_without_claim'
counts=list(map(int,output.split()))
report={'cases':counts[0],'assertions':counts[1],'failures':counts[2],'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'negative_controls_rejected':list(controls),'scope':__doc__+' Lists, locks, work cancellation and mempool ownership are modeled. No real kernel scheduling, live snapshot I/O or userspace-protocol execution.'}
(D/'evidence/dm-user-lifetime-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
