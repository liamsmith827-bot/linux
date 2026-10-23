#!/usr/bin/env python3
"""Host extraction check: establish waiter membership before donor task access.

Simulated lists and lock operations expose attempts to access a task whose
lifetime has ended. This tests the local defense, not whether a kernel scheduler
interleaving produces such a pointer or the correctness of the entire chain.
"""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_wakeup_reason_names import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'

PREAMBLE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
struct task_struct { int blocked_lock; void *blocked_on; struct task_struct *blocked_donor; };
struct list_head { struct list_head *next, *prev; };
struct mutex_waiter { struct list_head list; struct task_struct *task; };
struct rwsem_waiter { struct list_head list; struct task_struct *task; bool donor_wakeup; };
struct mutex { struct list_head wait_list; };
struct rw_semaphore { struct list_head wait_list; };
static struct task_struct owner, candidate, a, b, dead, *current=&owner;
static int accesses_after_lifetime, wakes, cases, failures;
static bool enabled;
#define SINGLE_DEPTH_NESTING 1
#define PROXY_WAKING ((void *)(-1L))
#define sched_proxy_exec() enabled
#define WARN_ON_ONCE(x) ((void)(x))
#define CHECK(x) do { if(!(x)) failures++; } while(0)
static void raw_spin_lock(int *l) { if(l==&dead.blocked_lock) accesses_after_lifetime++; }
#define raw_spin_lock_nested(l,s) ((void)(s),raw_spin_lock(l))
#define raw_spin_unlock(l) ((void)(l))
static void *__get_task_blocked_on(struct task_struct *p) {
 if(p==&dead) { accesses_after_lifetime++; return NULL; }
 return p->blocked_on==PROXY_WAKING ? NULL : p->blocked_on;
}
static void __set_task_blocked_on_waking(struct task_struct *p,void *m) {
 (void)m; if(p==&dead) accesses_after_lifetime++; else p->blocked_on=PROXY_WAKING;
}
#define wake_q_add(q,t) ((void)(q),(void)(t),wakes++)
#define entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) \
 for(struct list_head *n=(h)->next;n!=(h) && ((p)=entry(n,__typeof__(*(p)),m),1);n=n->next)
static void init(struct list_head *h) { h->next=h->prev=h; }
static void add(struct list_head *p,struct list_head *h) {
 p->next=h; p->prev=h->prev; h->prev->next=p; h->prev=p;
}
'''

MAIN = r'''
int main(void) {
 struct mutex m; struct rw_semaphore s; int other;
 for(int pe=0;pe<2;pe++) for(int kind=0;kind<2;kind++)
 for(int status=0;status<4;status++) for(int pos=0;pos<4;pos++)
 for(int relation=0;relation<4;relation++) {
  /* status: NULL, live unrelated task, live queued task, expired task. */
  struct mutex_waiter mw[3]; struct rwsem_waiter rw[3];
  init(&m.wait_list); init(&s.wait_list);
  void *lock=kind ? (void *)&s : (void *)&m;
  void *relations[]={NULL,lock,&other,PROXY_WAKING};
  candidate=(struct task_struct){.blocked_on=relations[relation]};
  dead=(struct task_struct){.blocked_on=relations[relation]};
  for(int i=0;i<3;i++) {
   struct task_struct *task=(status==2 && pos==i+1)?&candidate:(i==1?&b:&a);
   mw[i]=(struct mutex_waiter){.task=task}; rw[i]=(struct rwsem_waiter){.task=task};
   add(&mw[i].list,&m.wait_list); add(&rw[i].list,&s.wait_list);
  }
  owner=(struct task_struct){.blocked_donor=status==0?NULL:status==3?&dead:&candidate};
  enabled=pe; accesses_after_lifetime=wakes=0;
  bool expect=pe && status==2 && pos && relation==1;
  if(kind) {
   struct rwsem_waiter *selected=select_rwsem(&s);
   CHECK((selected!=NULL)==expect);
   if(selected) CHECK(selected->task==&candidate && selected->donor_wakeup);
   CHECK(wakes==0);
  } else {
   struct task_struct *selected=select_mutex(&m);
   CHECK((selected!=NULL)==expect);
   if(selected) CHECK(selected==&candidate && !owner.blocked_donor);
   CHECK(wakes==expect);
  }
  CHECK(!accesses_after_lifetime); cases++;
 }
 printf("cases=%d failures=%d\n",cases,failures);
 return failures?1:0;
}
'''


def selection(source, name):
    if name == '__mutex_unlock_slowpath':
        source = source[source.rindex('static noinline void __sched __mutex_unlock_slowpath'):]
    body = function(source, name)
    start = body.index('\tif (sched_proxy_exec()) {')
    end = body.index('\n\t}\n', start) + len('\n\t}\n')
    return body[start:end]


def main():
    paths = ['kernel/locking/mutex.c', 'kernel/locking/rwsem.c']
    port = [(ROOT / p).read_text() for p in paths]
    ack = [subprocess.check_output(['git','show',ACK+':'+p],cwd=ROOT,text=True) for p in paths]
    results = {}
    with tempfile.TemporaryDirectory(prefix='proxy-donor-waiter-') as tmp:
        for label, sources in [('port',port),('ack_control',ack)]:
            mutex,rwsem=sources
            code=PREAMBLE+'\nstatic struct task_struct *select_mutex(struct mutex *lock) {\nstruct task_struct *donor=NULL,*next=NULL; int wake_q=0;\n'
            code+=selection(mutex,'__mutex_unlock_slowpath')+'\nreturn next;\n}\n'
            code+='\nstatic struct rwsem_waiter *select_rwsem(struct rw_semaphore *sem) {\nstruct rwsem_waiter *w=NULL,*waiter=NULL; struct task_struct *_donor=NULL,*donor=NULL;\n'
            code+=selection(rwsem,'rwsem_mark_wake')+'\n(void)_donor; (void)donor; return waiter;\n}\n'+MAIN
            c=Path(tmp)/(label+'.c');exe=Path(tmp)/label;c.write_text(code)
            subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(c),'-o',str(exe)],check=True)
            run=subprocess.run([str(exe)],capture_output=True,text=True)
            match=re.fullmatch(r'cases=(\d+) failures=(\d+)\n',run.stdout)
            assert match,(run.returncode,run.stdout,run.stderr)
            results[label]=dict(cases=int(match[1]),failed_assertions=int(match[2]),exit_code=run.returncode,
                                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert results['port']['failed_assertions']==0
    assert results['ack_control']['failed_assertions']>0
    report=dict(source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in zip(paths,port)},
                results=results,scope=__doc__,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/proxy-donor-waiter-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__=='__main__':
    main()
