#!/usr/bin/env python3
"""Differential host check of actual rwsem writer handoff and waiter initialization.

Atomic/list primitives are single-threaded stubs. No kernel locking, proxy
execution, contention, scheduling or IRQ operation is executed.
"""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_wakeup_reason_names import function

ROOT = Path(__file__).resolve().parents[2]
PATH = 'kernel/locking/rwsem.c'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'

PREAMBLE = r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
struct task_struct { bool rt; } task;
static struct task_struct *current = &task;
struct list_head { bool singular; };
struct rwsem_waiter {
 struct list_head list;
 struct task_struct *task;
 int type;
 unsigned long timeout;
 bool handoff_set, donor_wakeup;
};
struct rw_semaphore { long count; int wait_lock; struct list_head wait_list; };
static struct rwsem_waiter *first_waiter;
static unsigned long jiffies;
static int deleted, owned, fail_once;
#define RWSEM_WAITING_FOR_READ 0
#define RWSEM_WAITING_FOR_WRITE 1
#define RWSEM_WAIT_TIMEOUT 5
#define BITS_PER_LONG (sizeof(long)*8)
#define lockdep_assert_held(x) ((void)(x))
#define rwsem_first_waiter(x) ((void)(x), first_waiter)
#define atomic_long_read(x) (*(x))
#define rt_or_dl_task(t) ((t)->rt)
#define time_after(a,b) ((long)((b)-(a)) < 0)
#define list_is_singular(l) ((l)->singular)
#define list_del(l) ((void)(l), deleted++)
#define rwsem_set_owner(s) ((void)(s), owned++)
#define lockevent_inc(x) ((void)0)
static bool atomic_long_try_cmpxchg_acquire(long *v,long *old,long new) {
 if(fail_once) { fail_once=0; *old=*v; return false; }
 if(*v!=*old) { *old=*v; return false; }
 *v=new; return true;
}
'''
MAIN = r'''
struct result { bool got; long count; bool handoff; int deleted,owned; };
static struct result run(bool port, long count, bool isfirst, bool handoff,
                         bool rt, bool expired, bool singular, bool fail,
                         bool donor) {
 struct rwsem_waiter waiter, first;
 memset(&waiter,1,sizeof(waiter));
 memset(&first,0,sizeof(first));
 jiffies=100; task.rt=rt;
 init_write(&waiter);
 waiter.timeout=expired ? 99 : 101;
 if(donor) waiter.donor_wakeup=true;
 first_waiter=isfirst ? &waiter : &first;
 first_waiter->handoff_set=handoff;
 struct rw_semaphore sem={.count=count,.wait_list={.singular=singular}};
 deleted=owned=0; fail_once=fail;
 bool got=port ? port_try(&sem,&waiter) : native_try(&sem,&waiter);
 return (struct result){got,sem.count,first_waiter->handoff_set,deleted,owned};
}
static int cases, failures;
#define CHECK(x) do { if(!(x)) failures++; } while(0)
int main(void) {
 for(int reader=0;reader<2;reader++) {
  struct rwsem_waiter waiter;
  memset(&waiter,1,sizeof(waiter));
  if(reader) init_read(&waiter); else init_write(&waiter);
  CHECK(!waiter.donor_wakeup); cases++;
 }
 for(int readers=0;readers<3;readers++)
 for(int writer=0;writer<2;writer++)
 for(int handoffbit=0;handoffbit<2;handoffbit++)
 for(int isfirst=0;isfirst<2;isfirst++)
 for(int handoff=0;handoff<2;handoff++)
 for(int rt=0;rt<2;rt++)
 for(int expired=0;expired<2;expired++)
 for(int singular=0;singular<2;singular++)
 for(int fail=0;fail<2;fail++) {
  long count=readers*RWSEM_READER_BIAS | (writer?RWSEM_WRITER_LOCKED:0)
            | RWSEM_FLAG_WAITERS | (handoffbit?RWSEM_FLAG_HANDOFF:0);
  struct result a=run(true,count,isfirst,handoff,rt,expired,singular,fail,false);
  struct result b=run(false,count,isfirst,handoff,rt,expired,singular,fail,false);
  CHECK(a.got==b.got && a.count==b.count && a.handoff==b.handoff
        && a.deleted==b.deleted && a.owned==b.owned);
  cases++;
 }
 /* Explicitly selected donors can bypass ordinary head handoff only when
  * the lock is free; initialization must not disable that existing policy. */
 for(int busy=0;busy<3;busy++) {
  long count=RWSEM_FLAG_WAITERS|RWSEM_FLAG_HANDOFF;
  if(busy==1) count|=RWSEM_WRITER_LOCKED;
  if(busy==2) count|=RWSEM_READER_BIAS;
  struct result a=run(true,count,false,true,true,true,false,false,true);
  CHECK(a.got==(busy==0));
  CHECK(a.deleted==(busy==0) && a.owned==(busy==0));
  cases++;
 }
 printf("cases=%d failures=%d\n",cases,failures);
 return failures ? 1 : 0;
}
'''


def initializers(source):
    out = []
    for kind, name in [('read', 'rwsem_down_read_slowpath'), ('write', 'rwsem_down_write_slowpath')]:
        body = function(source, name)
        start = body.index('\twaiter.task = current;')
        end = body.index('\n\n', start)
        block = body[start:end].replace('waiter.', 'w->')
        out.append('static void init_' + kind + '(struct rwsem_waiter *w) {\n' + block + '\n}\n')
    return ''.join(out)


def main():
    source = (ROOT / PATH).read_text()
    native = subprocess.check_output(['git', 'show', LTS + ':' + PATH], cwd=ROOT, text=True)
    ack = subprocess.check_output(['git', 'show', ACK + ':' + PATH], cwd=ROOT, text=True)
    defines = source[source.index('#define RWSEM_WRITER_LOCKED'):source.index('#define RWSEM_READ_FAILED_MASK')]
    actual = function(source, 'rwsem_try_write_lock').replace('rwsem_try_write_lock(', 'port_try(', 1)
    baseline = function(native, 'rwsem_try_write_lock').replace('rwsem_try_write_lock(', 'native_try(', 1)
    results = {}
    with tempfile.TemporaryDirectory(prefix='rwsem-waiter-init-') as tmp:
        for label, init_source in [('port', source), ('ack_initializer_control', ack)]:
            text = PREAMBLE + defines + initializers(init_source) + actual + baseline + MAIN
            c = Path(tmp) / (label + '.c'); exe = Path(tmp) / label
            c.write_text(text)
            subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(exe)], check=True)
            r = subprocess.run([str(exe)], text=True, capture_output=True)
            match = re.fullmatch(r'cases=(\d+) failures=(\d+)\n', r.stdout)
            assert match, (r.returncode, r.stdout, r.stderr)
            results[label] = dict(cases=int(match[1]), failures=int(match[2]), exit_code=r.returncode,
                                  harness_sha256=hashlib.sha256(text.encode()).hexdigest())
    assert results['port']['failures'] == 0
    assert results['ack_initializer_control']['failures'] > 0
    report = dict(source_sha256=hashlib.sha256(source.encode()).hexdigest(), results=results,
                  scope='Actual read/write initializer blocks and complete writer try-lock function; non-donor behavior compared to complete pinned LTS function after valid true-valued poison initialization. Explicit donor success/busy checks also run. Single-threaded atomic/list stubs; no real IRQ, locking, scheduling, proxy execution, wait-queue race or latency test.', remote_sources_used=[])
    (ROOT / 'Documentation/android-port/evidence/rwsem-waiter-init-check.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
