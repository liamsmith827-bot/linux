#!/usr/bin/env python3
"""Exercise extracted blocked-state helpers and two historical ordering fixes.

Locks, scheduling and release/acquire operations are single-threaded simulations.
The release callback forces one documented spurious-wakeup interleaving. This is
not a kernel concurrency, CPU-affinity, fairness or proxy-chain lifetime test.
"""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_wakeup_reason_names import function

ROOT = Path(__file__).resolve().parents[2]

PREAMBLE = r'''
#include <stdbool.h>
#include <stdio.h>
enum blocked_on_type { BO_T_NONE, BO_T_MUTEX, BO_T_RWSEM };
struct blocked_on_lock { void *lock; enum blocked_on_type type; };
struct task_struct { struct blocked_on_lock blocked_on; struct task_struct *blocked_donor; int blocked_lock, state, refs; };
struct rwsem_waiter { struct task_struct *task; };
static struct task_struct runner, sleeper, *current;
static int sem_storage, other_storage, cases, failures, warnings;
static bool enabled;
#define PROXY_WAKING ((void *)(-1L))
#define sched_proxy_exec() enabled
#define WARN_ON_ONCE(x) ((x) ? (++warnings, true) : false)
#define lockdep_assert_held_once(x) ((void)(x))
#define raw_spin_lock(x) ((void)(x))
#define raw_spin_unlock(x) ((void)(x))
#define raw_spin_lock_irqsave(x, f) ((void)(x), (void)((f)=0))
#define raw_spin_unlock_irqrestore(x, f) ((void)(x), (void)(f))
#define set_current_state(x) (current->state=(x))
#define CHECK(x) do { if (!(x)) failures++; } while (0)
'''

MAIN = r'''
int main(void) {
 void *sem=&sem_storage;
 current=&sleeper;
 for(int pe=0;pe<2;pe++) for(int type=BO_T_MUTEX;type<=BO_T_RWSEM;type++) {
  enabled=pe; warnings=0; sleeper=(struct task_struct){0};
  __set_task_blocked_on(current,sem,type);
  CHECK(__get_task_blocked_on(current)==sem && current->blocked_on.type==(unsigned)type);
  __set_task_blocked_on_waking(current,sem);
  CHECK(current->blocked_on.lock==(pe?PROXY_WAKING:NULL));
  CHECK(!__get_task_blocked_on(current));
  __clear_task_blocked_on(current,sem);
  CHECK(!current->blocked_on.lock && current->blocked_on.type==BO_T_NONE);
  __set_task_blocked_on_waking(current,sem);
  CHECK(!current->blocked_on.lock && !warnings); cases++;
 }
 for(int pe=0;pe<2;pe++) for(int initial=0;initial<3;initial++) {
  enabled=pe; warnings=0; current=&runner; runner=(struct task_struct){0};
  sleeper=(struct task_struct){.blocked_on={initial==0?NULL:initial==1?sem:PROXY_WAKING,BO_T_RWSEM}};
  runner.blocked_donor=&sleeper;
  struct rwsem_waiter waiter={.task=&sleeper};
  publish_reader(&waiter,sem);
  CHECK(!warnings && !waiter.task && sleeper.blocked_on.lock==&other_storage);
  CHECK(sleeper.blocked_on.type==BO_T_MUTEX && !sleeper.refs);
  CHECK(!runner.blocked_donor); cases++;
 }
 for(int state=1;state<=4;state++) {
  current=&sleeper; sleeper=(struct task_struct){0}; warnings=0;
  resume_after_spin(sem,state);
  CHECK(current->state==state && current->blocked_on.lock==sem);
  CHECK(current->blocked_on.type==BO_T_MUTEX && !warnings); cases++;
 }
 printf("cases=%d failures=%d\n",cases,failures);
 return failures?1:0;
}
'''


def read(rev, path):
    return subprocess.check_output(['git', 'show', rev + ':' + path], cwd=ROOT, text=True)


def reader_block(source):
    body = function(source, 'rwsem_mark_wake')
    body = body[body.index('/* 2nd pass */'):]
    start = body.index('\t\ttsk = waiter->task;')
    end = body.rindex('\n\t}')
    return body[start:end]


def mutex_block(source):
    body = function(source, '__mutex_lock_common')
    start = body.index('opt_acquired = mutex_optimistic_spin')
    start = body.index('\n', start) + 1
    end = body.index('\n\t\t\tif (opt_acquired)', start)
    return body[start:end]


def main():
    sched = (ROOT / 'include/linux/sched.h').read_text()
    rwsem = (ROOT / 'kernel/locking/rwsem.c').read_text()
    mutex = (ROOT / 'kernel/locking/mutex.c').read_text()
    helpers = ''.join(function(sched, n) for n in (
        '__get_task_blocked_on', '__set_task_blocked_on',
        '__clear_task_blocked_on', '__set_task_blocked_on_waking'))
    support = r'''
static void publish_and_run(struct task_struct **slot) {
 struct task_struct *woken=*slot, *saved=current;
 CHECK(woken->refs>0);
 *slot=NULL;
 current=woken;
 __clear_task_blocked_on(current,&sem_storage);
 __set_task_blocked_on(current,&other_storage,BO_T_MUTEX);
 current=saved;
}
#define smp_store_release(slot, v) ((void)(v), publish_and_run(slot))
#define get_task_struct(t) ((t)->refs++)
#define wake_q_add_safe(q,t) ((void)(q), (t)->refs--)
'''
    results = {}
    with tempfile.TemporaryDirectory(prefix='proxy-lock-state-') as tmp:
        for label, rsrc, msrc in [
            ('port', rwsem, mutex),
            ('pre_reader_order_fix_control', read('978a5c9c4e1a^', 'kernel/locking/rwsem.c'), mutex),
            ('pre_mutex_state_fix_control', rwsem, read('9bb516eaee64^', 'kernel/locking/mutex.c')),
        ]:
            code = PREAMBLE + helpers + support
            code += '\nstatic void publish_reader(struct rwsem_waiter *waiter, void *sem) {\nstruct task_struct *tsk; int wake_q=0;\n' + reader_block(rsrc) + '\n}\n'
            # wait_lock is simulated with an int; retain the actual ordered body.
            code += '\nstatic void resume_after_spin(void *lock, int state) { unsigned long flags; struct { int wait_lock; } dummy;\n'
            code += mutex_block(msrc).replace('&lock->wait_lock', '&dummy.wait_lock') + '\n(void)state;\n}\n'
            code += MAIN
            c = Path(tmp) / (label + '.c'); exe = Path(tmp) / label
            c.write_text(code)
            subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(exe)], check=True)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            match = re.fullmatch(r'cases=(\d+) failures=(\d+)\n', run.stdout)
            assert match, (run.returncode, run.stdout, run.stderr)
            results[label] = dict(cases=int(match[1]), failed_assertions=int(match[2]), exit_code=run.returncode,
                                  harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert results['port']['failed_assertions'] == 0
    assert all(results[k]['failed_assertions'] > 0 for k in results if k != 'port')
    report = dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in [
                      ('include/linux/sched.h',sched),('kernel/locking/mutex.c',mutex),('kernel/locking/rwsem.c',rwsem)]},
                  results=results, scope=__doc__, remote_sources_used=[])
    (ROOT / 'Documentation/android-port/evidence/proxy-lock-state-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
