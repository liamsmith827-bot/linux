#!/usr/bin/env python3
"""Check extracted chain migration and blocked-owner helpers in a host model.

The model injects PROXY_WAKING between the sentinel check and primitive-owner
access when blocked_lock is absent, and defers that write when the lock is held.
This exposes a permitted source-level interleaving, not a reproduced kernel crash
or compiler-machine-code race. Runqueue locks, lists and lifetime are simulated.
"""
import ctypes
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
CONTROL = '3409f41024900cdfa3107737b015ea59801cd711'
PRE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
enum { BO_T_NONE, BO_T_MUTEX, BO_T_RWSEM };
struct blocked_on_lock { void *lock; int type; };
struct rq;
struct task_struct { struct blocked_on_lock blocked_on; int blocked_lock; bool queued; struct rq *rq; };
struct rq { struct task_struct *donor; };
struct primitive { struct task_struct *owner; };
static struct task_struct tasks[3];
static struct primitive locks[3];
static int enabled, injection, pending, bad_access, unlocked_read, held_move, moves;
static unsigned moved;
#define PROXY_WAKING ((void *)-1L)
#define sched_proxy_exec() enabled
#define lockdep_assert_rq_held(rq) ((void)(rq))
#define WARN_ON(x) ((void)(x))
#define BUG() abort()
static bool task_is_blocked(struct task_struct *p) { return enabled && !!p->blocked_on.lock; }
static bool task_queued_on_rq(struct rq *rq, struct task_struct *p) { return p->queued && p->rq==rq; }
static bool task_current_donor(struct rq *rq, struct task_struct *p) { return rq->donor==p; }
static void inject_wake(void) {
 if(!injection) return;
 injection=0;
 if(tasks[0].blocked_lock) pending=1;
 else tasks[0].blocked_on.lock=PROXY_WAKING;
}
static struct task_struct *primitive_owner(void *p) {
 if(p==PROXY_WAKING || !p) { bad_access++; return NULL; }
 for(int i=0;i<3;i++) if(p==&locks[i] && !tasks[i].blocked_lock) unlocked_read++;
 return ((struct primitive *)p)->owner;
}
/* Evaluate bo->lock after the forced writer, modeling the unprotected reload. */
#define __mutex_owner(p) (inject_wake(), primitive_owner(p))
#define rwsem_writer_owner(p) (inject_wake(), primitive_owner(p))
static __attribute__((unused)) int *acquire(int *p) { if(*p) abort(); *p=1; return p; }
static __attribute__((unused)) void release(int *p) {
 *p=0;
 if(p==&tasks[0].blocked_lock && pending) { pending=0; tasks[0].blocked_on.lock=PROXY_WAKING; }
}
#define scoped_guard(kind,p) for(int *guardp=acquire(p); guardp; release(guardp),guardp=NULL)
static void __move_queued_task_locked(struct rq *src, struct rq *dst, struct task_struct *p) {
 for(int i=0;i<3;i++) held_move+=tasks[i].blocked_lock;
 if(++moves>3) abort();
 moved |= 1U << (p-tasks);
 p->rq=dst;
}
'''
WRAP = r'''
unsigned probe(int pe, int kind, int relation, int owner_state, int wake) {
 struct rq src = {0}, dst = {0}, other = {0};
 for(int i=0;i<3;i++) {
  tasks[i]=(struct task_struct){.queued=true,.rq=&src};
  locks[i]=(struct primitive){.owner=i<2 ? &tasks[i+1] : NULL};
 }
 enabled=pe; injection=wake; pending=bad_access=unlocked_read=held_move=moves=0; moved=0;
 tasks[0].blocked_on=(struct blocked_on_lock){.type=kind,.lock=&locks[0]};
 tasks[1].blocked_on=(struct blocked_on_lock){.type=kind,.lock=&locks[1]};
 if(relation==0) tasks[0].blocked_on=(struct blocked_on_lock){0};
 if(relation==1) tasks[0].blocked_on.lock=PROXY_WAKING;
 if(relation==3) locks[0].owner=NULL;
 if(relation==4) locks[0].owner=&tasks[0];
 if(owner_state==1) tasks[1].queued=false;
 if(owner_state==2) tasks[1].rq=&other;
 if(owner_state==3) src.donor=&tasks[1];
 move_queued_task_locked(&src,&dst,&tasks[0]);
 return moved | (bad_access<<8) | (unlocked_read<<12) | (held_move<<16);
}
'''


def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    cases = list(itertools.product(range(2), [1, 2], range(5), range(4), range(2)))
    # Before a deferred writer runs, capture the owner, then follow only tasks
    # still queued on the source and distinct from its selected donor.
    expected = [7 if pe and relation == 2 and state == 0 else 1
                for pe, kind, relation, state, wake in cases]
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=CONTROL,
                  cases=len(cases), scope=__doc__, results={}, remote_sources_used=[])
    names = ['__blocked_on_owner', 'task_blocked_on_owner', 'move_queued_task_locked']
    with tempfile.TemporaryDirectory(prefix='proxy-move-owner-') as tmp:
        for label, source in [('port', (ROOT / 'kernel/sched/core.c').read_text()),
                              ('pre_fix_control', git('show', CONTROL + ':kernel/sched/core.c'))]:
            bodies = [function(source, n) for n in names]
            code = PRE + '\n'.join(bodies) + WRAP
            path = Path(tmp) / (label + '.c'); path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror', str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_int] * 5; probe.restype = ctypes.c_uint
            outputs = [probe(*c) for c in cases]
            failures = [i for i, value in enumerate(outputs) if value != expected[i]]
            report['results'][label] = dict(failures=len(failures),
                invalid_primitive_cases=sum(bool(v & 0xf00) for v in outputs),
                unprotected_owner_read_cases=sum(bool(v & 0xf000) for v in outputs),
                move_with_blocked_lock_cases=sum(bool(v & 0xf0000) for v in outputs),
                functions={n:hashlib.sha256(b.encode()).hexdigest() for n,b in zip(names,bodies)},
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['invalid_primitive_cases'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT / 'Documentation/android-port/evidence/proxy-move-owner-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
