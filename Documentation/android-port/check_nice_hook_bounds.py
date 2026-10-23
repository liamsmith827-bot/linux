#!/usr/bin/env python3
"""Exercise extracted set_user_nice with modeled locks, classes and vendor hooks.

Checks hook ordering, veto, range rejection and lock cleanup, including invalid
callback outputs. The weight stub detects an invalid index without dereferencing
it. This is not kernel execution, concurrent scheduling or a userspace exploit.
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
CONTROL = 'dcef94ed034d124ddb857f63f3e6544f0c0970ce'
PRE = r'''
#include <stdbool.h>
#define MIN_NICE (-20)
#define MAX_NICE 19
#define NICE_TO_PRIO(n) ((n) + 120)
#define DEQUEUE_SAVE 1
#define DEQUEUE_NOCLOCK 2
struct rq { int dummy; };
struct task_struct;
struct sched_class { void (*prio_changed)(struct rq *, struct task_struct *, int); };
struct task_struct { int static_prio, prio, policy; struct sched_class *sched_class; };
static struct rq queue;
static int held, updates, bad_index, notifications, unlocked_calls, locked_calls;
static long unlocked_value, locked_value;
static bool hook_allowed;
struct lock_guard { struct rq *rq; };
static struct lock_guard acquire(struct task_struct *p) { held++; return (struct lock_guard){&queue}; }
static void release(struct lock_guard *g) { held--; }
#define CLASS(kind, name) struct lock_guard name __attribute__((cleanup(release))) = acquire
#define scoped_guard(...) for (int once = 1; once; once = 0)
#define task_nice(p) ((p)->static_prio - 120)
#define task_has_dl_policy(p) ((p)->policy == 2)
#define task_has_rt_policy(p) ((p)->policy == 1)
static void update_rq_clock(struct rq *rq) {}
static void trace_android_rvh_set_user_nice(struct task_struct *p, long *nice) {
 unlocked_calls++; if (unlocked_value != 10000) *nice = unlocked_value;
}
static void trace_android_rvh_set_user_nice_locked(struct task_struct *p, long *nice, bool *allowed) {
 locked_calls++; if (held != 1) __builtin_trap();
 if (locked_value != 10000) *nice = locked_value;
 *allowed = hook_allowed;
}
static void set_load_weight(struct task_struct *p, bool update) {
 int index = p->static_prio - 100;
 updates++; if (index < 0 || index >= 40) bad_index++;
}
static int effective_prio(struct task_struct *p) { return p->static_prio; }
static void changed(struct rq *rq, struct task_struct *p, int old) { notifications++; }
'''
WRAP = r'''
void probe(int current, int request, int unlocked, int locked, int allowed, int policy, int *out) {
 struct sched_class cls = {.prio_changed = changed};
 struct task_struct p = {.static_prio=current+120, .prio=current+120, .policy=policy, .sched_class=&cls};
 held=updates=bad_index=notifications=unlocked_calls=locked_calls=0;
 unlocked_value=unlocked; locked_value=locked; hook_allowed=allowed;
 set_user_nice(&p, request);
 out[0]=p.static_prio; out[1]=p.prio; out[2]=updates; out[3]=bad_index;
 out[4]=notifications; out[5]=unlocked_calls; out[6]=locked_calls; out[7]=held;
}
'''


def expected(case):
    current, request, unlocked, locked, allowed, policy = case
    value = request if unlocked == 10000 else unlocked
    out = [current + 120, current + 120, 0, 0, 0, 1, 0, 0]
    if value == current or not -20 <= value <= 19:
        return out
    out[6] = 1
    value = value if locked == 10000 else locked
    if not allowed or not -20 <= value <= 19:
        return out
    out[0] = value + 120
    if not policy:
        out[1] = value + 120
        out[2] = out[4] = 1
    return out


def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    values = [-1000, -21, -20, -1, 0, 1, 19, 20, 1000]
    cases = list(itertools.product([-20, 0, 19], values, [10000] + values,
                                   [10000] + values, range(2), range(3)))
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=CONTROL,
                  cases=len(cases), scope=__doc__, results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='nice-hook-') as tmp:
        for label, source in [('port', (ROOT/'kernel/sched/syscalls.c').read_text()),
                              ('pre_fix_control', git('show', CONTROL+':kernel/sched/syscalls.c'))]:
            body = function(source, 'set_user_nice')
            code = PRE + body + WRAP
            path = Path(tmp)/(label+'.c'); path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror',
                            str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_int]*6 + [ctypes.POINTER(ctypes.c_int)]
            probe.restype = None
            failed = invalid = leaked = 0
            for case in cases:
                out = (ctypes.c_int*8)(); probe(*case, out)
                failed += list(out) != expected(case)
                invalid += bool(out[3]); leaked += bool(out[7])
            report['results'][label] = dict(failures=failed, invalid_weight_indices=invalid,
                leaked_model_locks=leaked, function_sha256=hashlib.sha256(body.encode()).hexdigest(),
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['invalid_weight_indices'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT/'Documentation/android-port/evidence/nice-hook-bounds-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
