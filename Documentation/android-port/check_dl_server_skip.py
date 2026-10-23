#!/usr/bin/env python3
"""Exercise the actual DL pick loop with three simulated server candidates.

An opt-in hook vetoes selected servers and leaves other decisions untouched.
Verify that each decision is independent, and RETRY_TASK bypasses hooks/state.
This is a host control-flow test, not kernel scheduling or BPF concurrency.
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
CONTROL = 'b1cd2b2b27929af030c47d1803ffc903742fbfac'
PRE = r'''
#include <stdbool.h>
#include <stddef.h>
struct task_struct { int id; };
struct rq; struct rq_flags { int unused; };
struct sched_dl_entity { struct task_struct *(*server_pick_task)(struct sched_dl_entity *, struct rq_flags *); int id; };
struct dl_rq { int unused; };
struct rq { struct dl_rq dl; struct sched_dl_entity *dl_server; };
static struct sched_dl_entity servers[3];
static struct task_struct tasks[3];
static int index_now, kinds[3], veto, hooks, dumps, stopped;
#define RETRY_TASK ((struct task_struct *)-1L)
#define unlikely(x) (x)
#define WARN_ON_ONCE(x) ((void)(x))
static int sched_dl_runnable(struct rq *rq) { return index_now<3; }
static struct sched_dl_entity *pick_next_dl_entity(struct dl_rq *rq) { return &servers[index_now]; }
static bool dl_server(struct sched_dl_entity *s) { return true; }
static struct task_struct *dl_task_of(struct sched_dl_entity *s) { return &tasks[s->id]; }
static struct task_struct *pick(struct sched_dl_entity *s, struct rq_flags *rf) {
 return kinds[s->id]==0 ? NULL : kinds[s->id]==1 ? &tasks[s->id] : RETRY_TASK;
}
static void trace_android_rvh_dl_server_stop_skip(struct sched_dl_entity *s, struct rq *rq, struct task_struct *p, bool *skip) {
 if(p==RETRY_TASK) __builtin_trap();
 hooks |= 1U << s->id;
 if(veto & (1U<<s->id)) *skip=true;
}
static void dl_server_stop(struct sched_dl_entity *s) { stopped |= 1U<<s->id; index_now++; }
static void trace_android_vh_dump_dl_server(struct sched_dl_entity *s, struct task_struct *p) { dumps |= 1U<<s->id; }
'''
WRAP = r'''
void probe(int a, int b, int c, int mask, int *out) {
 struct rq rq = {0}; struct rq_flags rf = {0};
 kinds[0]=a; kinds[1]=b; kinds[2]=c;
 for(int i=0;i<3;i++) { tasks[i].id=i; servers[i]=(struct sched_dl_entity){.server_pick_task=pick,.id=i}; }
 index_now=hooks=dumps=stopped=0; veto=mask;
 struct task_struct *p=__pick_task_dl(&rq,&rf);
 out[0]=p==RETRY_TASK ? -2 : p ? p->id : -1;
 out[1]=rq.dl_server ? rq.dl_server->id : -1;
 out[2]=hooks; out[3]=dumps; out[4]=stopped;
}
'''


def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    cases = [(*k, mask) for k in itertools.product(range(3), repeat=3) for mask in range(8)]
    expected = []
    for *kinds, mask in cases:
        result, server, hooks, dumps, stopped = -1, -1, 0, 0, 0
        for i,kind in enumerate(kinds):
            if kind == 2:
                result = -2; break
            hooks |= 1 << i
            if kind == 0 or mask & (1 << i):
                stopped |= 1 << i; continue
            result = server = i; dumps = 1 << i; break
        expected.append([result, server, hooks, dumps, stopped])
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=CONTROL,
                  cases=len(cases), scope=__doc__, results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='dl-server-skip-') as tmp:
        for label, source in [('port', (ROOT / 'kernel/sched/deadline.c').read_text()),
                              ('pre_fix_control', git('show', CONTROL + ':kernel/sched/deadline.c'))]:
            body = function(source, '__pick_task_dl')
            code = PRE + body + WRAP
            path = Path(tmp) / (label + '.c'); path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror', str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_int] * 4 + [ctypes.POINTER(ctypes.c_int)]
            probe.restype = None
            failures = []
            for i,c in enumerate(cases):
                out = (ctypes.c_int * 5)(); probe(*c, out)
                if list(out) != expected[i]: failures.append(i)
            report['results'][label] = dict(failures=len(failures),
                first_failure_inputs=cases[failures[0]] if failures else None,
                function_sha256=hashlib.sha256(body.encode()).hexdigest(),
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['failures'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT / 'Documentation/android-port/evidence/dl-server-skip-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
