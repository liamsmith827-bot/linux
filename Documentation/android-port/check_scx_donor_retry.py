#!/usr/bin/env python3
"""Exercise extracted SCX/DL pick functions with simulated lock-drop donor changes.

Host control-flow tests, not kernel scheduling, BPF execution or concurrency tests.
Old donor storage becomes PROT_NONE on replacement, exposing stale dereferences.
"""
import hashlib
import itertools
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OLD = '697505edff4d7d95372c862de4c94d1089274825'

def function(source, name):
    lines = source.splitlines(True)
    for i, line in enumerate(lines):
        if (not line or line[0].isspace() or line.startswith(('/*', '//', '*'))
                or not re.search(r'\b' + name + r'\(', line)):
            continue
        tail = ''.join(lines[i:])
        if ';' in tail[:tail.index('{')]:
            continue
        for j in range(i + 1, len(lines)):
            if lines[j].startswith('}'):
                return ''.join(lines[i:j + 1])
    raise ValueError(name)

PRE = r'''
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint64_t u64;
struct rq; struct rq_flags { int unused; };
struct sched_class { int id; };
static struct sched_class ext_sched_class, other_class;
struct task_struct { struct sched_class *sched_class; struct { unsigned flags; u64 slice; } scx; };
struct sched_dl_entity { bool server; struct task_struct *(*server_pick_task)(struct sched_dl_entity *, struct rq_flags *); };
struct dl_rq { bool runnable; struct sched_dl_entity *entry; };
struct rq { struct task_struct *donor; struct { unsigned flags, pnt_seq; bool cpu_released; struct { int nr; } local_dsq; } scx; struct dl_rq dl; struct sched_dl_entity *dl_server; };
struct scx_sched { struct { unsigned flags; } ops; bool warned_zero_slice; };
struct scx_dsp_ctx { struct rq *rq; int nr_tasks; };
static struct scx_sched sched, *scx_root = &sched;
static struct scx_dsp_ctx dsp;
static struct task_struct replacement = { .sched_class=&other_class };
static struct task_struct *old_task, *direct_result;
static int scenario, force, higher, queued, slice, last, changed, global_calls;
static int bad_callback, hook_calls, dump_calls, stops, balance_callbacks;
static size_t pagesize;
#define SCX_TASK_QUEUED 1U
#define SCX_RQ_IN_BALANCE 1U
#define SCX_RQ_BAL_KEEP 2U
#define SCX_OPS_HAS_CPU_PREEMPT 1U
#define SCX_OPS_ENQ_LAST 2U
#define SCX_DSP_MAX_LOOPS 4
#define SCX_ENABLED 1
#define SCX_KF_REST 0
#define SCX_KF_DISPATCH 0
#define SCX_KICK_IDLE 0
#define SCX_EV_DISPATCH_KEEP_LAST 0
#define KERN_WARNING ""
#define RETRY_TASK ((struct task_struct *)-1UL)
#define unlikely(x) (x)
#define this_cpu_ptr(x) (&dsp)
#define lockdep_assert_rq_held(rq) ((void)0)
#define smp_store_release(p,v) (*(p)=(v))
#define rcu_dereference_sched(p) (p)
#define WARN_ON_ONCE(x) ((void)(x))
#define printk_deferred(...) ((void)0)
#define SCX_HAS_OP(s,n) true
#define SCX_CALL_OP(s,k,n,r,c,p) mock_##n(r,p)
static void replace_donor(struct rq *rq) {
 if (changed) return;
 rq->donor=&replacement; changed=1;
 if(mprotect(old_task,pagesize,PROT_NONE)) abort();
}
static bool scx_rq_bypassing(struct rq *rq) { return false; }
static bool scx_rq_online(struct rq *rq) { return true; }
static int cpu_of(struct rq *rq) { return 0; }
static int scx_enable_state(void) { return SCX_ENABLED; }
static void update_curr_scx(struct rq *rq) {}
static void mock_cpu_acquire(struct rq *rq, struct task_struct *p) {}
static void mock_dispatch(struct rq *rq, struct task_struct *p) {
 if (p && p != rq->donor) bad_callback++;
}
static bool consume_global_dsq(struct scx_sched *s, struct rq *rq) {
 global_calls++;
 if ((scenario==1 && global_calls==1) || (scenario==3 && global_calls==2)) replace_donor(rq);
 return false;
}
static void flush_dispatch_buf(struct scx_sched *s, struct rq *rq) {
 if(scenario==2) replace_donor(rq);
 dsp.nr_tasks=0;
}
static void trace_android_vh_scx_cpu_allowed(void *p, int cpu, bool *allowed) {}
static void scx_kick_cpu(struct scx_sched *s, int cpu, int flags) {}
static void __scx_add_event(struct scx_sched *s, int event, int n) {}
static void rq_unpin_lock(struct rq *rq, struct rq_flags *rf) {}
static void rq_repin_lock(struct rq *rq, struct rq_flags *rf) {
 if(scenario==4) replace_donor(rq);
}
static void maybe_queue_balance_callback(struct rq *rq) { balance_callbacks++; }
static void rq_modified_clear(struct rq *rq) {}
static bool rq_modified_above(struct rq *rq, struct sched_class *class) { return higher; }
static struct task_struct *first_local_task(struct rq *rq) { return NULL; }
static void refill_task_slice_dfl(struct scx_sched *s, struct task_struct *p) { p->scx.slice=10; }
static void trace_android_vh_scx_fix_prev_slice(struct task_struct *p) {}
static bool sched_dl_runnable(struct rq *rq) { return rq->dl.runnable; }
static struct sched_dl_entity *pick_next_dl_entity(struct dl_rq *dl) { return dl->entry; }
static bool dl_server(struct sched_dl_entity *e) { return e->server; }
static struct task_struct *dl_task_of(struct sched_dl_entity *e) { return &replacement; }
static void trace_android_rvh_dl_server_stop_skip(struct sched_dl_entity *e, struct rq *rq, struct task_struct *p, bool *skip) {
 hook_calls++; if (p==RETRY_TASK) bad_callback++;
}
static void trace_android_vh_dump_dl_server(struct sched_dl_entity *e, struct task_struct *p) {
 dump_calls++; if (p==RETRY_TASK) bad_callback++;
}
static struct rq *active_rq;
static void dl_server_stop(struct sched_dl_entity *e) { stops++; active_rq->dl.runnable=false; }
static struct task_struct *direct_pick(struct sched_dl_entity *e, struct rq_flags *rf) { return direct_result; }
'''
MAIN = r'''
static struct task_struct *via_scx(struct sched_dl_entity *e, struct rq_flags *rf) {
 return do_pick_task_scx(active_rq, rf, true);
}
int main(int argc, char **argv) {
 if(argc!=8) return 2;
 scenario=atoi(argv[1]); force=atoi(argv[2]); higher=atoi(argv[3]); queued=atoi(argv[4]);
 slice=atoi(argv[5]); last=atoi(argv[6]); int through_dl=atoi(argv[7]);
 pagesize=sysconf(_SC_PAGESIZE);
 old_task=mmap(NULL,pagesize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(old_task==MAP_FAILED) abort();
 old_task->sched_class=&ext_sched_class;
 old_task->scx.flags=queued ? SCX_TASK_QUEUED:0; old_task->scx.slice=slice;
 sched.ops.flags=last ? SCX_OPS_ENQ_LAST:0;
 struct rq rq={.donor=old_task}; struct rq_flags rf={0};
 struct sched_dl_entity e={.server=true,.server_pick_task=direct_pick};
 active_rq=&rq; rq.dl.entry=&e; rq.dl.runnable=true;
 struct task_struct *got, *expected;
 if(scenario>=5) {
  direct_result=scenario==5 ? RETRY_TASK : scenario==6 ? NULL : &replacement;
  got=__pick_task_dl(&rq,&rf); expected=direct_result;
  if (got!=expected || bad_callback) return 1;
  if(scenario==5 && (hook_calls || dump_calls || stops || rq.dl_server)) return 1;
  if(scenario==6 && (hook_calls!=1 || dump_calls || stops!=1 || rq.dl_server)) return 1;
  if(scenario==7 && (hook_calls!=1 || dump_calls!=1 || stops || rq.dl_server!=&e)) return 1;
 } else {
  if (through_dl) { e.server_pick_task=via_scx; got=__pick_task_dl(&rq,&rf); }
  else got=do_pick_task_scx(&rq,&rf,force);
  if(changed || (higher && !force && !through_dl)) expected=RETRY_TASK;
  else if(queued && (slice || !last)) expected=old_task;
  else expected=NULL;
  if(got!=expected || bad_callback || (rq.scx.flags & SCX_RQ_IN_BALANCE) || balance_callbacks!=1) return 1;
  if(through_dl && expected==RETRY_TASK && (hook_calls || dump_calls || rq.dl_server || stops)) return 1;
 }
 return 0;
}
'''

def run():
    sources = {}
    for label, ref in [('port', None), ('pre_fix_control', OLD)]:
        parts = []
        witnesses = []
        for path, names in [('kernel/sched/ext.c', ['balance_one','balance_scx','do_pick_task_scx']),
                            ('kernel/sched/deadline.c', ['__pick_task_dl'])]:
            s = (ROOT/path).read_text() if ref is None else subprocess.check_output(['git','show',ref+':'+path],cwd=ROOT,text=True)
            for name in names:
                f = function(s,name)
                # Extractor starts at identifier when return type occupies prior line.
                if name == 'do_pick_task_scx': f = 'static struct task_struct *\n' + f
                parts.append(f)
                witnesses.append({'path':path,'function':name,'sha256':hashlib.sha256(f.encode()).hexdigest()})
        sources[label] = (PRE+'\n'.join(parts)+MAIN, witnesses)
    cases = list(itertools.product(range(5),range(2),range(2),range(2),range(2),range(2),range(2)))
    cases += [(mode,0,0,0,0,0,0) for mode in (5,6,7)]
    results = {}
    with tempfile.TemporaryDirectory(prefix='scx-donor-retry-') as td:
        for label,(source,witnesses) in sources.items():
            c = Path(td)/(label+'.c'); c.write_text(source); exe=Path(td)/label
            subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-parameter',str(c),'-o',str(exe)],check=True)
            failures=[]
            for case in cases:
                r=subprocess.run([str(exe),*map(str,case)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if r.returncode: failures.append({'case':case,'returncode':r.returncode})
            results[label]={'cases':len(cases),'failures':len(failures),'failed_cases':failures,'witnesses':witnesses}
    assert results['port']['failures']==0,results['port']['failed_cases'][:8]
    assert results['pre_fix_control']['failures']>0
    report={'base_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'control_commit':OLD,'results':results,
            'scope':__doc__,'remote_sources_used':[]}
    out=ROOT/'Documentation/android-port/evidence/scx-donor-retry-check.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"{len(cases)} port cases passed; {results['pre_fix_control']['failures']} pre-fix controls failed")

if __name__=='__main__': run()
