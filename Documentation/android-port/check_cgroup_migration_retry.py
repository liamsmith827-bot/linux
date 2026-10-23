#!/usr/bin/env python3
"""Test extracted cgroup task lookup with a forced group-leader retry.

Models task flags, opt-in callbacks, references and lock counts. A forced change
at attach-lock acquisition exercises the retry path; this is not a reproduced
kernel race, permission check, migration, or exploit test.
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
CONTROL = '2ed111267d9e5725b076fe4566ee2fed53b4b754'
PRE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#define PF_KTHREAD 1
#define PF_NO_SETAFFINITY 2
#define ERR_PTR(e) ((struct task_struct *)(intptr_t)(e))
typedef int pid_t;
struct cgroup { int unused; };
struct task_struct { unsigned flags; bool no_cgroup_migration; struct task_struct *group_leader; };
enum cgroup_attach_lock_mode { CGRP_ATTACH_LOCK_NONE, CGRP_ATTACH_LOCK_PER_THREADGROUP, CGRP_ATTACH_LOCK_GLOBAL };
static struct task_struct tasks[2];
static int lookup, pid_input, force_retry, callback_bits, hooks, rcu, refs, locks;
static bool cgroup_enable_per_threadgroup_rwsem;
#define current (&tasks[lookup])
#define lockdep_assert_held(x) ((void)0)
static char *strstrip(char *s) { return s; }
static int kstrtoint(char *s, int base, int *pid) { *pid=pid_input; return 0; }
static void rcu_read_lock(void) { rcu++; }
static void rcu_read_unlock(void) { rcu--; }
static struct task_struct *find_task_by_vpid(int pid) { return &tasks[lookup]; }
static void trace_android_rvh_cgroup_force_kthread_migration(struct task_struct *p, struct cgroup *c, bool *allow) {
 if(rcu!=1) __builtin_trap();
 hooks++;
 if(callback_bits & (1<<lookup)) *allow=true;
}
static void get_task_struct(struct task_struct *p) { refs++; }
static void put_task_struct(struct task_struct *p) { refs--; }
static void cgroup_attach_lock(enum cgroup_attach_lock_mode mode, struct task_struct *p) { locks++; }
static void cgroup_attach_unlock(enum cgroup_attach_lock_mode mode, struct task_struct *p) { locks--; lookup++; }
static bool thread_group_leader(struct task_struct *p) { return lookup!=0 || !force_retry; }
'''
WRAP = r'''
void probe(int first, int second, int bits, int group, int pid, int per_group, int retry, int *out) {
 struct cgroup cg={0}; enum cgroup_attach_lock_mode mode=CGRP_ATTACH_LOCK_NONE;
 int flags[2]={first,second};
 for(int i=0;i<2;i++) tasks[i]=(struct task_struct){.flags=flags[i]&3,.no_cgroup_migration=!!(flags[i]&4),.group_leader=&tasks[i]};
 lookup=hooks=rcu=refs=locks=0; pid_input=pid; callback_bits=bits; force_retry=retry;
 cgroup_enable_per_threadgroup_rwsem=per_group;
 struct task_struct *p=cgroup_procs_write_start("1", group, &mode, &cg);
 out[0]=(intptr_t)p<0 ? (int)(intptr_t)p : p==&tasks[0] ? 0 : 1;
 out[1]=hooks; out[2]=rcu; out[3]=refs; out[4]=locks;
}
'''


def expected(case):
    first, second, bits, group, pid, per_group, retry = case
    hooks = 0
    for index, flags in enumerate([first, second]):
        kernel = bool(flags & 1)
        hooks += kernel
        allow = kernel and bool(bits & (1 << index))
        if flags & 6 and not allow:
            return [-22, hooks, 0, 0, 0]
        if not (index == 0 and group and retry):
            return [index, hooks, 0, 1, 1]
    raise AssertionError(case)


def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    cases = list(itertools.product(range(8), range(8), range(4), range(2),
                                   range(2), range(2), range(2)))
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=CONTROL,
                  cases=len(cases), scope=__doc__, results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='cgroup-retry-') as tmp:
        for label, source in [('port', (ROOT/'kernel/cgroup/cgroup.c').read_text()),
                              ('pre_fix_control', git('show', CONTROL+':kernel/cgroup/cgroup.c'))]:
            body = function(source, 'cgroup_procs_write_start')
            code = PRE + body + WRAP
            path = Path(tmp)/(label+'.c'); path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror',
                            str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_int]*7 + [ctypes.POINTER(ctypes.c_int)]
            probe.restype = None
            failures = stale = 0
            example = None
            for case in cases:
                out = (ctypes.c_int*5)(); probe(*case, out)
                want = expected(case)
                failures += list(out) != want
                if want[0] == -22 and out[0] >= 0:
                    stale += 1
                    if example is None: example = case
            report['results'][label] = dict(failures=failures, stale_override_acceptances=stale,
                first_stale_input=example, function_sha256=hashlib.sha256(body.encode()).hexdigest(),
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['stale_override_acceptances'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT/'Documentation/android-port/evidence/cgroup-migration-retry-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
