#!/usr/bin/env python3
"""Exercise extracted cgroup-v1 write code with distinct opener/writer credentials.

Capability/namespace responses and cgroup operations are host shims. This checks
permission selection, error returns, notifications and balanced references; it
does not execute kernel LSMs, real cgroup migration, or an inherited-fd exploit.
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
CONTROL = 'c3756f712d3d'
PRE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <errno.h>
#define GLOBAL_ROOT_UID 0
#define CAP_SYS_NICE 23
struct user_namespace { int id; };
struct cred { int euid, uid, suid, caps; struct user_namespace *user_ns; };
struct file { const struct cred *f_cred; };
struct kernfs_open_file { struct file *file; void *kn; };
struct cgroup { int unused; };
struct task_struct { int unused; };
enum cgroup_attach_lock_mode { CGRP_ATTACH_LOCK_NONE };
static struct cgroup group;
static struct task_struct target;
static struct cred opener, writer, target_cred;
static struct user_namespace ns;
static int early, attach_ret, locks, tasks, creds, notifications, attaches, misuse;
static bool uid_eq(int a, int b) { return a==b; }
static struct cgroup *cgroup_kn_lock_live(void *kn, bool ignored) {
 if(early==1) return NULL;
 locks++; return &group;
}
static struct task_struct *cgroup_procs_write_start(char *buf, bool threadgroup,
 enum cgroup_attach_lock_mode *mode, struct cgroup *dst) {
 if(dst!=&group || locks!=1) misuse++;
 if(early==2) return (void *)(intptr_t)-ESRCH;
 tasks++; return &target;
}
static int PTR_ERR_OR_ZERO(struct task_struct *p) { return (intptr_t)p<0 ? (int)(intptr_t)p : 0; }
static const struct cred *get_task_cred(struct task_struct *p) {
 if(p!=&target || tasks!=1) misuse++;
 creds++; return &target_cred;
}
static void put_cred(const struct cred *c) { if(c!=&target_cred) misuse++; creds--; }
static bool file_ns_capable(const struct file *f, struct user_namespace *n, int cap) {
 if(f->f_cred!=&opener || n!=&ns || cap!=CAP_SYS_NICE) misuse++;
 return !!(f->f_cred->caps & (1<<n->id));
}
static bool ns_capable(struct user_namespace *n, int cap) {
 if(n!=&ns || cap!=CAP_SYS_NICE) misuse++;
 return !!(writer.caps & (1<<n->id));
}
static int cgroup_attach_task(struct cgroup *c, struct task_struct *p, bool group_write) {
 if(c!=&group || p!=&target || tasks!=1 || creds) misuse++;
 attaches++; return attach_ret;
}
static void trace_android_vh_cgroup_set_task(int ret, struct cgroup *c, struct task_struct *p, bool tg) {
 if(ret!=attach_ret || attaches!=1) misuse++;
 notifications++;
}
static void cgroup_procs_write_finish(struct task_struct *p, enum cgroup_attach_lock_mode mode) { tasks--; }
static void cgroup_kn_unlock(void *kn) { locks--; }
'''
WRAP = r'''
void probe(int eu, int tu, int ts, int oc, int wc, int nsid, int err, int ar, int *out) {
 opener=(struct cred){.euid=eu,.caps=oc}; writer=(struct cred){.caps=wc};
 ns.id=nsid; target_cred=(struct cred){.uid=tu,.suid=ts,.user_ns=&ns};
 struct file file={.f_cred=&opener}; struct kernfs_open_file of={.file=&file};
 early=err; attach_ret=ar ? -EBUSY : 0;
 locks=tasks=creds=notifications=attaches=misuse=0;
 out[0]=__cgroup1_procs_write(&of,"1",16,0,true);
 out[1]=attaches; out[2]=notifications; out[3]=locks; out[4]=tasks; out[5]=creds; out[6]=misuse;
}
'''

def expected(case):
    eu, tu, ts, oc, wc, nsid, err, ar = case
    if err:
        return [-19 if err == 1 else -3, 0, 0, 0, 0, 0, 0]
    ordinary = eu == 0 or eu in (tu, ts)
    privileged = all(caps & (1 << nsid) for caps in (oc, wc))
    if not ordinary and not privileged:
        return [-13, 0, 0, 0, 0, 0, 0]
    return [-16 if ar else 16, 1, 1, 0, 0, 0, 0]

def main():
    git=lambda *a: subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
    control=git('rev-parse',CONTROL).strip()
    cases=list(itertools.product(range(4),range(4),range(4),range(4),range(4),range(2),range(3),range(2)))
    p='kernel/cgroup/cgroup-v1.c'
    report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,cases=len(cases),scope=__doc__,results={},remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='cgroup-creds-') as tmp:
        for label,src in [('port',(ROOT/p).read_text()),('pre_fix_control',git('show',control+':'+p))]:
            body=function(src,'__cgroup1_procs_write'); code=PRE+body+WRAP
            path=Path(tmp)/(label+'.c');path.write_text(code);lib=path.with_suffix('.so')
            subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror','-Wno-unused-function',str(path),'-o',str(lib)],check=True)
            probe=ctypes.CDLL(str(lib)).probe;probe.argtypes=[ctypes.c_int]*8+[ctypes.POINTER(ctypes.c_int)];probe.restype=None
            failures=unsafe=0;example=None
            for case in cases:
                out=(ctypes.c_int*7)();probe(*case,out);want=expected(case)
                failures += list(out)!=want
                if want[0]==-13 and out[1]:
                    unsafe+=1
                    if example is None: example=case
            report['results'][label]=dict(failures=failures,opener_denied_but_attach_called=unsafe,example=example,function_sha256=hashlib.sha256(body.encode()).hexdigest(),harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures']==0
    assert report['results']['pre_fix_control']['opener_denied_but_attach_called']>0
    report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
    (ROOT/'Documentation/android-port/evidence/cgroup-open-credentials-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__': main()
