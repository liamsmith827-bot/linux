#!/usr/bin/env python3
"""Check extracted CPU cgroup free callback ordering against modeled RCU reclaim.

Reclamation at explicit scheduling points models a grace period after call_rcu;
this is not an actual kernel RCU stress test or reproduced use-after-free.
"""
import ctypes
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
struct cgroup_subsys_state { int unused; };
struct task_group { struct cgroup_subsys_state css; };
static struct task_group tg;
static int enabled, at_unregister, at_entry, at_read, queued, freed, callbacks, bad_reads, unregisters;
static struct task_group *css_tg(struct cgroup_subsys_state *css) { return &tg; }
static void reclaim(int when) { if(when && queued) freed=1; }
static void sched_unregister_group(struct task_group *p) { unregisters++;queued=1;reclaim(at_unregister); }
static void trace_android_vh_cpu_cgroup_css_free(struct cgroup_subsys_state *css) {
 reclaim(at_entry);
 if(enabled) { callbacks++;reclaim(at_read);bad_reads+=freed; }
}
'''
POST=r'''
void probe(int active, int u, int e, int r, int *out) {
 enabled=active;at_unregister=u;at_entry=e;at_read=r;
 queued=freed=callbacks=bad_reads=unregisters=0;
 cpu_cgroup_css_free(&tg.css);
 out[0]=bad_reads;out[1]=callbacks;out[2]=unregisters;out[3]=queued;
}
'''
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 control=git('rev-parse','0b81c1a66cdf').strip();p='kernel/sched/core.c'
 cases=list(itertools.product(range(2),repeat=4));report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,cases=len(cases),scope=__doc__,results={},remote_sources_used=[])
 with tempfile.TemporaryDirectory(prefix='cgroup-free-hook-') as tmp:
  for label,src in [('port',(ROOT/p).read_text()),('pre_fix_control',git('show',control+':'+p))]:
   body=function(src,'cpu_cgroup_css_free');code=PRE+body+POST;path=Path(tmp)/(label+'.c');path.write_text(code);lib=path.with_suffix('.so')
   subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',str(path),'-o',str(lib)],check=True)
   probe=ctypes.CDLL(str(lib)).probe;probe.argtypes=[ctypes.c_int]*4+[ctypes.POINTER(ctypes.c_int)];probe.restype=None
   failures=bad=0
   for case in cases:
    out=(ctypes.c_int*4)();probe(*case,out);bad+=out[0];failures+=list(out)!=[0,case[0],1,1]
   report['results'][label]=dict(failures=failures,reads_after_modeled_free=bad,function_sha256=hashlib.sha256(body.encode()).hexdigest(),harness_sha256=hashlib.sha256(code.encode()).hexdigest())
 assert report['results']['port']['failures']==0
 assert report['results']['pre_fix_control']['reads_after_modeled_free']>0
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/cgroup-free-hook-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
