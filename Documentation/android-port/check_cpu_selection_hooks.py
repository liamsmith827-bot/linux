#!/usr/bin/env python3
"""Exercise extracted CPU selection functions with invalid callback outputs.

CPU masks, hotplug eligibility and scheduler locks are host shims. Invalid mask
accesses are counted without dereferencing out-of-range memory. This does not
reproduce an actual kernel fault or validate asynchronous hotplug behavior.
"""
import ctypes,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#define nr_cpu_ids 4U
#define unlikely(x) (x)
#define lockdep_assert_held(x) ((void)0)
#define WF_RQ_SELECTED 64
#define HK_TYPE_KERNEL_NOISE 1
#define fallthrough __attribute__((fallthrough))
#define BUG() abort()
#define printk_deferred(...) ((void)0)
struct cpumask { unsigned bits; };
struct task_struct;
struct sched_class { int (*select_task_rq)(struct task_struct *,int,int); };
struct task_struct { struct cpumask *cpus_ptr; unsigned nr_cpus_allowed; int disabled,cpu,pi_lock; void *mm; char *comm; struct sched_class *sched_class; };
static struct cpumask all={15}, eligible, local, housekeeping, idle, taskmask;
static struct {struct cpumask *idle_cpus_mask;} nohz;
static int callback, proposal, class_cpu, current_cpu, node, invalid_accesses;
static int cpumask_test_cpu(int cpu,const struct cpumask *m) {
 if((unsigned)cpu>=nr_cpu_ids) {invalid_accesses++;return 0;} return !!(m->bits&(1U<<cpu));
}
#define for_each_cpu(i,m) for(i=0;i<(int)nr_cpu_ids;i++) if(cpumask_test_cpu(i,m))
#define for_each_cpu_and(i,a,b) for_each_cpu(i,a) if(cpumask_test_cpu(i,b))
static int cpumask_any(const struct cpumask *m) {int i;for_each_cpu(i,m) return i;return nr_cpu_ids;}
static int is_cpu_allowed(struct task_struct *p,int cpu) {return cpumask_test_cpu(cpu,p->cpus_ptr)&&cpumask_test_cpu(cpu,&eligible);}
static void trace_android_rvh_select_fallback_rq(int cpu,struct task_struct *p,int *dest) {if(callback)*dest=proposal;}
static void trace_android_rvh_find_new_ilb(struct cpumask *m,int *dest) {if(callback)*dest=proposal;}
static const struct cpumask *housekeeping_cpumask(int type) {return &housekeeping;}
static int smp_processor_id(void) {return current_cpu;}
static int idle_cpu(int cpu) {return cpumask_test_cpu(cpu,&idle);}
static int cpu_to_node(int cpu) {return node;}
static const struct cpumask *cpumask_of_node(int nid) {return &all;}
static int cpuset_cpus_allowed_fallback(struct task_struct *p) {return 0;}
static const struct cpumask *task_cpu_fallback_mask(struct task_struct *p) {return &eligible;}
static void do_set_cpus_allowed(struct task_struct *p,const struct cpumask *m) {taskmask=*m;p->cpus_ptr=&taskmask;}
static int task_cpu(struct task_struct *p) {return p->cpu;}
static int is_migration_disabled(struct task_struct *p) {return p->disabled;}
static int printk_ratelimit(void) {return 0;}
static int select_class(struct task_struct *p,int cpu,int flags) {return class_cpu;}
'''
POST=r'''
void probe_task(unsigned affinity,unsigned active,int dest,int cb,int selected,int disabled,int nid,int *out) {
 struct sched_class cls={select_class};
 struct task_struct task={.cpus_ptr=&taskmask,.nr_cpus_allowed=__builtin_popcount(affinity),.disabled=disabled,.cpu=0,.sched_class=&cls};
 int flags=0;
 eligible.bits=active;taskmask.bits=affinity;callback=cb;proposal=dest;class_cpu=selected;node=nid;invalid_accesses=0;
 out[0]=select_fallback_rq(0,&task);out[1]=invalid_accesses;
 taskmask.bits=affinity;invalid_accesses=0;
 out[2]=select_task_rq(&task,0,&flags);out[3]=invalid_accesses;out[4]=flags;
}
void probe_idle(unsigned mask,unsigned hk,unsigned im,int cpu,int cb,int dest,int *out) {
 local.bits=mask;housekeeping.bits=hk;idle.bits=im;current_cpu=cpu;callback=cb;proposal=dest;invalid_accesses=0;nohz.idle_cpus_mask=&local;
 out[0]=find_new_ilb();out[1]=invalid_accesses;
}
'''
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 control=git('rev-parse','3ef8a57a8853').strip()
 report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,results={},remote_sources_used=[])
 candidates=[-3,-1,0,1,2,3,4,5,2147483647]
 tasks=list(itertools.product(range(1,16),range(1,16),candidates,range(2),[-1,0,3,5,2147483647],range(2),[-1,0]))
 idles=list(itertools.product(range(16),range(16),range(16),range(4),range(2),candidates))
 first=lambda mask:next((i for i in range(4) if mask&(1<<i)),-1)
 valid=lambda cpu,mask:0<=cpu<4 and bool(mask&(1<<cpu))
 with tempfile.TemporaryDirectory(prefix='cpu-selection-hooks-') as temp:
  for label,ref in [('port',None),('pre_fix_control',control)]:
   source=lambda p:(ROOT/p).read_text() if ref is None else git('show',ref+':'+p)
   bodies=[function(source('kernel/sched/core.c'),n) for n in ['select_fallback_rq','select_task_rq']]+[function(source('kernel/sched/fair.c'),'find_new_ilb')]
   code=PRE+'\n'.join(bodies)+POST;c=Path(temp)/(label+'.c');c.write_text(code);lib=c.with_suffix('.so')
   subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',str(c),'-o',str(lib)],check=True)
   dll=ctypes.CDLL(str(lib));dll.probe_task.argtypes=[ctypes.c_int]*7+[ctypes.POINTER(ctypes.c_int)];dll.probe_task.restype=None;dll.probe_idle.argtypes=[ctypes.c_int]*6+[ctypes.POINTER(ctypes.c_int)];dll.probe_idle.restype=None
   failures=badaccess=idlefail=0
   for affinity,active,dest,cb,selected,disabled,nid in tasks:
    allowed=affinity&active;fallback=dest if cb and valid(dest,allowed) else first(allowed or active)
    chosen=selected if affinity.bit_count()>1 and not disabled else first(affinity)
    expected=chosen if valid(chosen,allowed) else fallback
    flags=64 if affinity.bit_count()>1 and not disabled else 0
    out=(ctypes.c_int*5)();dll.probe_task(affinity,active,dest,cb,selected,disabled,nid,out)
    failures+=list(out)!=[fallback,0,expected,0,flags];badaccess+=out[1]+out[3]
   for mask,hk,im,cpu,cb,dest in idles:
    acceptable=mask&hk&im&~(1<<cpu)
    expected=-1 if cb and dest<0 else (dest if cb and valid(dest,acceptable) else first(acceptable))
    out=(ctypes.c_int*2)();dll.probe_idle(mask,hk,im,cpu,cb,dest,out)
    idlefail+=list(out)!=[expected,0];badaccess+=out[1]
   report['results'][label]=dict(task_selection_failures=failures,idle_selection_failures=idlefail,modeled_invalid_mask_accesses=badaccess,function_sha256=[hashlib.sha256(b.encode()).hexdigest() for b in bodies])
 report['task_cases']=len(tasks);report['idle_cases']=len(idles)
 assert report['results']['port']['task_selection_failures']==report['results']['port']['idle_selection_failures']==0
 assert report['results']['pre_fix_control']['modeled_invalid_mask_accesses']>0
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/cpu-selection-hooks-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
