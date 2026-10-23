#!/usr/bin/env python3
"""Extract current RT CPU selector; model cpupri masks and NULL proxy owner.

This checks callback result eligibility and no-override selection, not real
priority races, hotplug, CPU distribution, or proxy-chain locking.
"""
import ctypes,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
#define nr_cpu_ids 4U
#define unlikely(x) (x)
#define IS_ENABLED(x) 1
#define SD_WAKE_AFFINE 1
struct cpumask {unsigned bits;};
struct cpupri {int unused;};
struct root_domain {struct cpupri cpupri;};
struct rq {struct root_domain *rd;};
struct task_struct {struct cpumask cpus_mask;int nr_cpus_allowed,cpu;};
struct sched_domain {int flags;struct cpumask span;};
static struct root_domain root;
static struct rq rq={&root};
static struct cpumask scratch,active,available;
static struct cpumask *local_cpu_mask;
static struct sched_domain domain;
static int has_domain,callback,proposal,mask_reads,invalid_reads;
#define this_cpu_cpumask_var_ptr(x) (x)
static int smp_processor_id(void) {return 0;}
static int sched_asym_cpucap_active(void) {return 0;}
static struct rq *task_rq(struct task_struct *p) {return &rq;}
static int task_cpu(struct task_struct *p) {return p->cpu;}
static int cpumask_test_cpu(int cpu,const struct cpumask *m) {mask_reads++;if((unsigned)cpu>=nr_cpu_ids){invalid_reads++;return 0;}return !!(m->bits&(1U<<cpu));}
static inline int cpu_active(int cpu) {return cpumask_test_cpu(cpu,&active);}
static bool rt_task_fits_cpu(struct task_struct *p,int cpu) {return true;}
static int cpupri_find(struct cpupri *cp,struct task_struct *sched,struct task_struct *exec,struct cpumask *mask) {mask->bits=available.bits&active.bits&(exec?exec->cpus_mask.bits:15);return !!mask->bits;}
static int cpupri_find_fitness(struct cpupri *cp,struct task_struct *sched,struct task_struct *exec,struct cpumask *mask,bool (*fits)(struct task_struct*,int)) {return cpupri_find(cp,sched,exec,mask);}
static void trace_android_rvh_find_lowest_rq(struct task_struct *sched,struct task_struct *exec,struct cpumask *mask,int ret,int *cpu) {if(callback)*cpu=proposal;}
static void rcu_read_lock(void) {}
static void rcu_read_unlock(void) {}
#define for_each_domain(cpu,sd) for(sd=has_domain?&domain:0;sd;sd=0)
static const struct cpumask *sched_domain_span(struct sched_domain *sd) {return &sd->span;}
static int cpumask_any_and_distribute(const struct cpumask *a,const struct cpumask *b) {for(int i=0;i<4;i++)if((a->bits&b->bits)&(1U<<i))return i;return nr_cpu_ids;}
static int cpumask_any_distribute(const struct cpumask *a) {return cpumask_any_and_distribute(a,a);}
'''
POST=r'''
void probe(int avail,int on,int owner,int has_owner,int allocated,int cb,int value,int dom,int *out) {
 struct task_struct donor={.cpus_mask={15},.nr_cpus_allowed=4,.cpu=2};
 struct task_struct exec={.cpus_mask={owner},.nr_cpus_allowed=__builtin_popcount((unsigned)owner),.cpu=1};
 available.bits=avail;active.bits=on;local_cpu_mask=allocated?&scratch:0;callback=cb;proposal=value;has_domain=dom;domain.flags=SD_WAKE_AFFINE;domain.span.bits=3;invalid_reads=mask_reads=0;
 out[0]=find_lowest_rq(&donor,has_owner?&exec:0);out[1]=invalid_reads;
}
'''
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 control=git('rev-parse','e496198e4e74').strip();p='kernel/sched/rt.c'
 cases=list(itertools.product(range(16),[0,1,3,7,15],[0,1,3,5,15],range(2),range(2),range(2),[-3,-1,0,1,2,3,4,5,2147483647],range(2)))
 report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,cases=len(cases),results={},remote_sources_used=[])
 first=lambda m:next((i for i in range(4) if m&(1<<i)),-1)
 with tempfile.TemporaryDirectory(prefix='rt-selection-hook-') as temp:
  for label,src in [('port',(ROOT/p).read_text()),('pre_fix_control',git('show',control+':'+p))]:
   body=function(src,'find_lowest_rq');code=PRE+body+POST;c=Path(temp)/(label+'.c');c.write_text(code);lib=c.with_suffix('.so')
   subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',str(c),'-o',str(lib)],check=True)
   dll=ctypes.CDLL(str(lib));dll.probe.argtypes=[ctypes.c_int]*8+[ctypes.POINTER(ctypes.c_int)];dll.probe.restype=None
   failures=unsafe=bad=0
   for av,on,owner,has_owner,allocated,cb,value,dom in cases:
    allowed=on&(owner if has_owner else 15);mask=av&allowed
    if not allocated or (has_owner and owner.bit_count()==1):expect=-1
    elif cb and 0<=value<4 and allowed&(1<<value):expect=value
    elif not mask:expect=-1
    elif mask&4:expect=2
    elif mask&1:expect=0
    elif dom and mask&3:expect=first(mask&3)
    else:expect=first(mask)
    out=(ctypes.c_int*2)();dll.probe(av,on,owner,has_owner,allocated,cb,value,dom,out)
    failures+=list(out)!=[expect,0];bad+=out[1]
    unsafe+=out[0]>=0 and (out[0]>=4 or not allowed&(1<<out[0]))
   report['results'][label]=dict(failures=failures,ineligible_cpu_results=unsafe,modeled_invalid_mask_reads=bad,function_sha256=hashlib.sha256(body.encode()).hexdigest())
 assert report['results']['port']['failures']==0
 assert report['results']['pre_fix_control']['ineligible_cpu_results']>0
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/rt-selection-hook-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
