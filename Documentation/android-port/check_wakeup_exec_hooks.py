#!/usr/bin/env python3
"""Extract wake-list and exec selection paths with host eligibility/lock shims.

Does not execute IPIs, CPU stoppers, real SCX callbacks, hotplug or LSM behavior.
Invalid mask/per-CPU accesses are counted without accessing invalid memory.
"""
import ctypes,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
#define CONFIG_SMP 1
#define nr_cpu_ids 4U
#define unlikely(x) (x)
#define WF_EXEC 4
struct cpumask {unsigned bits;};
struct task_struct;
struct sched_class {int (*select_task_rq)(struct task_struct *,int,int);};
struct task_struct {struct sched_class *sched_class;struct cpumask *cpus_ptr;int pi_lock;};
struct rq {int nr_running;};
struct migration_arg {struct task_struct *task;int dest_cpu;};
static struct sched_class stop_sched_class,normal_class;
static struct cpumask online,affinity;
static struct task_struct task;
static struct task_struct *current=&task;
static struct rq rq;
static int scx,feature,force,shared,dest,skip,locks,invalid,queues,clocks,migrations,bad_lock,destination;
static int cpumask_test_cpu(int cpu,const struct cpumask *m) {if((unsigned)cpu>=nr_cpu_ids){invalid++;return 0;}return !!(m->bits&(1U<<cpu));}
static bool cpu_active(int cpu) {return cpumask_test_cpu(cpu,&online);}
static bool task_allowed_on_cpu(struct task_struct *p,int cpu) {return cpumask_test_cpu(cpu,p->cpus_ptr);}
static bool scx_allow_ttwu_queue(struct task_struct *p) {return scx;}
static int smp_processor_id(void) {return 0;}
static bool cpus_share_cache(int a,int b) {return a==b||shared;}
static struct rq *cpu_rq(int cpu) {if((unsigned)cpu>=nr_cpu_ids)invalid++;return &rq;}
#define sched_feat(x) feature
static void trace_android_rvh_ttwu_cond(int cpu,bool *cond) {*cond=force;}
static void sched_clock_cpu(int cpu) {clocks++;if((unsigned)cpu>=nr_cpu_ids)invalid++;}
static void __ttwu_queue_wakelist(struct task_struct *p,int cpu,int flags) {queues++;if((unsigned)cpu>=nr_cpu_ids)invalid++;}
static void trace_android_rvh_sched_exec(bool *cond) {*cond=skip;}
static int task_cpu(struct task_struct *p) {return 0;}
static int select_class(struct task_struct *p,int cpu,int flags) {bad_lock+=locks!=1;return dest;}
struct guard {int active;};
static void release_guard(struct guard *g) {locks--;}
#define scoped_guard(type,arg) for(struct guard g __attribute__((cleanup(release_guard)))={(locks++,1)};g.active;g.active=0)
static void migration_cpu_stop(void) {}
static void stop_one_cpu(int cpu,void (*fn)(void),struct migration_arg *arg) {migrations++;bad_lock+=locks!=0;destination=arg->dest_cpu;}
'''
POST=r'''
void probe_wake(int cpu,int active,int allowed,int permit,int stop,int ft,int override,int share,int running,int *out) {
 online.bits=active;affinity.bits=allowed;task.cpus_ptr=&affinity;task.sched_class=stop?&stop_sched_class:&normal_class;scx=permit;feature=ft;force=override;shared=share;rq.nr_running=running;invalid=queues=clocks=0;
 out[0]=ttwu_queue_wakelist(&task,cpu,0);out[1]=queues;out[2]=clocks;out[3]=invalid;
}
void probe_exec(int choice,int active,int allowed,int veto,int *out) {
 normal_class.select_task_rq=select_class;task.sched_class=&normal_class;task.cpus_ptr=&affinity;online.bits=active;affinity.bits=allowed;dest=choice;skip=veto;locks=invalid=migrations=bad_lock=0;destination=-1;
 sched_exec();out[0]=migrations;out[1]=destination;out[2]=locks;out[3]=bad_lock;out[4]=invalid;
}
'''
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 old=git('rev-parse','f95d29516a28').strip();p='kernel/sched/core.c'
 wake_cases=list(itertools.product([-1,0,1,2,3,4,2147483647],[0,1,3,15],[0,1,3,15],range(2),range(2),range(2),range(2),range(2),[0,2]))
 exec_cases=list(itertools.product([-1,0,1,2,3,4,2147483647],range(16),range(16),range(2)))
 report=dict(source_head=git('rev-parse','HEAD').strip(),control=old,scope=__doc__,wake_cases=len(wake_cases),exec_cases=len(exec_cases),results={},remote_sources_used=[])
 with tempfile.TemporaryDirectory(prefix='wakeup-exec-hooks-') as temp:
  for label,src in [('port',(ROOT/p).read_text()),('pre_fix_control',git('show',old+':'+p))]:
   names=['ttwu_queue_cond','ttwu_queue_wakelist','sched_exec']
   if label=='port':names.insert(0,'ttwu_queue_allowed')
   bodies=[function(src,n) for n in names];code=PRE+'\n'.join(bodies)+POST;c=Path(temp)/(label+'.c');c.write_text(code);lib=c.with_suffix('.so')
   subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror','-Wno-unused-function',str(c),'-o',str(lib)],check=True)
   dll=ctypes.CDLL(str(lib));dll.probe_wake.argtypes=[ctypes.c_int]*9+[ctypes.POINTER(ctypes.c_int)];dll.probe_wake.restype=None;dll.probe_exec.argtypes=[ctypes.c_int]*4+[ctypes.POINTER(ctypes.c_int)];dll.probe_exec.restype=None
   wf=ef=bad=0
   for cpu,active,allowed,permit,stop,ft,override,share,running in wake_cases:
    eligible=0<cpu<4 and active&(1<<cpu) and allowed&(1<<cpu) and permit and not stop
    expect=int(bool(eligible and (override or (ft and (not share or not running)))))
    out=(ctypes.c_int*4)();dll.probe_wake(cpu,active,allowed,permit,stop,ft,override,share,running,out);wf+=list(out)!=[expect,expect,expect,0];bad+=out[3]
   for choice,active,allowed,veto in exec_cases:
    migrate=int(bool(not veto and 0<choice<4 and active&(1<<choice) and allowed&(1<<choice)))
    out=(ctypes.c_int*5)();dll.probe_exec(choice,active,allowed,veto,out);ef+=list(out)!=[migrate,choice if migrate else -1,0,0,0];bad+=out[4]
   report['results'][label]=dict(wake_failures=wf,exec_failures=ef,modeled_invalid_accesses=bad,function_sha256=dict(zip(names,[hashlib.sha256(b.encode()).hexdigest() for b in bodies])))
 assert report['results']['port']['wake_failures']==report['results']['port']['exec_failures']==0
 assert report['results']['pre_fix_control']['wake_failures']>0 and report['results']['pre_fix_control']['exec_failures']>0
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/wakeup-exec-hooks-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
