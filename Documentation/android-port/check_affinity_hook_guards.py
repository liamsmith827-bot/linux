#!/usr/bin/env python3
"""Test extracted affinity selection, syscall authorization and SCX idle updates.

Host shims model masks, credentials/LSM outcomes and balanced ownership. They do
not execute actual scheduler migration, kernel LSMs, RCU, or concurrent hotplug.
"""
import ctypes, hashlib, itertools, json, subprocess, tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
COMMON=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <errno.h>
struct cpumask { unsigned bits; };
static int bad_index;
static bool cpumask_test_cpu(unsigned cpu, const struct cpumask *m) {
 if(cpu>=4) {bad_index++;return false;} return !!(m->bits & (1U<<cpu));
}
'''
DEST=r'''
#define PF_KTHREAD 1
#define PF_NO_SETAFFINITY 2
#define SCA_CHECK 1
#define SCA_MIGRATE_ENABLE 2
#define SCA_USER 4
#define __releases(x)
#define WARN_ON_ONCE(x) (x)
#define swap(a,b) do { struct cpumask *tmp=(a);(a)=(b);(b)=tmp; } while(0)
struct task_struct { unsigned flags;bool disabled;struct cpumask cpus_mask;struct cpumask *user_cpus_ptr; };
struct affinity_context { const struct cpumask *new_mask;struct cpumask *user_mask;unsigned flags; };
struct rq { int unused; };struct rq_flags { int unused; };
static struct cpumask active,online,possible={15};
static const struct cpumask *cpu_active_mask=&active,*cpu_online_mask=&online;
static const unsigned nr_cpu_ids=4;
static struct task_struct *current;
static int selected,sets,moves,unlocks;
static const struct cpumask *task_cpu_possible_mask(struct task_struct *p) {return &possible;}
static void update_rq_clock(struct rq *rq) {}
static bool is_migration_disabled(struct task_struct *p) {return p->disabled;}
static bool cpumask_subset(const struct cpumask *a,const struct cpumask *b) {return !(a->bits & ~b->bits);}
static bool cpumask_equal(const struct cpumask *a,const struct cpumask *b) {return a->bits==b->bits;}
static void trace_android_vh_sca_migrate_same(struct task_struct *p,struct affinity_context *ctx) {}
static int task_cpu(struct task_struct *p) {return 0;}
static unsigned cpumask_any_and_distribute(const struct cpumask *a,const struct cpumask *b) {
 for(unsigned i=0;i<4;i++) if((a->bits & b->bits)&(1U<<i)) return i;
 return 4;
}
static void trace_android_rvh_set_cpus_allowed_by_task(const struct cpumask *valid,const struct cpumask *new,struct task_struct *p,unsigned *dst) {if(selected!=6)*dst=(unsigned)selected;}
static void __do_set_cpus_allowed(struct task_struct *p,struct affinity_context *ctx) {sets++;}
static int affine_move_task(struct rq *rq,struct task_struct *p,struct rq_flags *rf,unsigned dest,unsigned flags) {moves++;unlocks++;return 0;}
static void task_rq_unlock(struct rq *rq,struct task_struct *p,struct rq_flags *rf) {unlocks++;}
'''
DEST_POST=r'''
void probe(int on,int ac,int nm,int dest,int kt,int md,int *out) {
 online.bits=on;active.bits=ac;struct cpumask new={nm};
 struct task_struct p={.flags=kt?PF_KTHREAD:0,.disabled=md,.cpus_mask={nm^15}};
 struct affinity_context ctx={.new_mask=&new};struct rq rq;struct rq_flags rf;
 selected=dest;sets=moves=unlocks=bad_index=0;
 out[0]=__set_cpus_allowed_ptr_locked(&p,&ctx,&rq,&rf);
 out[1]=sets;out[2]=moves;out[3]=unlocks;out[4]=bad_index;
}
'''
AUTH=r'''
#define sched_setaffinity audit_sched_setaffinity
#define PF_NO_SETAFFINITY 1
#define CAP_SYS_NICE 23
#define NUMA_NO_NODE (-1)
#define SCA_USER 1
struct cred {void *user_ns;};
struct task_struct {unsigned flags;};
struct affinity_context {const struct cpumask *new_mask;struct cpumask *user_mask;unsigned flags;};
static struct task_struct task;static struct cred cred;
static struct cpumask storage;
static int exists,owner,capability,lsm,skip,allocfail,attacherror,postret;
static int refs,rcu,lsmcalls,earlycalls,postcalls,attached,allocs,freed;
static struct task_struct *find_task(pid_t pid) {if(!exists)return NULL;refs++;return &task;}
static void release_task(struct task_struct **p) {if(*p)refs--;}
#define CLASS(name,p) struct task_struct *p __attribute__((cleanup(release_task))) = find_task
struct guard_type {int unused;};
static struct guard_type enter_guard(void) {rcu++;return (struct guard_type){0};}
static void drop_guard(struct guard_type *g) {rcu--;}
#define guard(name) struct guard_type g __attribute__((cleanup(drop_guard))) = enter_guard
static bool check_same_owner(struct task_struct *p) {return owner;}
static struct cred *__task_cred(struct task_struct *p) {return &cred;}
static bool ns_capable(void *ns,int cap) {return capability;}
static int security_task_setscheduler(struct task_struct *p) {lsmcalls++;return lsm?-EACCES:0;}
static void trace_android_vh_sched_setaffinity_early(struct task_struct *p,const struct cpumask *m,bool *v) {earlycalls++;*v=skip;}
static struct cpumask *alloc_user_cpus_ptr(int node) {if(allocfail)return NULL;allocs++;return &storage;}
static void cpumask_copy(struct cpumask *a,const struct cpumask *b) {a->bits=b->bits;}
static int __sched_setaffinity(struct task_struct *p,struct affinity_context *a) {attached++;return attacherror?-EINVAL:0;}
static void trace_android_rvh_sched_setaffinity(struct task_struct *p,const struct cpumask *m,int *v) {postcalls++;if(postret!=123)*v=postret;}
static void kfree(void *p) {freed++;}
'''
AUTH_POST=r'''
void probe(int found,int noaff,int own,int cap,int deny,int veto,int fail,int err,int post,int *out) {
 exists=found;task.flags=noaff?PF_NO_SETAFFINITY:0;owner=own;capability=cap;lsm=deny;skip=veto;allocfail=fail;attacherror=err;postret=post;
 refs=rcu=lsmcalls=earlycalls=postcalls=attached=allocs=freed=0;struct cpumask mask={3};
 out[0]=sched_setaffinity(1,&mask);out[1]=refs;out[2]=rcu;out[3]=lsmcalls;out[4]=earlycalls;out[5]=attached;out[6]=postcalls;out[7]=allocs-freed;
}
'''
IDLE=r'''
#define CONFIG_SCHED_SMT 1
static struct cpumask cpus,smts,cores[2]={{3},{12}};
struct idle_map {struct cpumask *cpu,*smt;};static struct idle_map map={&cpus,&smts};
static int policy,smt_enabled,hooks;
static int scx_cpu_node_if_enabled(int cpu) {return 0;}
static struct idle_map *idle_cpumask(int node) {return &map;}
static void trace_android_vh_scx_cpu_allowed(void *p,int cpu,bool *allow) {hooks++;*allow=policy;}
static void assign_cpu(int cpu,struct cpumask *m,bool set) {if(set)m->bits|=1U<<cpu;else m->bits&=~(1U<<cpu);}
static bool sched_smt_active(void) {return smt_enabled;}
static const struct cpumask *cpu_smt_mask(int cpu) {return &cores[cpu/2];}
static bool cpumask_subset(const struct cpumask *a,const struct cpumask *b) {return !(a->bits&~b->bits);}
static void cpumask_or(struct cpumask *a,const struct cpumask *b,const struct cpumask *c) {a->bits=b->bits|c->bits;}
static void cpumask_andnot(struct cpumask *a,const struct cpumask *b,const struct cpumask *c) {a->bits=b->bits&~c->bits;}
'''
IDLE_POST=r'''
void probe(int cpu,int cm,int sm,int idle,int allow,int active,int *out) {
 cpus.bits=cm;smts.bits=sm;policy=allow;smt_enabled=active;hooks=0;
 update_builtin_idle(cpu,idle);out[0]=cpus.bits;out[1]=smts.bits;out[2]=hooks;
}
'''
def dest_expected(c):
 on,ac,new,dest,kt,md=c;valid=on if kt or md else ac
 if dest==6: dest=next((i for i in range(4) if valid & new & (1<<i)),4)
 good=0<=dest<4 and bool(valid & new & (1<<dest))
 return [0 if good else -22,int(good),int(good),1,0]
def auth_expected(c):
 found,noaff,own,cap,deny,veto,fail,err,post=c
 ret=-3 if not found else -22 if noaff else -1 if not(own or cap) else None
 if ret is not None:return [ret,0,0,0,0,0,0,0]
 if deny:return [-13,0,0,1,0,0,0,0]
 if veto:return [0,0,0,1,1,0,0,0]
 if fail:return [-12,0,0,1,1,0,0,0]
 return [post if post!=123 else -22 if err else 0,0,0,1,1,1,1,0]
def idle_expected(c):
 cpu,cm,sm,idle,allow,active=c;usable=idle and allow;bit=1<<cpu;core=3<<(2*(cpu//2));cm=(cm|bit) if usable else(cm&~bit)
 if active:
  if not usable: sm &= ~core
  elif cm&core==core: sm |= core
 return [cm,sm,idle]
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 control=git('rev-parse','97a12e6cd2f3').strip()
 cases_dest=[c for c in itertools.product(range(16),range(16),range(16),[0,1,2,3,4,-1,6],range(2),range(2)) if not(c[1]&~c[0])]
 suites=[('destination','kernel/sched/core.c','__set_cpus_allowed_ptr_locked',DEST,DEST_POST,cases_dest,dest_expected,5),('authorization','kernel/sched/syscalls.c','sched_setaffinity',AUTH,AUTH_POST,list(itertools.product(*([range(2)]*8),[-1,0,123])),auth_expected,8),('idle_masks','kernel/sched/ext_idle.c','update_builtin_idle',IDLE,IDLE_POST,list(itertools.product(range(4),range(16),range(16),range(2),range(2),range(2))),idle_expected,3)]
 report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,suites={},remote_sources_used=[])
 with tempfile.TemporaryDirectory(prefix='affinity-hooks-') as tmp:
  for name,p,n,pre,post,cases,expected,width in suites:
   outreport=dict(cases=len(cases),results={});report['suites'][name]=outreport
   for label,src in [('port',(ROOT/p).read_text()),('pre_fix_control',git('show',control+':'+p))]:
    body=function(src,n);code=COMMON+pre+body+post;path=Path(tmp)/(name+'-'+label+'.c');path.write_text(code);lib=path.with_suffix('.so')
    subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror','-Wno-unused-function',str(path),'-o',str(lib)],check=True)
    probe=ctypes.CDLL(str(lib)).probe;probe.argtypes=[ctypes.c_int]*len(cases[0])+[ctypes.POINTER(ctypes.c_int)];probe.restype=None
    failures=0;example=None
    for case in cases:
     out=(ctypes.c_int*width)();probe(*case,out);want=expected(case)
     if list(out)!=want:
      failures+=1
      if example is None:example=dict(input=case,actual=list(out),expected=want)
    outreport['results'][label]=dict(failures=failures,example=example,function_sha256=hashlib.sha256(body.encode()).hexdigest(),harness_sha256=hashlib.sha256(code.encode()).hexdigest())
   assert outreport['results']['port']['failures']==0,name
   assert outreport['results']['pre_fix_control']['failures']>0,name
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/affinity-hook-guards-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
