#!/usr/bin/env python3
"""Exercise extracted fair selection and delayed-dequeue hooks with host shims.

Checks donor-retry control flow and native exclusions for delayed dequeue. This
is not kernel scheduling, concurrent locking, a fairness test or an exploit.
"""
import ctypes,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
COMMON=r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define unlikely(x) (x)
'''
PICK=r'''
#define CONFIG_FAIR_GROUP_SCHED 1
#define RETRY_TASK ((struct task_struct *)-1L)
struct sched_class {int unused;};static struct sched_class fair_sched_class,other_class;
struct task_struct;
struct sched_entity {struct task_struct *task;int depth;};
struct task_struct {struct sched_class *sched_class;struct sched_entity se;};
struct rq {struct task_struct *donor;};struct rq_flags {int unused;};struct cfs_rq {int unused;};
static struct cfs_rq cfs;
static struct task_struct old,a,b,replacement;
static struct rq *active_rq;
static int before_choice,before_change,pick_choice,after_choice,after_change,balance_result,balance_change;
static int rounds,stale,balances;
static void trace_android_rvh_before_pick_task_fair(struct rq *rq,struct task_struct **p,struct task_struct *prev,struct rq_flags *rf) {
 rounds++;if(prev!=rq->donor)stale++;
 if(rounds==1){if(before_choice)*p=&a;if(before_change)rq->donor=&replacement;}
}
static struct task_struct *pick_task_fair(struct rq *rq,struct rq_flags *rf) {return rounds>1 || pick_choice ? &a : NULL;}
static void trace_android_rvh_replace_next_task_fair(struct rq *rq,struct task_struct **p,struct task_struct *prev) {
 if(prev!=rq->donor)stale++;
 if(rounds==1){if(after_choice>=0)*p=after_choice==0?NULL:after_choice==1?&a:&b;if(after_change)rq->donor=&replacement;}
}
static void __put_prev_set_next_dl_server(struct rq *rq,struct task_struct *prev,struct task_struct *p) {if(prev!=rq->donor)stale++;}
static struct cfs_rq *is_same_group(struct sched_entity *a,struct sched_entity *b) {return &cfs;}
static struct cfs_rq *cfs_rq_of(struct sched_entity *se) {return &cfs;}
static void put_prev_entity(struct cfs_rq *c,struct sched_entity *se) {if(se->task!=active_rq->donor)stale++;}
static struct sched_entity *parent_entity(struct sched_entity *se) {return se;}
static void set_next_entity(struct cfs_rq *c,struct sched_entity *se,bool first) {}
static void __set_next_task_fair(struct rq *rq,struct task_struct *p,bool first) {}
static void put_prev_set_next_task(struct rq *rq,struct task_struct *prev,struct task_struct *p) {if(prev!=rq->donor)stale++;}
static int sched_balance_newidle(struct rq *rq,struct rq_flags *rf) {balances++;if(balance_change)rq->donor=&replacement;return balance_result;}
'''
PICK_POST=r'''
void probe(int fair,int bc,int bm,int pc,int ac,int am,int br,int rf_present,int changed,int *out) {
 old=(struct task_struct){.sched_class=fair?&fair_sched_class:&other_class};old.se.task=&old;
 a=(struct task_struct){.sched_class=&fair_sched_class};a.se.task=&a;
 b=(struct task_struct){.sched_class=&fair_sched_class};b.se.task=&b;
 replacement=(struct task_struct){.sched_class=&fair_sched_class};replacement.se.task=&replacement;
 static struct rq rq;rq=(struct rq){.donor=&old};struct rq_flags rf;active_rq=&rq;
 before_choice=bc;before_change=bm;pick_choice=pc;after_choice=ac;after_change=am;balance_result=br;balance_change=changed;
 rounds=stale=balances=0;
 struct task_struct *p=pick_next_task_fair(&rq,rf_present?&rf:NULL);
 out[0]=p==RETRY_TASK?-1:p==NULL?0:p==&a?1:p==&b?2:99;
 out[1]=stale;out[2]=rounds;out[3]=balances;
}
'''
DEQUEUE=r'''
#define DEQUEUE_SLEEP 1
#define DEQUEUE_SPECIAL 2
#define DEQUEUE_THROTTLE 4
#define DEQUEUE_DELAYED 8
#define UPDATE_TG 1
#define DO_DETACH 2
#define WARN_ON_ONCE(x) ((void)(x))
#define sched_feat(name) feat_##name
static int feat_DELAY_DEQUEUE,feat_PLACE_REL_DEADLINE;
struct task_struct {bool migrating;};
struct sched_entity {bool sched_delayed,on_rq,is_task;uint64_t deadline,vruntime;int rel_deadline;struct task_struct task;};
struct cfs_rq {struct sched_entity *curr;int nr_queued;};
static int eligible,callback,hooks,delayed,removed,finished;
static void update_curr(struct cfs_rq *c) {}
static void clear_buddies(struct cfs_rq *c,struct sched_entity *s) {}
static void trace_android_rvh_dequeue_entity_delayed(struct cfs_rq *c,struct sched_entity *s,bool *delay) {hooks++;if(callback>=0)*delay=callback;}
static bool entity_eligible(struct cfs_rq *c,struct sched_entity *s) {return eligible;}
static void update_load_avg(struct cfs_rq *c,struct sched_entity *s,int action) {}
static void set_delayed(struct sched_entity *s) {s->sched_delayed=true;delayed++;}
static bool entity_is_task(struct sched_entity *s) {return s->is_task;}
static struct task_struct *task_of(struct sched_entity *s) {return &s->task;}
static bool task_on_rq_migrating(struct task_struct *p) {return p->migrating;}
static void se_update_runnable(struct sched_entity *s) {}
static void update_stats_dequeue_fair(struct cfs_rq *c,struct sched_entity *s,int flags) {}
static void update_entity_lag(struct cfs_rq *c,struct sched_entity *s) {}
static void __dequeue_entity(struct cfs_rq *c,struct sched_entity *s) {removed++;}
static void account_entity_dequeue(struct cfs_rq *c,struct sched_entity *s) {}
static void return_cfs_rq_runtime(struct cfs_rq *c) {}
static void update_cfs_group(struct sched_entity *s) {}
static void finish_delayed_dequeue_entity(struct sched_entity *s) {finished++;}
static void update_idle_cfs_rq_clock_pelt(struct cfs_rq *c) {}
'''
DEQUEUE_POST=r'''
void probe(int flags,int feat,int elig,int cb,int task,int migrating,int *out) {
 feat_DELAY_DEQUEUE=feat;feat_PLACE_REL_DEADLINE=1;eligible=elig;callback=cb;hooks=delayed=removed=finished=0;
 struct sched_entity se={.sched_delayed=!!(flags&DEQUEUE_DELAYED),.on_rq=true,.is_task=task,.deadline=8,.vruntime=3,.task={.migrating=migrating}};
 struct cfs_rq cfs={.nr_queued=1};
 out[0]=dequeue_entity(&cfs,&se,flags);out[1]=hooks;out[2]=delayed;out[3]=removed;out[4]=finished;out[5]=se.on_rq;
}
'''
def pick_expected(c):
 fair,bc,bm,pc,ac,am,br,rf,change=c
 if bm:return [-1,0,1,0]
 if bc:choice=1
 else:
  if am:return [-1,0,1,0]
  choice=pc if ac==-1 else ac
 if choice:return [choice,0,1,0]
 if not rf:return [0,0,1,0]
 return [-1,0,1,1] if br<0 else [0,0,1,1] if br==0 else [1,0,2,1]
def dequeue_expected(c):
 flags,feat,elig,cb,task,migrating=c
 already=bool(flags&8);ordinary_sleep=bool(flags&1) and not(flags&6)
 wait=not already and ordinary_sleep and feat and not elig and cb!=0
 return [int(not wait),int(not already),int(wait),int(not wait),int(already),int(wait)]
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 control=git('rev-parse','53f6fb1d78a7').strip();p='kernel/sched/fair.c'
 suites=[('selection','pick_next_task_fair','static struct task_struct *\n',PICK,PICK_POST,list(itertools.product(range(2),range(2),range(2),range(2),[-1,0,1,2],range(2),[-1,0,1],range(2),range(2))),pick_expected,4),('delayed_dequeue','dequeue_entity','static bool\n',DEQUEUE,DEQUEUE_POST,list(itertools.product(range(16),range(2),range(2),[-1,0,1],range(2),range(2))),dequeue_expected,6)]
 report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,suites={},remote_sources_used=[])
 with tempfile.TemporaryDirectory(prefix='fair-hooks-') as tmp:
  for label,n,prefix,pre,post,cases,expected,width in suites:
   result=dict(cases=len(cases),results={});report['suites'][label]=result
   for version,src in [('port',(ROOT/p).read_text()),('pre_fix_control',git('show',control+':'+p))]:
    body=function(src,n);code=COMMON+pre+prefix+body+post;path=Path(tmp)/(label+'-'+version+'.c');path.write_text(code);lib=path.with_suffix('.so')
    subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',str(path),'-o',str(lib)],check=True)
    probe=ctypes.CDLL(str(lib)).probe;probe.argtypes=[ctypes.c_int]*len(cases[0])+[ctypes.POINTER(ctypes.c_int)];probe.restype=None
    failures=0;example=None
    for case in cases:
     out=(ctypes.c_int*width)();probe(*case,out);want=expected(case)
     if list(out)!=want:
      failures+=1
      if example is None:example=dict(input=case,actual=list(out),expected=want)
    result['results'][version]=dict(failures=failures,example=example,function_sha256=hashlib.sha256(body.encode()).hexdigest(),harness_sha256=hashlib.sha256(code.encode()).hexdigest())
   assert result['results']['port']['failures']==0,(label,result['results']['port']['example'])
   assert result['results']['pre_fix_control']['failures']>0,label
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/fair-hook-guards-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
