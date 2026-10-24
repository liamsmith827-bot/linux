#!/usr/bin/env python3
"""Check SCX veto isolation and the extracted class-transition loop bodies.

Dispatch queues, task iteration, locks, class methods and scoped guard cleanup
are host models. This checks source control flow and notification ordering,
not BPF execution, real scheduling or concurrent lifetime behavior.
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
#include <stddef.h>
#define SCX_TASK_READY 2
#define SCX_SLICE_DFL 100
#define DEQUEUE_SLEEP 1
#define DEQUEUE_DELAYED 2
#define DEQUEUE_NOCLOCK 4
#define DEQUEUE_SAVE 8
#define DEQUEUE_MOVE 16
#define likely(x) (x)
struct sched_class {int id;};
struct rq {int id;};
struct scx_sched {int unused;};
struct task_struct {int id,state,queued,policy,prio;const struct sched_class *sched_class;struct {bool sched_delayed;} se;struct {int slice;} scx;};
struct scx_dispatch_q {struct {int unused;} list;int lock;};
static struct sched_class classes[2];
static struct rq dest,other;
static struct task_struct tasks[4];
static int nr,denied,localmask,remote_allowed,fail_once,selected,removed,callback_skip,desired_class;
static int events,bad_event,guard_depth,changing,exited,changed,iterator;
#define task_rq(p) (((localmask>>((p)->id))&1)?&dest:&other)
#define nldsq_for_each_task(p,dsq) for(p=tasks;p<tasks+nr;p++) if(!(removed&(1<<p->id)))
static void scx_breather(struct rq *rq) {}
static int list_empty(void *l) {return nr==0 || removed==((1<<nr)-1);}
static void raw_spin_lock(int *l) {(*l)++;}
static void raw_spin_unlock(int *l) {(*l)--;}
static void trace_android_vh_scx_task_can_run_on(bool *disallow,struct task_struct *p,struct rq *rq) {if(denied&(1<<p->id))*disallow=true;}
static void task_unlink_from_dsq(struct task_struct *p,struct scx_dispatch_q *dsq) {}
static void move_local_task_to_local_dsq(struct task_struct *p,int flags,struct scx_dispatch_q *dsq,struct rq *rq) {selected=p->id;}
static int task_can_run_on_remote_rq(struct scx_sched *sch,struct task_struct *p,struct rq *rq,bool b) {return !!(remote_allowed&(1<<p->id));}
static int consume_remote_task(struct rq *rq,struct task_struct *p,struct scx_dispatch_q *dsq,struct rq *src) {
 raw_spin_unlock(&dsq->lock);
 if(fail_once==p->id) {removed|=1<<p->id;fail_once=-1;return 0;}
 selected=p->id;return 1;
}
static struct task_struct *scx_task_iter_next_locked(int *sti) {return iterator++ ? NULL:tasks;}
static const struct sched_class *scx_setscheduler_class(struct task_struct *p) {return &classes[desired_class];}
static void trace_android_vh_scx_switch_repeat_skip(struct task_struct *p,bool *skip,int *repeat) {*skip=callback_skip;}
static void trace_android_vh_setscheduler_class(const struct sched_class **c,int *scx,struct task_struct *p,int policy,int prio) {}
static int scx_get_task_state(struct task_struct *p) {return p->state;}
static void update_rq_clock(struct rq *rq) {}
static void dequeue_task(struct rq *rq,struct task_struct *p,int flags) {p->queued=0;p->se.sched_delayed=false;}
struct guard_scope {struct task_struct *p;int once,was_queued;};
static struct guard_scope enter_guard(struct task_struct *p) {struct guard_scope g={p,1,p->queued};p->queued=0;guard_depth++;return g;}
static void leave_guard(struct guard_scope *g) {g->p->queued=g->was_queued;guard_depth--;}
#define scoped_guard(type,p,flags) for(struct guard_scope scope __attribute__((cleanup(leave_guard)))=enter_guard(p);scope.once;scope.once=0)
static void check_class_changing(struct rq *rq,struct task_struct *p,const struct sched_class *old) {changing=1;}
static void trace_android_vh_scx_task_switch_finish(struct task_struct *p,int enable) {events++;bad_event+=!guard_depth || !changing || p->queued || p->sched_class!=&classes[desired_class];}
static void check_class_changed(struct rq *rq,struct task_struct *p,const struct sched_class *old,int prio) {changed++;}
static void scx_exit_task(struct task_struct *p) {exited++;}
'''
POST=r'''
void probe_dispatch(int count,int deny,int local,int remote,int fail,int *out) {
 struct scx_sched sch={0};struct scx_dispatch_q dsq={0};
 nr=count;denied=deny;localmask=local;remote_allowed=remote;fail_once=fail;selected=-1;removed=0;
 for(int i=0;i<4;i++)tasks[i].id=i;
 out[0]=consume_dispatch_q(&sch,&dest,&dsq);out[1]=selected;out[2]=dsq.lock;
}
void probe_transition(int enable,int state,int old,int next,int queued,int delayed,int skip,int *out) {
 tasks[0]=(struct task_struct){.id=0,.state=state,.sched_class=&classes[old],.queued=queued,.se.sched_delayed=delayed};
 desired_class=next;callback_skip=skip;iterator=guard_depth=changing=events=bad_event=changed=exited=0;
 if(enable)loop_enable();else loop_disable();
 out[0]=events;out[1]=bad_event;out[2]=guard_depth;out[3]=changed;out[4]=exited;
 out[5]=tasks[0].sched_class==&classes[next];out[6]=tasks[0].queued;
}
'''

def transition(source,name):
    body=function(source,name)
    start=body.index('\twhile ((p = scx_task_iter_next_locked(&sti))) {',body.index('repeat_iter:'))
    end=body.index('\n\t}\n',start)+len('\n\t}')
    return body[start:end]

def main():
    git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
    control=git('rev-parse','e48d2b13bac4').strip()
    report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,results={},remote_sources_used=[])
    d_cases=list(itertools.product(range(5),range(16),range(16),range(16),range(-1,4)))
    t_cases=list(itertools.product(range(2),range(4),range(2),range(2),range(2),range(2),range(2)))
    with tempfile.TemporaryDirectory(prefix='scx-callback-order-') as temp:
        for label,ref in [('port',None),('pre_fix_control',control)]:
            source=(ROOT/'kernel/sched/ext.c').read_text() if ref is None else git('show',ref+':kernel/sched/ext.c')
            blocks={'dispatch':function(source,'consume_dispatch_q'),'disable':transition(source,'scx_root_disable'),'enable':transition(source,'scx_root_enable_workfn')}
            code=PRE+blocks['dispatch']
            for n in ['disable','enable']:
                code+='\nstatic void loop_'+n+'(void) {int sti=0,repeat=0;struct task_struct *p;\n'+blocks[n]+'\n}\n'
            c=Path(temp)/(label+'.c');c.write_text(code+POST);lib=c.with_suffix('.so')
            subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',str(c),'-o',str(lib)],check=True)
            dll=ctypes.CDLL(str(lib));dll.probe_dispatch.argtypes=[ctypes.c_int]*5+[ctypes.POINTER(ctypes.c_int)];dll.probe_dispatch.restype=None;dll.probe_transition.argtypes=[ctypes.c_int]*7+[ctypes.POINTER(ctypes.c_int)];dll.probe_transition.restype=None
            dfail=tfail=0
            for count,deny,local,remote,fail in d_cases:
                eligible=((1<<count)-1)&~deny&(local|remote)
                first=next((i for i in range(count) if eligible&(1<<i)),-1)
                if first==fail and first>=0 and not local&(1<<first):
                    eligible&=~(1<<first)
                expected=next((i for i in range(count) if eligible&(1<<i)),-1)
                out=(ctypes.c_int*3)();dll.probe_dispatch(count,deny,local,remote,fail,out);dfail+=list(out)!=[int(expected>=0),expected,0]
            for enable,state,old,nextcls,queued,delayed,skip in t_cases:
                run=not skip and (not enable or state==2)
                expected=[int(run),0,0,int(run),int(run and not enable),int(nextcls==old or run),0 if run and old!=nextcls and delayed else queued]
                out=(ctypes.c_int*7)();dll.probe_transition(enable,state,old,nextcls,queued,delayed,skip,out);tfail+=list(out)!=expected
            report['results'][label]=dict(dispatch_failures=dfail,transition_failures=tfail,block_sha256={k:hashlib.sha256(v.encode()).hexdigest() for k,v in blocks.items()})
    report.update(dispatch_cases=len(d_cases),transition_cases=len(t_cases),compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0])
    assert report['results']['port']['dispatch_failures']==report['results']['port']['transition_failures']==0
    assert report['results']['pre_fix_control']['dispatch_failures']>0 and report['results']['pre_fix_control']['transition_failures']>0
    (ROOT/'Documentation/android-port/evidence/scx-callback-order-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
