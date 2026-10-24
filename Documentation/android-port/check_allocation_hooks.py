#!/usr/bin/env python3
"""Host checks of extracted workqueue allocation and cpuidle entry prefixes.

Mocks check allocation shape, cleanup and callback-adjusted limits. This is not
kernel execution, a scheduler test or proof of arbitrary vendor callback safety.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from check_scx_donor_retry import function
ROOT = Path(__file__).resolve().parents[2]
OLD = '4bc26919b7d8'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
def source(ref, path):
    return (ROOT/path).read_text() if ref == 'worktree' else subprocess.check_output(
        ['git', 'show', ref+':'+path], cwd=ROOT, text=True)
PRE = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#define WQ_UNBOUND 1U
#define WQ_BH 2U
#define WQ_HIGHPRI 4U
#define WQ_POWER_EFFICIENT 8U
#define WQ_SYSFS 16U
#define __WQ_BH_ALLOWS (WQ_BH | WQ_HIGHPRI)
#define WQ_DFL_ACTIVE 256
#define WQ_DFL_MIN_ACTIVE 8
#define WQ_NAME_LEN 24
#define GFP_KERNEL 0
#define CONFIG_ANDROID_VENDOR_HOOKS hooks_config
#define IS_ENABLED(x) (x)
#define WARN_ON_ONCE(x) (!!(x))
#define min(a,b) ((a)<(b)?(a):(b))
#define struct_size(p,m,n) (sizeof(*(p)) + sizeof((p)->m[0])*(n))
#define mutex_init(x) ((void)0)
#define mutex_lock(x) ((void)0)
#define mutex_unlock(x) ((void)0)
#define atomic_set(x,y) ((void)0)
#define INIT_LIST_HEAD(x) ((void)0)
#define list_add_tail_rcu(x,y) ((void)0)
#define pr_warn_once(...) ((void)0)
#define apply_wqattrs_lock() ((void)0)
#define apply_wqattrs_unlock() ((void)0)
#define kthread_flush_worker(x) ((void)0)
struct workqueue_attrs { int tag; };
struct workqueue_struct {
    struct workqueue_attrs *unbound_attrs;
    char name[WQ_NAME_LEN];
    unsigned flags;
    int max_active, min_active, saved_max_active, saved_min_active;
    int mutex, nr_pwqs_to_flush, pwqs, flusher_queue, flusher_overflow, maydays, list;
    void *node_nr_active[];
};
static int hooks_config, nr_node_ids, wq_power_efficient, wq_online=1;
static int failure, callback, callback_max, live_wq, live_attrs, live_nodes;
static unsigned callback_flags;
static size_t allocated;
static int faults, calls, snapshots;
static struct workqueue_struct *hook_pointer;
static void *kzalloc_noprof(size_t n,int g) {
    if(failure==1) return NULL;
    allocated=n; live_wq++; return calloc(1,n);
}
static void kfree(void *p) {if(p) {live_wq--; free(p);}}
static struct workqueue_attrs *alloc_workqueue_attrs_noprof(void) {
    if(failure==2) return NULL;
    live_attrs++; return calloc(1,sizeof(struct workqueue_attrs));
}
static void free_workqueue_attrs(struct workqueue_attrs *p) {
    if(p) {live_attrs--; free(p);}
}
static int wq_clamp_max_active(int n,unsigned f,const char *name) {
    if(n<1) return 1;
    if(n>2048) return 2048;
    return n;
}
static void trace_android_rvh_alloc_workqueue(struct workqueue_struct *wq,
                                            unsigned *flags,int *active) {
    if(!hooks_config || !callback) return;
    assert(strcmp(wq->name,"hook-test")==0);
    hook_pointer=wq;
    *flags=callback_flags; *active=callback_max;
}
static int alloc_node_nr_active(void **p) {
    if(allocated < sizeof(struct workqueue_struct)+(nr_node_ids+1)*sizeof(*p)) {
        faults++; return -ENOMEM;
    }
    if(failure==3) return -ENOMEM;
    for(int i=0;i<=nr_node_ids;i++) {p[i]=malloc(1);live_nodes++;}
    return 0;
}
static void free_node_nr_active(void **p) {
    for(int i=0;i<=nr_node_ids;i++) if(p[i]) {free(p[i]);p[i]=NULL;live_nodes--;}
}
static int alloc_and_link_pwqs(struct workqueue_struct *wq) {
    if((wq->flags&WQ_UNBOUND) && !wq->unbound_attrs) {faults++;return -EINVAL;}
    return failure==4 ? -ENOMEM : 0;
}
static void wq_adjust_max_active(struct workqueue_struct *wq) {}
static int init_rescuer(struct workqueue_struct *wq) {return failure==5 ? -ENOMEM : 0;}
static int workqueue_sysfs_register(struct workqueue_struct *wq) {return failure==6 ? -ENOMEM : 0;}
static void destroy_workqueue(struct workqueue_struct *wq) {
    if(wq->flags&WQ_UNBOUND) free_node_nr_active(wq->node_nr_active);
    free_workqueue_attrs(wq->unbound_attrs);kfree(wq);
}
'''
POST = r'''
typedef struct workqueue_struct *(*allocfn)(const char*,unsigned,int,va_list);
struct outcome {int ok;unsigned flags;int max;};
static struct outcome invoke(allocfn fn,unsigned flags,int active,...) {
    va_list ap;va_start(ap,active);
    hook_pointer=NULL; allocated=0; faults=0;
    struct workqueue_struct *wq=fn("hook-test",flags,active,ap);
    va_end(ap);
    struct outcome out={!!wq,wq?wq->flags:0,wq?wq->max_active:0};
    if(wq) {
        if(hook_pointer && hook_pointer!=wq) faults++;
        if(wq->flags&WQ_BH) {
            if((wq->flags&~__WQ_BH_ALLOWS) || wq->max_active!=INT_MAX) faults++;
        } else if(wq->max_active<1 || wq->max_active>2048) faults++;
        if((wq->flags&WQ_UNBOUND) != 0) {
            if(!wq->unbound_attrs) faults++;
        } else if(wq->unbound_attrs) faults++;
        destroy_workqueue(wq);
    }
    if(live_wq || live_attrs || live_nodes) faults++;
    return out;
}
struct cpuidle_device {int cpu;};
struct cpuidle_state {int flags;};
struct cpuidle_driver {int state_count;struct cpuidle_state states[8];};
typedef long ktime_t;
#define noinstr
static int idle_index, instrumentation;
#define instrumentation_begin() (instrumentation++)
#define instrumentation_end() (instrumentation--)
static void trace_android_vh_cpu_idle_enter(int *index,struct cpuidle_device *dev) {*index=idle_index;}
'''
MAIN = r'''
int main(void) {
    unsigned flags[]={0,WQ_UNBOUND,WQ_BH,WQ_BH|WQ_HIGHPRI,WQ_POWER_EFFICIENT,WQ_SYSFS,WQ_BH|WQ_UNBOUND};
    int active[]={-1,0,1,256,3333,INT_MAX};
    int nodes[]={1,4,29};
    long cases=0,old_bad=0,nohook=0;
    for(int hi=0;hi<2;hi++) for(int ni=0;ni<3;ni++) for(int power=0;power<2;power++)
    for(int fi=0;fi<7;fi++) for(int mi=0;mi<6;mi++) for(int fail=0;fail<7;fail++) {
        hooks_config=hi;nr_node_ids=nodes[ni];wq_power_efficient=power;failure=fail;callback=0;
        struct outcome a=invoke(native_alloc,flags[fi],active[mi]);assert(!faults);
        struct outcome b=invoke(new_alloc,flags[fi],active[mi]);assert(!faults);
        assert(a.ok==b.ok && a.flags==b.flags && a.max==b.max);nohook++;
        if(!hooks_config) continue;
        callback=1;
        for(int ci=0;ci<7;ci++) for(int cm=0;cm<6;cm++) {
            callback_flags=flags[ci];callback_max=active[cm];
            invoke(new_alloc,flags[fi],active[mi]);assert(!faults);cases++;
            invoke(old_alloc,flags[fi],active[mi]);if(faults) old_bad++;
        }
    }
    struct cpuidle_device dev={0};struct cpuidle_driver drv={0};int idle_cases=0,idle_old_bad=0;
    for(int count=1;count<=8;count++) for(int idx=-2;idx<=10;idx++) {
        drv.state_count=count;idle_index=idx;instrumentation=0;
        int ret=idle_new(&dev,&drv,0);assert(!instrumentation);
        assert(ret==(idx<0?idx:(idx>=count?-EINVAL:0)));idle_cases++;
        instrumentation=0;ret=idle_old(&dev,&drv,0);assert(!instrumentation);
        if(idx>=count && ret==1) idle_old_bad++;
    }
    assert(old_bad && idle_old_bad);
    printf("{\"workqueue_callback_cases\":%ld,\"native_no_callback_comparisons\":%ld,\"old_workqueue_invariant_failures\":%ld,\"cpuidle_cases\":%d,\"old_cpuidle_out_of_range_acceptances\":%d}\n",cases,nohook,old_bad,idle_cases,idle_old_bad);
    return 0;
}
'''
functions=[]
for ref,name in [(LTS,'native_alloc'),(OLD,'old_alloc'),('worktree','new_alloc')]:
    functions.append(function(source(ref,'kernel/workqueue.c'),'__alloc_workqueue').replace('__alloc_workqueue(',name+'(',1))
idle=[]
for ref,name in [(OLD,'idle_old'),('worktree','idle_new')]:
    s=function(source(ref,'drivers/cpuidle/cpuidle.c'),'cpuidle_enter_state')
    s=s[:s.index('\ttarget_state = &drv->states[index];')]
    s=s.replace('cpuidle_enter_state(',name+'(',1)
    s+='\tinstrumentation_end();\n\treturn index >= drv->state_count ? 1 : 0;\n}\n'
    idle.append(s)
code=PRE+'\n'.join(functions)+POST+'\n'.join(idle)+MAIN
with tempfile.TemporaryDirectory(prefix='allocation-hooks-') as tmp:
    p=Path(tmp);(p/'check.c').write_text(code)
    cmd=['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(p/'check.c'),'-o',str(p/'check')]
    subprocess.run(cmd,check=True,capture_output=True,text=True)
    result=json.loads(subprocess.check_output([str(p/'check')],text=True))
result.update(scope=__doc__,old_source=OLD,lts_source=LTS,workqueue_function_sha256=hashlib.sha256(functions[-1].encode()).hexdigest(),cpuidle_prefix_sha256=hashlib.sha256(idle[-1].encode()).hexdigest(),sanitizers='ASan and UBSan',limits='Workqueue primitives mocked, native attribute limits modeled as 1..2048; failed original shape intercepted before an out-of-bounds write. No actual kernel allocation, concurrent callback registration, CPU idle or module execution.')
print(json.dumps(result,indent=2))
