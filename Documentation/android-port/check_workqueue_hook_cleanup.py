#!/usr/bin/env python3
"""Fault-inject extracted alloc_and_link_pwqs with modeled pool allocation.

Use real host allocations and explicit outstanding-allocation counts. Locks,
RCU release work and pool linking are shims; this does not exercise live workers,
callback concurrency or asynchronous hotplug. Old control uses SDK-equivalent
zero stack initialization to make missing callback status deterministic.
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
#include <stdlib.h>
#include <errno.h>
#define __percpu
#define WQ_HIGHPRI 1
#define WQ_UNBOUND 2
#define WQ_BH 4
#define __WQ_ORDERED 8
#define GFP_KERNEL 0
#define lockdep_assert_held(x) ((void)0)
#define mutex_lock(x) ((void)0)
#define mutex_unlock(x) ((void)0)
#define WARN(x,...) ((void)(x))
#define rcu_access_pointer(x) (x)
#define per_cpu_ptr(p,cpu) ((p)+(cpu)*_Generic((p),struct worker_pool *:2,default:1))
#define for_each_possible_cpu(cpu) for(cpu=0;cpu<4;cpu++)
struct list {struct list *next,*prev;};
struct pool_workqueue {struct list pwqs_node;};
struct worker_pool {int node;};
struct workqueue_struct {unsigned flags;struct pool_workqueue **cpu_pwq;struct pool_workqueue *dfl_pwq;struct list pwqs;int mutex;char *name;};
static struct worker_pool cpu_worker_pools[8],bh_worker_pools[8];
static struct pool_workqueue dummy;
static int ordered_wq_attrs[2],unbound_std_wq_attrs[2];
static int fail_percpu,fail_pool,fail_attrs,mode,status,arrays,pools,pool_attempts,attrs_calls;
static void *alloc_percpu_impl(void) {if(fail_percpu)return 0;arrays++;return calloc(4,sizeof(void*));}
#define alloc_percpu(type) alloc_percpu_impl()
static void free_percpu(void *p) {arrays--;free(p);}
static void *kmem_cache_alloc_node(int cache,int gfp,int node) {
 if(pool_attempts++==fail_pool)return 0;
 pools++;return calloc(1,sizeof(struct pool_workqueue));
}
static void kmem_cache_free(int cache,void *p) {pools--;free(p);}
#define pwq_cache 0
static void init_pwq(struct pool_workqueue *pwq,struct workqueue_struct *wq,struct worker_pool *pool) {}
static void link_pwq(struct pool_workqueue *p) {}
static int apply_workqueue_attrs_locked(struct workqueue_struct *wq,int attrs) {
 attrs_calls++;if(fail_attrs)return -EIO;
 wq->dfl_pwq=&dummy;wq->pwqs.next=wq->pwqs.prev=&dummy.pwqs_node;return 0;
}
static inline void trace_android_rvh_alloc_and_link_pwqs(struct workqueue_struct *wq,int *ret,bool *skip) {
 if(!mode)return;
 *skip=true;
 if(mode==1)*ret=status;
 if(mode==3)*ret=apply_workqueue_attrs_locked(wq,0);
}
'''
POST=r'''
void probe(int flags,int fp,int bp,int ap,int cb,int code,int *out) {
 struct workqueue_struct wq={.flags=flags};
 fail_percpu=fp;fail_pool=bp;fail_attrs=ap;mode=cb;status=code;arrays=pools=pool_attempts=attrs_calls=0;
 out[0]=alloc_and_link_pwqs(&wq);out[1]=arrays;out[2]=pools;out[3]=attrs_calls;out[4]=wq.cpu_pwq!=0;
 /* Tear down the host fixture after recording any leak in the control. */
 if(wq.cpu_pwq) {
  for(int i=0;i<4;i++)if(wq.cpu_pwq[i])kmem_cache_free(0,wq.cpu_pwq[i]);
  free_percpu(wq.cpu_pwq);
 }
}
'''

def main():
    git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
    control=git('rev-parse','ba1be7a48df9').strip()
    lts='2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
    report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,results={},remote_sources_used=[])
    cases=list(itertools.product(range(16),range(2),[-1,0,1,2,3],range(2),range(4),[-12,-5,1,22]))
    with tempfile.TemporaryDirectory(prefix='workqueue-hook-cleanup-') as temp:
        libs={}
        for label,ref in [('port',None),('pre_fix_control',control),('lts',lts)]:
            src=(ROOT/'kernel/workqueue.c').read_text() if ref is None else git('show',ref+':kernel/workqueue.c')
            body=function(src,'alloc_and_link_pwqs');c=Path(temp)/(label+'.c');c.write_text(PRE+body+POST);lib=c.with_suffix('.so')
            extra=['-Wno-error=maybe-uninitialized'] if label=='pre_fix_control' else []
            build=subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',*extra,'-ftrivial-auto-var-init=zero',str(c),'-o',str(lib)],check=True,capture_output=True,text=True)
            dll=ctypes.CDLL(str(lib));dll.probe.argtypes=[ctypes.c_int]*6+[ctypes.POINTER(ctypes.c_int)];dll.probe.restype=None;libs[label]=dll
            report['results'][label]=dict(failures=0,failure_with_outstanding_core_allocation=0,function_sha256=hashlib.sha256(body.encode()).hexdigest(),compiler_warnings=build.stderr.replace(temp,'<temporary>'),compiler_extra_flags=extra)
        native_comparisons=0
        for flags,fp,bp,ap,mode,status in cases:
            outs={}
            for label,dll in libs.items():
                cb=0 if label=='lts' else mode
                if fp:expected=[-12,0,0,0,0]
                elif not flags&2:expected=[-12,0,0,0,0] if bp>=0 else [0,1,4,0,1]
                elif cb in [1,2]:expected=[status if cb==1 and status<0 else -22,0,0,0,0]
                elif ap:expected=[-5 if cb==3 else -12,0,0,1,0]
                else:expected=[0,1,0,1,1]
                out=(ctypes.c_int*5)();dll.probe(flags,fp,bp,ap,mode,status,out);outs[label]=list(out)
                r=report['results'][label];r['failures']+=list(out)!=expected;r['failure_with_outstanding_core_allocation']+=out[0]!=0 and out[1]>0
            if mode==0:
                native_comparisons+=1;assert outs['port']==outs['lts']
    report.update(cases=len(cases),native_default_comparisons=native_comparisons,compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0])
    assert report['results']['port']['failures']==report['results']['lts']['failures']==0
    assert report['results']['pre_fix_control']['failure_with_outstanding_core_allocation']>0
    (ROOT/'Documentation/android-port/evidence/workqueue-hook-cleanup-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
