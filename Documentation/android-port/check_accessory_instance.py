#!/usr/bin/env python3
"""Exercise actual accessory singleton functions with host lifetime stubs.

Tests failure publication, lookup identity, final put context, non-resurrection,
and reservation until work drains. Simulated interleavings, not kernel USB tests.
"""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT = Path(__file__).resolve().parents[2]
OLD = '00951cd18f1e9f344c92e5dbfc2734ae989728b3'
PRE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct work_struct { void (*fn)(struct work_struct *); int queued; };
struct delayed_work { struct work_struct work; };
struct kref { int refcount; };
struct acc_dev {
 struct kref kref; struct work_struct release_work, getprotocol_work, sendstring_work, hid_work;
 struct delayed_work start_work; int lock,read_wq,write_wq,tx_idle,hid_list,new_hid_list,dead_hid_list;
};
static struct acc_dev *acc_dev_instance, *replacement, *allocation;
static bool acc_dev_instance_creating;
static int acc_dev_instance_lock, acc_device, depth, fail_alloc, fail_register;
static int bad_sleep, self_cancel, publication, resurrected, wrong_identity, bad_reservation, bad_free, checks;
static int unlock_replace, releasing, drained, register_reentry, reentry_result, inject_drain;
static struct work_struct *running;
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define GFP_KERNEL 1
#define GFP_ATOMIC 0
#define ENOMEM 12
#define EBUSY 16
#define INIT_WORK(w,f) do { (w)->fn=(f); (w)->queued=0; } while(0)
#define INIT_DELAYED_WORK(w,f) INIT_WORK(&(w)->work,f)
#define INIT_LIST_HEAD(l) ((void)0)
#define init_waitqueue_head(l) ((void)0)
#define spin_lock_init(l) ((void)0)
#define pr_err(...) ((void)0)
#define spin_lock_irqsave(l,f) do { (f)=0; depth++; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(f); depth--; if(unlock_replace) { unlock_replace=0; acc_dev_instance=replacement; } } while(0)
static void kref_init(struct kref *k) { k->refcount=1; }
static void kref_get(struct kref *k) { if(!k->refcount) resurrected++; k->refcount++; }
static bool kref_get_unless_zero(struct kref *k) { if(!k->refcount) return false; k->refcount++; return true; }
static void kref_put(struct kref *k,void (*release)(struct kref *)) { if(!--k->refcount) release(k); }
static int refcount_dec_and_lock_irqsave(int *r,int *l,unsigned long *f) { if(--*r) return 0; depth++; *f=0; return 1; }
static void *kzalloc(size_t n,int gfp) { if(gfp==GFP_KERNEL && depth) bad_sleep++; if(fail_alloc) return NULL; allocation=calloc(1,n); return allocation; }
static void kfree(void *p) { if(p && ((struct acc_dev *)p)->kref.refcount>1) bad_free++; }
static void schedule_work(struct work_struct *w) { w->queued=1; }
static struct acc_dev *get_acc_dev(void);
static int acc_init(void);
static void cancel_work_sync(struct work_struct *w) {
 bad_sleep+=depth!=0; self_cancel+=w==running; w->queued=0;
 if(inject_drain) {
  inject_drain=0; struct acc_dev *d=get_acc_dev();
  if(d) { resurrected++; d->kref.refcount--; }
  if(!acc_dev_instance) bad_reservation++;
  if(acc_init()!=-EBUSY) bad_reservation++;
 }
 drained++;
}
static void cancel_delayed_work_sync(struct delayed_work *w) { cancel_work_sync(&w->work); }
static void acc_start_work(struct work_struct *w) {}
static void acc_hid_work(struct work_struct *w) {}
static void acc_getprotocol_work(struct work_struct *w) {}
static void acc_sendstring_work(struct work_struct *w) {}
static int misc_register(int *m) {
 bad_sleep+=depth!=0;
 struct acc_dev *d=get_acc_dev();
 if(d) { publication++; /* Deliberately keep the reference to test failure free. */ }
 if(register_reentry) { register_reentry=0; reentry_result=acc_init(); }
 return fail_register?-EBUSY:0;
}
'''
MAIN = r'''
static void reset(void) {
 acc_dev_instance=NULL; acc_dev_instance_creating=false; replacement=NULL;
 depth=0; fail_alloc=0; fail_register=0; unlock_replace=0; running=NULL; inject_drain=0;
}
static void drain_release(struct acc_dev *dev) {
 if(dev->release_work.queued) { dev->release_work.queued=0; dev->release_work.fn(&dev->release_work); }
}
int main(void) {
 reset(); fail_register=1; checks++;
 if(acc_init()!=-EBUSY || acc_dev_instance || acc_dev_instance_creating || depth) bad_reservation++;
 reset(); fail_alloc=1; checks++;
 if(acc_init()!=-ENOMEM || acc_dev_instance || acc_dev_instance_creating || depth) bad_reservation++;
 reset(); register_reentry=1; checks++;
 if(acc_init() || reentry_result!=-EBUSY || !acc_dev_instance || acc_dev_instance_creating || depth) bad_reservation++;
 struct acc_dev a={0},b={0}; kref_init(&a.kref); kref_init(&b.kref);
 reset(); acc_dev_instance=&a; replacement=&b; unlock_replace=1; checks++;
 if(get_acc_dev()!=&a || a.kref.refcount!=2 || b.kref.refcount!=1) wrong_identity++;
 reset(); a.kref.refcount=2; b.kref.refcount=2; acc_dev_instance=&b; checks++;
 put_acc_dev(&a);
 if(a.kref.refcount!=1 || b.kref.refcount!=2) wrong_identity++;
 reset(); a.kref.refcount=0; acc_dev_instance=&a; checks++;
 if(get_acc_dev()) resurrected++;
 for(int from_worker=0;from_worker<2;from_worker++) {
  reset(); checks++; if(acc_init()) return 2;
  struct acc_dev *dev=acc_dev_instance;
  /* discard references held only by the publication-failure probe */
  dev->kref.refcount=1;
  running=from_worker?&dev->hid_work:NULL;
  put_acc_dev(dev);
  if(depth) bad_sleep++;
  running=NULL; depth=0;
  if(dev->release_work.queued) {
   if(acc_dev_instance!=dev) bad_reservation++;
   inject_drain=1; drain_release(dev);
  }
  if(acc_dev_instance || depth) bad_reservation++;
 }
 printf("{\"checks\":%d,\"sleep_or_lock_leak\":%d,\"self_cancel\":%d,\"premature_publication\":%d,\"resurrection\":%d,\"wrong_identity\":%d,\"bad_reservation\":%d,\"free_with_references\":%d}\n",checks,bad_sleep,self_cancel,publication,resurrected,wrong_identity,bad_reservation,bad_free);
 return 0;
}
'''
def run(ref):
    path='drivers/usb/gadget/function/android_f_accessory.c'
    src=(ROOT/path).read_text() if ref=='working-tree' else subprocess.check_output(['git','show',ref+':'+path],cwd=ROOT,text=True)
    names=['get_acc_dev']
    if ref=='working-tree': names += ['acc_dev_release_work']
    names += ['__acc_dev_instance_release','put_acc_dev','acc_init']
    code=PRE+'\n'.join(function(src,n) for n in names)+MAIN
    with tempfile.TemporaryDirectory(prefix='accessory-instance-') as td:
        c=Path(td)/'check.c'; c.write_text(code); exe=Path(td)/'check'
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter',str(c),'-o',str(exe)],check=True)
        result=json.loads(subprocess.check_output([str(exe)],text=True))
    return dict(source=ref,extracted_model_sha256=hashlib.sha256(code.encode()).hexdigest(),**result)
if __name__=='__main__':
    old=run(OLD); current=run('working-tree')
    assert all(v==0 for k,v in current.items() if k not in ['source','extracted_model_sha256','checks'])
    assert all(old[k]>0 for k in ['sleep_or_lock_leak','self_cancel','premature_publication','resurrection','wrong_identity','free_with_references'])
    report=dict(scope=__doc__,old=old,current=current,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/accessory-instance-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
