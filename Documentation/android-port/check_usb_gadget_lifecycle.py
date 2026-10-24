#!/usr/bin/env python3
"""Extract USB gadget error/notification paths into a host lifecycle model.

Exercises allocation failures, two same-devt instances, producer interleavings
at flush, and reported configuration state. No real USB, sysfs or kernel races.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
OLD = 'cef6ed5fe6a4edf0d70962a6dabb1c9204018503'
PRE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef long ssize_t;
struct work_struct { int initialized, queued; };
struct ida { int unused; };
struct device { void *class; int devt, alive; void *drvdata; };
struct device_attribute { int unused; };
struct android_uevent_opts { struct device *dev; int device_id; bool connected,configured,sw_connected; struct work_struct work; struct ida function_ida; };
struct config_group { int unused; };
struct driver { char *name; };
struct gadget_driver { struct driver driver; char *function; };
struct composite { struct gadget_driver gadget_driver; const char *name; };
struct cdev { struct android_uevent_opts android_opts; int lock; void *config; };
struct gadget_info { struct config_group group; struct composite composite; struct cdev cdev; };
static struct gadget_driver configfs_driver_template;
static struct android_uevent_opts *android_opts;
static int opts_lock, android_usb_class, depth, bad_sleep, wrong_device, after_drain, uninit_work, double_free, bad_state, checks;
static struct ida android_ida;
static struct device devices[4], *wanted;
static int next_id, inject, fail_alloc, allocation, freed[4];
static char buffers[3][64];
static struct gadget_info gi_storage;
#define GFP_ATOMIC 0
#define GFP_KERNEL 0
#define ENOMEM 12
#define MKDEV(a,b) 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define IS_ERR(p) ((intptr_t)(p)<0)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define spin_lock_irqsave(l,f) do { (f)=0; depth++; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(f); depth--; } while(0)
#define spin_lock(l) do { depth++; } while(0)
#define spin_unlock(l) do { depth--; } while(0)
#define INIT_WORK(w,f) do { (w)->initialized=1; } while(0)
static int ida_alloc(struct ida *i,int flags) { return next_id++; }
static void ida_init(struct ida *i) {}
static void ida_free(struct ida *i,int n) {}
static void ida_destroy(struct ida *i) {}
static struct device *device_create(void *class,void *parent,int devt,void *opts,const char *fmt,int id) {
 struct device *d=&devices[id]; *d=(struct device){.class=class,.devt=devt,.alive=1,.drvdata=opts}; return d;
}
static void device_unregister(struct device *d) { bad_sleep+=depth!=0; wrong_device+=d!=wanted; d->alive=0; }
static void device_destroy(void *class,int devt) {
 for(int i=0;i<next_id;i++) if(devices[i].alive && devices[i].class==class && devices[i].devt==devt) { device_unregister(&devices[i]); return; }
}
static void schedule_work(struct work_struct *w) { if(!w->initialized) uninit_work++; w->queued++; }
static void __android_set_connected(struct android_uevent_opts *,bool);
static void __android_set_configured(struct android_uevent_opts *,bool);
static void flush_work(struct work_struct *w) {
 w->queued=0;
 if(inject) {
  struct android_uevent_opts *o=(void *)((char *)w - offsetof(struct android_uevent_opts,work));
  __android_set_connected(o,!o->connected); __android_set_configured(o,!o->configured);
  after_drain+=w->queued;
 }
}
static void *dev_get_drvdata(struct device *d) { return d->drvdata; }
static int sysfs_emit(char *buf,const char *fmt,const char *s) { return sprintf(buf,fmt,s); }
static char *new_string(void) { allocation++; return fail_alloc==allocation?NULL:buffers[allocation]; }
static char *kasprintf(int flags,const char *fmt,const char *name) { return new_string(); }
static char *kstrdup(const char *name,int flags) { return new_string(); }
static void kfree(void *p) {
 if(!p) return;
 int index=p==&gi_storage?0:(p==buffers[1]?1:2);
 if(freed[index]++) double_free++;
}
static int make_android_device(struct android_uevent_opts *opts) { return fail_alloc==3?-ENOMEM:0; }
static int fake_config_result, fake_config_present;
static int set_config(struct cdev *c,void *ctrl,int value) { c->config=fake_config_present?c:NULL; return fake_config_result; }
'''
MAIN = r'''
int main(void) {
 for(int failure=1;failure<=3;failure++) {
  fail_alloc=failure; allocation=0; memset(freed,0,sizeof(freed)); memset(&gi_storage,0,sizeof(gi_storage));
  struct config_group *g=make_fragment(); checks++;
  if(!IS_ERR(g) || freed[0]!=1 || (failure>=2 && freed[1]!=1) || (failure==3 && freed[2]!=1)) bad_state++;
 }
 fail_alloc=0; allocation=0; memset(freed,0,sizeof(freed)); checks++; if(IS_ERR(make_fragment())) bad_state++;
 for(int interleave=0;interleave<2;interleave++) {
  struct android_uevent_opts a={0},b={0}; next_id=0; depth=0; android_opts=NULL; inject=interleave;
  android_device_create(&a); android_device_create(&b);
  __android_set_connected(&a,true); __android_set_connected(&b,true); __android_set_configured(&b,true);
  wanted=b.dev; android_device_destroy(&b); checks++;
  if(!devices[0].alive || devices[1].alive || depth) bad_state++;
  wanted=a.dev; android_device_destroy(&a); checks++;
  if(devices[0].alive || devices[1].alive || depth) bad_state++;
 }
 struct android_uevent_opts absent={0}; checks++;
 __android_set_connected(&absent,true); __android_set_configured(&absent,true);
 for(int result=-1;result<=1;result++) for(int present=0;present<2;present++) {
  struct cdev c={0}; struct device dev={.drvdata=&c.android_opts}; c.android_opts.dev=&dev; c.android_opts.work.initialized=1;
  fake_config_result=result; fake_config_present=present; config_fragment(&c); checks++;
  if(c.android_opts.configured!=present || depth) bad_state++;
 }
 struct android_uevent_opts state={.connected=true,.configured=true}; struct device dev={.drvdata=&state}; char buf[64];
 state.dev=&dev; state.work.initialized=1; __android_set_connected(&state,false); state_show(&dev,NULL,buf); checks++;
 if(strcmp(buf,"DISCONNECTED\n") || depth) bad_state++;
 printf("{\"checks\":%d,\"double_free\":%d,\"sleep_under_spinlock\":%d,\"wrong_instance\":%d,\"queued_after_drain\":%d,\"uninitialized_work\":%d,\"bad_state_or_cleanup\":%d}\n",checks,double_free,bad_sleep,wrong_device,after_drain,uninit_work,bad_state);
 return 0;
}
'''

def source(ref,path):
    return (ROOT/path).read_text() if ref=='working-tree' else subprocess.check_output(['git','show',ref+':'+path],cwd=ROOT,text=True)

def test(ref):
    gadget=source(ref,'drivers/usb/gadget/configfs.c')
    uevent=source(ref,'drivers/usb/gadget/android_configfs_uevent.c')
    composite=source(ref,'drivers/usb/gadget/composite.c')
    make=function(gadget,'gadgets_make'); make=make[make.index('\tgi->composite.gadget_driver = configfs_driver_template;'):]
    make='static struct config_group *make_fragment(void) {\nstruct gadget_info *gi=&gi_storage;const char *name="test";\n'+make.replace('android_device_create(', 'make_android_device(')
    config=composite[composite.index('\tcase USB_REQ_SET_CONFIGURATION:'):]
    config=config[config.index('\t\tspin_lock(&cdev->lock);'):config.index('\tcase USB_REQ_GET_CONFIGURATION:')]
    config=config[:config.rindex('\t\tbreak;')]
    config='static void config_fragment(struct cdev *cdev) {\nint value,w_value=1; void *ctrl=NULL;\n'+config+'(void)value;\n}\n'
    names=['android_device_create','android_device_destroy','__android_set_connected','__android_set_configured','android_set_configured','android_set_unconfigured','state_show']
    functions='\n'.join(function(uevent,n) for n in names)
    code=PRE+functions+make+config+MAIN
    with tempfile.TemporaryDirectory(prefix='usb-gadget-check-') as td:
        c=Path(td)/'check.c'; exe=Path(td)/'check'; c.write_text(code)
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-variable',str(c),'-o',str(exe)],check=True)
        result=json.loads(subprocess.check_output([str(exe)],text=True))
    return dict(source=ref,extracted_model_sha256=hashlib.sha256(code.encode()).hexdigest(),**result)

if __name__=='__main__':
    old=test(OLD); current=test('working-tree')
    assert all(current[k]==0 for k in ['double_free','sleep_under_spinlock','wrong_instance','queued_after_drain','uninitialized_work','bad_state_or_cleanup'])
    assert all(old[k]>0 for k in ['double_free','sleep_under_spinlock','wrong_instance','queued_after_drain','uninitialized_work','bad_state_or_cleanup'])
    report=dict(scope=__doc__,old=old,current=current,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/usb-gadget-lifecycle-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
