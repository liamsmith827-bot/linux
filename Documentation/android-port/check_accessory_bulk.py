#!/usr/bin/env python3
"""Host tests of extracted accessory bulk I/O, disable and unbind functions.

Uses pthread mutexes and modeled USB completion/dequeue. Checks asynchronous
cancel retry and buffer ownership during concurrent unbind, not kernel/USB I/O.
"""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <unistd.h>
struct list_head { struct list_head *next,*prev; };
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
static void init_list(struct list_head *h) { h->next=h->prev=h; }
static bool list_empty(struct list_head *h) { return h->next==h; }
static void list_del(struct list_head *p) { p->next->prev=p->prev;p->prev->next=p->next; }
static void list_add_tail(struct list_head *p,struct list_head *h) { p->next=h;p->prev=h->prev;h->prev->next=p;h->prev=p; }
struct mutex { pthread_mutex_t p; };
typedef pthread_mutex_t spinlock_t;
struct usb_request;
struct usb_ep { bool enabled; unsigned maxpacket; struct usb_request *pending[8]; };
struct usb_request { struct list_head list; void *buf,*context; unsigned length,actual,zero; int status; void (*complete)(struct usb_ep *,struct usb_request *); };
struct usb_composite_dev { void *gadget; };
struct usb_configuration { struct usb_composite_dev *cdev; };
struct usb_function { struct usb_configuration *config; };
struct acc_dev {
 spinlock_t lock,io_lock; struct mutex read_mutex,write_mutex; struct usb_function function;
 bool online,disconnected,unbinding,closing,rx_pending; int rx_done;
 struct usb_ep *ep_in,*ep_out; struct list_head tx_idle; struct usb_request *rx_req[2];
 int read_wq,write_wq; char manufacturer[256],model[256],description[256],version[256],uri[256],serial[256];int start_requested,audio_mode;
};
struct file { struct acc_dev *private_data; };
static struct acc_dev dev;static struct usb_ep in_ep,out_ep;static struct file fp={.private_data=&dev};
static int mode,queues,dequeues,checks,copy_failure,copy_unbind,enable_fail,config_fail,config_calls,fail_queue,zero_packets;
static _Atomic int freed;
static pthread_t unbinder;static pthread_mutex_t sync_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sync_cond=PTHREAD_COND_INITIALIZER;
static bool waiting,finished;static _Thread_local bool is_unbinder;static _Thread_local int spin_depth;
#define __user
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_ACQUIRE)
#define WRITE_ONCE(x,y) __atomic_store_n(&(x),(y),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define GFP_ATOMIC 0
#define BULK_BUFFER_SIZE 16384
#define RX_REQ_MAX 2
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define round_up(n,d) (((n)+(d)-1)/(d)*(d))
#define pr_debug(...) ((void)0)
#define spin_lock_irqsave(l,f) do { (f)=0;assert(!pthread_mutex_lock(l));spin_depth++; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(f);spin_depth--;assert(!pthread_mutex_unlock(l)); } while(0)
#define wake_up(q) ((void)0)
static void mutex_lock(struct mutex *m) {
 assert(!spin_depth);int r=pthread_mutex_trylock(&m->p);
 if(r==EBUSY) {
  if(is_unbinder) { pthread_mutex_lock(&sync_lock);waiting=true;pthread_cond_broadcast(&sync_cond);pthread_mutex_unlock(&sync_lock); }
  assert(!pthread_mutex_lock(&m->p));
 } else assert(!r);
}
static int mutex_lock_interruptible(struct mutex *m) { mutex_lock(m);return 0; }
static void mutex_unlock(struct mutex *m) { assert(!pthread_mutex_unlock(&m->p)); }
static struct acc_dev *func_to_dev(struct usb_function *f) { return container_of(f,struct acc_dev,function); }
static int usb_ep_queue(struct usb_ep *ep,struct usb_request *r,int flags) {
 assert(spin_depth==1);if(fail_queue)return -EIO;assert(ep->enabled);
 for(int i=0;i<8;i++)assert(ep->pending[i]!=r);
 for(int i=0;i<8;i++)if(!ep->pending[i]) { ep->pending[i]=r;queues++;return 0; }
 abort();
}
static void finish_one(struct usb_ep *ep,int status,unsigned actual) {
 for(int i=0;i<8;i++)if(ep->pending[i]) {
  struct usb_request *r=ep->pending[i];ep->pending[i]=NULL;r->status=status;r->actual=actual;
  r->complete(ep,r);return;
 }
 abort();
}
static int usb_ep_dequeue(struct usb_ep *ep,struct usb_request *r) { dequeues++;return 0; /* intentionally asynchronous */ }
static int usb_ep_disable(struct usb_ep *ep) {
 for(int i=0;i<8;i++)if(ep->pending[i])finish_one(ep,-ESHUTDOWN,0);
 ep->enabled=false;return 0;
}
static int usb_ep_enable(struct usb_ep *ep) { if(enable_fail && ep==&out_ep)return -EIO;ep->enabled=true;return 0; }
static int config_ep_by_speed(void *g,struct usb_function *f,struct usb_ep *ep) { config_calls++;return config_fail==config_calls?-EINVAL:0; }
static void usb_ep_free_request(struct usb_ep *ep,struct usb_request *r) { for(int i=0;i<8;i++)assert(ep->pending[i]!=r);atomic_fetch_add(&freed,1);free(r); }
#define kfree free
static void acc_hid_unbind(struct acc_dev *d) {}
static void acc_function_disable(struct usb_function *f);
static void acc_function_unbind(struct usb_configuration *c,struct usb_function *f);
static int wait_hook(int which) {
 if(mode==1)return -EINTR;
 if(mode==2) { finish_one(&out_ep,-ECONNRESET,0);return 0; }
 if(mode==4) { acc_function_disable(&dev.function);return 0; }
 if(mode==5) { WRITE_ONCE(dev.unbinding,true);return 0; }
 if(which==dev.write_wq) { finish_one(&in_ep,0,0);return 0; }
 if(mode==3 && !zero_packets++)finish_one(&out_ep,0,0);
 else finish_one(&out_ep,0,4);
 return 0;
}
#define wait_event_interruptible(q,cond) ({ int e=0,steps=0; while(!(cond)) { assert(++steps<20);e=wait_hook(q);if(e)break; } e; })
static void *unbind_thread(void *unused) {
 is_unbinder=true;acc_function_unbind(NULL,&dev.function);
 pthread_mutex_lock(&sync_lock);finished=true;pthread_cond_broadcast(&sync_cond);pthread_mutex_unlock(&sync_lock);return NULL;
}
static void maybe_unbind(void) {
 if(!copy_unbind)return;
 copy_unbind=0;assert(!pthread_create(&unbinder,NULL,unbind_thread,NULL));
 pthread_mutex_lock(&sync_lock);while(!waiting && !finished)pthread_cond_wait(&sync_cond,&sync_lock);
 assert(waiting && !finished && !atomic_load(&freed));pthread_mutex_unlock(&sync_lock);
}
static int copy_to_user(void *dst,const void *src,size_t n) { assert(!spin_depth);maybe_unbind();if(copy_failure)return 1;memcpy(dst,src,n);return 0; }
static int copy_from_user(void *dst,const void *src,size_t n) { assert(!spin_depth);maybe_unbind();if(copy_failure)return 1;memcpy(dst,src,n);return 0; }
'''
MAIN=r'''
static struct usb_request *new_req(struct usb_ep *ep,void (*cb)(struct usb_ep *,struct usb_request *)) {
 struct usb_request *r=calloc(1,sizeof(*r));assert(r);r->buf=calloc(1,BULK_BUFFER_SIZE);assert(r->buf);r->context=&dev;r->complete=cb;return r;
}
static void reset(void) {
 memset(&dev,0,sizeof(dev));memset(&in_ep,0,sizeof(in_ep));memset(&out_ep,0,sizeof(out_ep));
 assert(!pthread_mutex_init(&dev.lock,NULL));assert(!pthread_mutex_init(&dev.io_lock,NULL));
 assert(!pthread_mutex_init(&dev.read_mutex.p,NULL));assert(!pthread_mutex_init(&dev.write_mutex.p,NULL));
 dev.ep_in=&in_ep;dev.ep_out=&out_ep;in_ep.maxpacket=out_ep.maxpacket=512;in_ep.enabled=out_ep.enabled=true;
 dev.online=true;dev.read_wq=1;dev.write_wq=2;init_list(&dev.tx_idle);
 struct usb_request *r=new_req(&in_ep,acc_complete_in);req_put(&dev,&dev.tx_idle,r);
 dev.rx_req[0]=new_req(&out_ep,acc_complete_out);
 mode=queues=dequeues=copy_failure=copy_unbind=enable_fail=config_fail=config_calls=fail_queue=zero_packets=0;
 atomic_store(&freed,0);waiting=finished=false;
}
static void finish(bool already_unbound) {
 if(!already_unbound)acc_function_unbind(NULL,&dev.function);
 assert(atomic_load(&freed)==2 && !dev.rx_pending && !dev.rx_req[0] && list_empty(&dev.tx_idle));
 assert(!pthread_mutex_destroy(&dev.lock));assert(!pthread_mutex_destroy(&dev.io_lock));
 assert(!pthread_mutex_destroy(&dev.read_mutex.p));assert(!pthread_mutex_destroy(&dev.write_mutex.p));checks++;
}
int main(void) {
 char buffer[BULK_BUFFER_SIZE*2]={0};
 for(int cancelled=0;cancelled<2;cancelled++) {
  reset();mode=1;assert(acc_read(&fp,buffer,4,NULL)==-EINTR);
  assert(queues==1 && dequeues==1 && dev.rx_pending && !dev.rx_done);
  mode=cancelled?2:0;assert(acc_read(&fp,buffer,4,NULL)==(cancelled?-ECONNRESET:4));assert(queues==1);finish(false);
 }
 for(int m=0;m<=5;m++) {
  if(m==1 || m==2)continue;reset();mode=m;if(m==5)dev.online=false;
  int r=acc_read(&fp,buffer,4,NULL);
  assert(r==(m==4?-ESHUTDOWN:m==5?-ENODEV:4));if(m==3)assert(queues==2);finish(false);
 }
 reset();copy_failure=1;assert(acc_read(&fp,buffer,4,NULL)==-EFAULT);finish(false);
 reset();fail_queue=1;assert(acc_read(&fp,buffer,4,NULL)==-EIO && !dev.rx_pending);finish(false);
 reset();dev.online=false;dev.closing=true;assert(acc_read(&fp,buffer,4,NULL)==-ENODEV);finish(false);
 for(int write=0;write<2;write++) {
  reset();copy_unbind=1;
  int r=write?acc_write(&fp,buffer,4,NULL):acc_read(&fp,buffer,4,NULL);
  assert(r==(write?-EIO:4));assert(!pthread_join(unbinder,NULL));finish(true);
 }
 for(int bad=0;bad<3;bad++) {
  reset();copy_failure=bad==1;fail_queue=bad==2;
  int r=acc_write(&fp,buffer,sizeof(buffer),NULL);
  assert(r==(bad==1?-EFAULT:bad==2?-EIO:(int)sizeof(buffer)));finish(false);
 }
 for(int fail=0;fail<3;fail++) {
  reset();struct usb_composite_dev cd={0};struct usb_configuration cfg={.cdev=&cd};dev.function.config=&cfg;
  config_fail=fail==1?2:0;enable_fail=fail==2;
  int r=acc_function_set_alt(&dev.function,0,0);
  assert((r==0)==!fail);assert(in_ep.enabled==!fail && out_ep.enabled==!fail && dev.online==!fail);finish(false);
 }
 reset();dev.closing=true;assert(!acc_read(&fp,buffer,0,NULL));assert(!acc_write(&fp,buffer,0,NULL));finish(false);
 printf("{\"checks\":%d,\"asynchronous_dequeue_cases\":2,\"concurrent_unbind_cases\":2}\n",checks);
 return 0;
}
'''
if __name__=='__main__':
    s=(ROOT/'drivers/usb/gadget/function/android_f_accessory.c').read_text()
    names=['acc_request_free','req_put','req_get','acc_free_all_requests','acc_complete_in','acc_complete_out','acc_read','acc_write','acc_function_disable','acc_function_unbind','acc_function_set_alt']
    code=PRE+'\n'.join(function(s,n) for n in names)+MAIN
    variants=[('current',code),('missing_unbind_buffer_locks',code.replace('\tmutex_lock(&dev->read_mutex);','').replace('\tmutex_lock(&dev->write_mutex);','').replace('\tmutex_unlock(&dev->write_mutex);\n\tmutex_unlock(&dev->read_mutex);','')),
              ('forget_pending_on_cancel',code.replace('\t\tif (!ret)\n\t\t\tret = -ENODEV;','\t\tdev->rx_pending = false;\n\t\tif (!ret)\n\t\t\tret = -ENODEV;'))]
    results=[]
    with tempfile.TemporaryDirectory(prefix='accessory-bulk-') as td:
        for name,text in variants:
            c=Path(td)/(name+'.c');e=Path(td)/name;c.write_text(text)
            subprocess.run(['cc','-std=gnu11','-pthread','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-misleading-indentation',str(c),'-o',str(e)],check=True)
            r=subprocess.run([str(e)],text=True,capture_output=True,timeout=30,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1'))
            if name=='current':assert not r.returncode,r.stderr
            else:assert r.returncode,name
            results.append(dict(variant=name,exit_code=r.returncode,model_sha256=hashlib.sha256(text.encode()).hexdigest(),result=json.loads(r.stdout) if name=='current' else 'Injected regression rejected'))
    report=dict(scope=__doc__,results=results,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/accessory-bulk-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
