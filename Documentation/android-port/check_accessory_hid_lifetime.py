#!/usr/bin/env python3
"""Exercise extracted accessory control/HID lifecycle code with host USB stubs.

Native HID registration and USB scheduling are modeled. Tests include completion
after disconnect, replacement during registration, failure and bounded allocation.
ASan/UBSan check the model; this is not real kernel concurrency or USB validation.
"""
import hashlib,json,subprocess,tempfile,os
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
typedef uint8_t u8; typedef uint16_t u16; typedef int spinlock_t; typedef int wait_queue_head_t;
struct mutex { int unused; };
struct kref { unsigned n; };
struct work_struct { void (*fn)(struct work_struct *); bool pending; };
struct delayed_work { struct work_struct work; };
struct list_head { struct list_head *prev,*next; };
struct usb_function { int unused; };
struct device { int unused; };
struct hid_device { void *driver_data; };
struct usb_ep { void *driver_data; };
struct usb_request { void *context; void (*complete)(struct usb_ep *,struct usb_request *); unsigned actual,length,zero; int status; void *buf; };
struct usb_gadget { struct usb_ep *ep0; };
struct usb_composite_dev { struct usb_request *req; struct usb_gadget *gadget; };
struct usb_ctrlrequest { u8 bRequestType,bRequest; u16 wIndex,wValue,wLength; };
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_first_entry(h,t,m) list_entry((h)->next,t,m)
#define list_for_each_entry(p,h,m) for(p=list_first_entry(h,__typeof__(*p),m); &(p)->m!=(h); p=list_entry((p)->m.next,__typeof__(*p),m))
#define list_for_each_safe(p,n,h) for(p=(h)->next,n=p->next;p!=(h);p=n,n=p->next)
static void INIT_LIST_HEAD(struct list_head *h) { h->next=h->prev=h; }
static bool list_empty(struct list_head *h) { return h->next==h; }
static void list_del(struct list_head *n) { n->prev->next=n->next; n->next->prev=n->prev; }
static void list_del_init(struct list_head *n) { list_del(n); INIT_LIST_HEAD(n); }
static void list_add(struct list_head *n,struct list_head *h) { n->next=h->next;n->prev=h;h->next->prev=n;h->next=n; }
static void list_move(struct list_head *n,struct list_head *h) { list_del(n);list_add(n,h); }
static int depth,allocations,fail_alloc,init_mode,parse_result,destroyed,delivered,checks;
static struct work_struct *queue[4096]; static unsigned qin,qout;
#define spin_lock_irqsave(l,f) do { (void)(l); (f)=0; assert(!depth); depth++; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(l); (void)(f); assert(depth==1); depth--; } while(0)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define GFP_ATOMIC 0
#define INIT_WORK(w,f) do { (w)->fn=(f);(w)->pending=false; } while(0)
#define le16_to_cpu(x) (x)
#define USB_DIR_IN 128
#define USB_DIR_OUT 0
#define USB_TYPE_VENDOR 64
#define PROTOCOL_VERSION 2
#define MAX_HID_DESC_SIZE 4096
#define MAX_HID_DEVICES 32
#define MAX_HID_ALLOCATIONS 64
#define RX_REQ_MAX 2
#define pr_err(...) ((void)0)
#define ERROR(...) ((void)0)
#define DBG(...) ((void)0)
#define HID_INPUT_REPORT 0
#define msecs_to_jiffies(n) (n)
static void kref_init(struct kref *k) { k->n=1; }
static void kref_get(struct kref *k) { assert(k->n);k->n++; }
static void kref_put(struct kref *k,void (*f)(struct kref *)) { assert(k->n);if(!--k->n) f(k); }
static void *kzalloc(size_t n,int gfp) { if(fail_alloc && !--fail_alloc)return NULL;void *p=calloc(1,n);assert(p);allocations++;return p; }
static void kfree(void *p) { if(p) { allocations--;free(p); } }
static bool schedule_work(struct work_struct *w) { if(w->pending)return false;assert(qin<4096);w->pending=true;queue[qin++]=w;return true; }
static bool schedule_delayed_work(struct delayed_work *w,int delay) { return schedule_work(&w->work); }
static void drain(void) { while(qout<qin) { struct work_struct *w=queue[qout++];w->pending=false;assert(!depth);w->fn(w); } qin=qout=0; }
static void hid_destroy_device(struct hid_device *h) { assert(!depth);destroyed++;kfree(h); }
static int hid_safe_input_report(struct hid_device *h,int type,void *buf,unsigned n,unsigned actual,int irq) { assert(h);delivered++;return 0; }
static int hid_parse_report(struct hid_device *h,u8 *buf,int len) { return parse_result; }
'''
STUBS=r'''
static struct acc_dev *instance;
static bool queue_fail,immediate_complete,close_on_get;
static struct usb_request *pending;
static struct usb_ep *pending_ep;
static struct acc_dev *get_acc_dev(void) { if(!instance || instance->closing)return NULL;kref_get(&instance->kref);if(close_on_get)instance->closing=true;return instance; }
static void put_acc_dev(struct acc_dev *d) { assert(d->kref.n>1);d->kref.n--; }
static void noop_work(struct work_struct *w) {}
static void kill_all_hid_devices(struct acc_dev *dev);
static int acc_register_hid(struct acc_dev *dev,int id,int size);
static int acc_hid_init(struct acc_hid_dev *h) {
 int mode=init_mode;init_mode=0;assert(!depth);
 if(mode==1)kill_all_hid_devices(h->dev);
 if(mode==2) { unsigned long flags;spin_lock_irqsave(&h->dev->lock,flags);assert(!acc_register_hid(h->dev,h->id,4));spin_unlock_irqrestore(&h->dev->lock,flags); }
 if(mode==3)return -EINVAL;
 h->hid=kzalloc(sizeof(*h->hid),GFP_ATOMIC);h->hid->driver_data=h;return 0;
}
static int usb_ep_queue(struct usb_ep *ep,struct usb_request *req,int flags) {
 assert(!depth);if(queue_fail)return -ESHUTDOWN;
 assert(!pending);pending=req;pending_ep=ep;
 if(immediate_complete) { /* Model another CPU completing before queue returns. */
  pending=NULL;req->status=0;req->actual=req->length;req->complete(ep,req);
 }
 return 0;
}
'''
MAIN=r'''
static struct acc_dev dev;
static struct usb_ep ep;
static u8 buffer[4096];
static struct usb_request req;
static struct usb_gadget gadget={.ep0=&ep};
static struct usb_composite_dev cdev={.req=&req,.gadget=&gadget};
static void reset(void) {
 assert(!pending && !allocations && qin==qout && !depth);
 memset(&dev,0,sizeof(dev));memset(&req,0,sizeof(req));req.buf=buffer;
 memset(buffer,0x5a,sizeof(buffer));instance=&dev;kref_init(&dev.kref);
 INIT_LIST_HEAD(&dev.new_hid_list);INIT_LIST_HEAD(&dev.hid_list);INIT_LIST_HEAD(&dev.dead_hid_list);
 INIT_WORK(&dev.hid_work,acc_hid_work);INIT_WORK(&dev.getprotocol_work,noop_work);
 INIT_WORK(&dev.sendstring_work,noop_work);INIT_WORK(&dev.start_work.work,noop_work);
 destroyed=delivered=0;queue_fail=immediate_complete=close_on_get=false;fail_alloc=init_mode=0;
}
static void finish(void) {
 assert(!pending);kill_all_hid_devices(&dev);drain();
 assert(dev.hid_count==0 && dev.kref.n==1 && allocations==0 && !depth);
 checks++;
}
static int setup(int cmd,int val,int idx,int len) {
 struct usb_ctrlrequest ctrl={.bRequestType=USB_TYPE_VENDOR|(cmd==ACCESSORY_GET_PROTOCOL?USB_DIR_IN:0),.bRequest=cmd,.wValue=val,.wIndex=idx,.wLength=len};
 return __acc_setup(&cdev,&ctrl);
}
static void complete(int status,int actual) {
 struct usb_request *r=pending;assert(r);pending=NULL;r->status=status;r->actual=actual;r->complete(pending_ep,r);
}
static void add(void) { assert(!setup(ACCESSORY_REGISTER_HID,1,4,0));complete(0,0); }
static struct acc_hid_dev *find_new(void) { return acc_hid_get_locked(&dev.new_hid_list,1); }
int main(void) {
 /* A descriptor completion can arrive after disconnect destroyed list ownership. */
 for(int error=0;error<2;error++) {
  reset();add();assert(!setup(ACCESSORY_SET_HID_REPORT_DESC,1,0,4));
  struct acc_hid_dev *h=find_new();kill_all_hid_devices(&dev);drain();
  assert(h->dead && dev.hid_count==1 && h->kref.n==1);
  complete(error?-ESHUTDOWN:0,4);drain();assert(!delivered);finish();
 }
 /* Registration cannot hide an initializing object from disconnect/replacement. */
 for(int mode=0;mode<4;mode++) {
  reset();add();assert(!setup(ACCESSORY_SET_HID_REPORT_DESC,1,0,4));complete(0,4);init_mode=mode;drain();
  assert(list_empty(&dev.hid_list)==(mode!=0));
  if(mode==2)assert(find_new() && !find_new()->dead && find_new()->report_desc_offset==0);
  if(mode==1 || mode==3)assert(!dev.hid_count);
  if(mode==0) { assert(!setup(ACCESSORY_SEND_HID_EVENT,1,0,4));kill_all_hid_devices(&dev);drain();assert(dev.hid_count==1);complete(0,4);drain();assert(!delivered); }
  finish();
 }
 /* Every queued control holds a distinct device reference, including errors. */
 for(int cmd=ACCESSORY_GET_PROTOCOL;cmd<=ACCESSORY_SET_AUDIO_MODE;cmd++) {
  if(cmd==ACCESSORY_SET_HID_REPORT_DESC || cmd==ACCESSORY_SEND_HID_EVENT || cmd==ACCESSORY_UNREGISTER_HID)continue;
  for(int fail=0;fail<3;fail++) {
   reset();queue_fail=fail==1;immediate_complete=fail==2;
   int ret=setup(cmd,cmd==ACCESSORY_REGISTER_HID?1:0,cmd==ACCESSORY_REGISTER_HID?4:0,0);
   assert((ret<0)==queue_fail);
   if(pending)complete(-ESHUTDOWN,0);
   finish();
  }
 }
 /* Descriptor completions revalidate length, offset and shutdown under the lock. */
 for(int bad=0;bad<4;bad++) {
  reset();add();assert(!setup(ACCESSORY_SET_HID_REPORT_DESC,1,0,4));struct acc_hid_dev *h=find_new();
  if(bad==1)h->report_desc_offset=1;
  if(bad==2)dev.closing=true;
  if(bad==3)h->initializing=true;
  complete(0,bad==0?5:4);assert(h->report_desc_offset==(bad==1?1:0));finish();
 }
 /* Replacement failure leaves the original lookup intact. */
 for(int fail=1;fail<=3;fail++) {
  reset();add();struct acc_hid_dev *h=find_new();fail_alloc=fail;
  assert(setup(ACCESSORY_REGISTER_HID,1,4,0)==-ENOMEM);assert(find_new()==h && !h->dead);fail_alloc=0;finish();
 }
 reset();
 for(int n=0;n<MAX_HID_ALLOCATIONS;n++) { assert(!setup(ACCESSORY_REGISTER_HID,1,4,0));complete(0,0); }
 assert(setup(ACCESSORY_REGISTER_HID,1,4,0)==-EBUSY && dev.hid_count==MAX_HID_ALLOCATIONS);
 drain();assert(dev.hid_count==1);finish();
 reset();close_on_get=true;assert(setup(ACCESSORY_START,0,0,0)==-ENODEV);assert(!qin);finish();
 reset();struct acc_hid_dev h={.report_desc=buffer,.report_desc_len=4};struct hid_device native={.driver_data=&h};
 for(parse_result=-1;parse_result<=0;parse_result++)assert(acc_hid_parse(&native)==parse_result);finish();
 printf("{\"checks\":%d,\"live_allocations\":%d}\n",checks,allocations);
 return 0;
}
'''
def model():
    s=(ROOT/'drivers/usb/gadget/function/android_f_accessory.c').read_text()
    structs=''
    for n in ['acc_hid_dev','acc_dev','acc_control_request']:
        st=s.index('struct '+n+' {');en=s.index('\n};',st)+3;structs+=s[st:en]+'\n'
    names=['acc_hid_release_work','acc_hid_release','acc_hid_put','acc_control_put','acc_complete_control','acc_complete_set_string','acc_complete_set_hid_report_desc','acc_complete_send_hid_event','acc_hid_parse','acc_hid_new','acc_hid_get_locked','acc_register_hid','acc_unregister_hid','kill_all_hid_devices','acc_hid_work','acc_complete_setup_noop','__acc_setup']
    return PRE+(ROOT/'include/uapi/linux/usb/android_accessory.h').read_text()+structs+STUBS+'\n'.join(function(s,n) for n in names)+MAIN
if __name__=='__main__':
    code=model();results=[]
    mutants=[('current',code),('missing_EP0_HID_reference',code.replace('\t\t\tkref_get(&hid->kref);','\t\t\t/* fault injection: missing EP0 ownership */')),
             ('missing_initialization_visibility_check',code.replace('if (!hid->dead) {','if (true) {')),
             ('missing_allocation_bound',code.replace('if (dev->hid_count >= MAX_HID_ALLOCATIONS)','if (false)')),
             ('ignored_parse_error',code.replace('return hid_parse_report(hid, hdev->report_desc, hdev->report_desc_len);','hid_parse_report(hid, hdev->report_desc, hdev->report_desc_len); return 0;'))]
    with tempfile.TemporaryDirectory(prefix='accessory-ownership-') as td:
        for name,text in mutants:
            c=Path(td)/(name+'.c');e=Path(td)/name;c.write_text(text)
            subprocess.run(['cc','-std=gnu11','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare','-Wno-misleading-indentation',str(c),'-o',str(e)],check=True)
            env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=0');r=subprocess.run([str(e)],text=True,capture_output=True,env=env)
            if name=='current':
                assert r.returncode==0,r.stderr;result=json.loads(r.stdout)
            else: assert r.returncode!=0,name
            results.append(dict(variant=name,exit_code=r.returncode,model_sha256=hashlib.sha256(text.encode()).hexdigest(),result=result if name=='current' else 'Injected ownership/visibility/bound/parser defect rejected'))
    report=dict(scope=__doc__,results=results,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/accessory-hid-lifetime-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
