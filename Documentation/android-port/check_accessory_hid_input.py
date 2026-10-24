#!/usr/bin/env python3
"""Exercise accessory completion through extracted native HID entry functions.

Host stubs model held input lock, driver absence, empty reports and USB errors.
They do not test actual HID devices, BPF, concurrent removal or object ownership.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
OLD='68368a960aade5ca71c204d4a62703101831ff7c'
PRE=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
enum hid_report_type { HID_INPUT_REPORT };
struct hid_report { int unused; };
struct hid_driver { int (*raw_event)(void *,void *,void *,int); };
struct hid_report_enum { int unused; };
struct hid_device { int driver_input_lock; struct hid_driver *driver; struct hid_report_enum report_enum[1]; int debug_list; };
struct acc_dev { bool closing; };
struct acc_hid_dev { struct hid_device *hid; bool dead; };
struct acc_control_request { struct acc_dev *dev; struct acc_hid_dev *hid; unsigned length; };
struct usb_ep { int unused; };
struct usb_request { void *context; unsigned actual; int status; u8 *buf; };
static int delivered, invalid_buffer, held_delivery;
static struct hid_report report;
#define READ_ONCE(x) (x)
#define pr_err(...) ((void)0)
#define dbg_hid(...) ((void)0)
#define IS_ERR(p) false
#define PTR_ERR(p) (-1)
static int down_trylock(int *s) { if(*s) return 1; *s=1; return 0; }
static void up(int *s) { *s=0; }
static bool list_empty(int *l) { return true; }
static void hid_dump_report(struct hid_device *h,int t,u8 *data,u32 size) {}
static struct hid_report *hid_get_report(struct hid_report_enum *e,u8 *d) { return &report; }
static bool hid_match_report(struct hid_device *h,struct hid_report *r) { return true; }
static u8 *dispatch_hid_bpf_device_event(struct hid_device *h,int t,u8 *data,size_t *b,u32 *s,int irq,u64 source,bool from) { return data; }
static int hid_report_raw_event(struct hid_device *h,int t,u8 *data,size_t bufsize,u32 size,int irq) {
 delivered++; if(bufsize!=size || size>4096) invalid_buffer++;
 if(!h->driver_input_lock) held_delivery++;
 return 0;
}
'''
MAIN=r'''
int main(void) {
 int failures=0,checks=0; struct hid_driver drv={0}; u8 buffer[4096]={0};
 for(int locked=0;locked<2;locked++) for(int driver=0;driver<2;driver++)
 for(int failed=0;failed<2;failed++) for(int length=0;length<3;length++) {
  struct hid_device h={.driver_input_lock=locked,.driver=driver?&drv:NULL};
  struct acc_hid_dev ah={.hid=&h};
  struct acc_dev dev={0}; struct acc_control_request control={.dev=&dev,.hid=&ah,.length=4096};
  struct usb_request req={.context=CONTEXT,.actual=length==2?4096:length,.status=failed?-ESHUTDOWN:0,.buf=buffer};
  delivered=0; held_delivery=0;
  acc_complete_send_hid_event(NULL,&req); checks++;
  int expected=!locked && driver && !failed && length;
  if(delivered!=expected || h.driver_input_lock!=locked || (expected && held_delivery)) failures++;
 }
 printf("{\"checks\":%d,\"delivery_failures\":%d,\"incorrect_buffer_extent\":%d}\n",checks,failures,invalid_buffer);
 return 0;
}
'''
def run(ref):
    hid=(ROOT/'drivers/hid/hid-core.c').read_text()
    p='drivers/usb/gadget/function/android_f_accessory.c'
    acc=(ROOT/p).read_text() if ref=='working-tree' else subprocess.check_output(['git','show',ref+':'+p],cwd=ROOT,text=True)
    context="&control" if "struct acc_control_request *control" in function(acc,"acc_complete_send_hid_event") else "&ah"
    code=PRE+function(hid,'__hid_input_report')+function(hid,'hid_safe_input_report')+function(acc,'acc_complete_send_hid_event')+MAIN.replace('CONTEXT',context)
    with tempfile.TemporaryDirectory(prefix='accessory-hid-') as td:
        c=Path(td)/'check.c';e=Path(td)/'check';c.write_text(code)
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-variable',str(c),'-o',str(e)],check=True)
        out=json.loads(subprocess.check_output([str(e)],text=True))
    return dict(source=ref,extracted_model_sha256=hashlib.sha256(code.encode()).hexdigest(),**out)
if __name__=='__main__':
    old=run(OLD);current=run('working-tree')
    assert current['delivery_failures']==current['incorrect_buffer_extent']==0 and old['delivery_failures']>0
    r=dict(scope=__doc__,old=old,current=current,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/accessory-hid-input-check.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
