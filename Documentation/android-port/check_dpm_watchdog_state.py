#!/usr/bin/env python3
"""Extract real watchdog set/handler/clear with host timer-lifecycle observers."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
from check_wakeup_reason_names import function
ROOT=Path(__file__).resolve().parents[2]
FILE='drivers/base/power/main.c'
ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
PRE=r'''
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>
#define READ_ONCE(x) (x)
#define min(x,y) ((x)<(y) ? (x):(y))
#define HZ 250UL
#define KERN_EMERG ""
#define KERN_WARNING ""
struct device { int dummy; }; struct task_struct { int dummy; };
struct timer_list { unsigned long expires; void (*function)(struct timer_list *); };
static struct task_struct task, *current=&task;
static unsigned long jiffies;
static unsigned dpm_watchdog_timeout,dpm_watchdog_warning_timeout;
static bool dpm_watchdog_enabled,dpm_watchdog_all_cpu_backtrace;
static bool initialized,pending;
static unsigned setups,deletes,destroys,panics,failures,cases;
static jmp_buf panic_return;
#define timer_container_of(v,p,m) ((struct dpm_watchdog *)((char *)(p)-offsetof(struct dpm_watchdog,m)))
#define CHECK(x) do { if(!(x)) failures++; } while(0)
#define dev_emerg(...) ((void)0)
#define dev_warn(...) ((void)0)
#define show_stack(...) ((void)0)
#define dev_driver_string(x) "driver"
#define dev_name(x) "device"
#define smp_processor_id() 0
#define trigger_allbutcpu_cpu_backtrace(x) ((void)(x))
#define panic(...) do { panics++; longjmp(panic_return,1); } while(0)
static void timer_setup_on_stack(struct timer_list *t,void (*f)(struct timer_list *),int flags) {
 (void)flags; CHECK(!initialized && !pending); initialized=true; setups++; t->function=f;
}
static void add_timer(struct timer_list *t) { (void)t; CHECK(initialized); pending=true; }
static void mod_timer(struct timer_list *t,unsigned long when) { CHECK(initialized); t->expires=when; pending=true; }
static void timer_delete_sync(struct timer_list *t) { (void)t; CHECK(initialized); pending=false; deletes++; }
static void timer_destroy_on_stack(struct timer_list *t) { (void)t; CHECK(initialized && !pending); initialized=false; destroys++; }
'''
MAIN=r'''
static struct dpm_watchdog wd;
static void run_handler(void) {
 if(!setjmp(panic_return)) dpm_watchdog_handler(&wd.timer);
}
int main(void) {
 struct device dev={};
 for(unsigned timeout=1;timeout<=25;timeout++)
 for(unsigned warning=1;warning<=25;warning++)
 for(unsigned enabled=0;enabled<2;enabled++)
 for(unsigned after_enabled=0;after_enabled<2;after_enabled++)
 for(unsigned after=0;after<3;after++) {
  unsigned bounded=warning<timeout ? warning : timeout;
  memset(&wd,0xa5,sizeof(wd)); initialized=false; pending=false;
  setups=deletes=destroys=panics=0; jiffies=100;
  dpm_watchdog_timeout=timeout; dpm_watchdog_warning_timeout=warning;
  dpm_watchdog_enabled=enabled; dpm_watchdog_all_cpu_backtrace=false;
  dpm_watchdog_set(&wd,&dev);
  CHECK(setups==enabled);
  if(enabled) { CHECK(wd.timer.expires==100+HZ*bounded); CHECK(wd.fatal==(bounded==timeout)); }
  dpm_watchdog_enabled=after_enabled;
  dpm_watchdog_timeout=after==1 ? 25 : 1;
  dpm_watchdog_warning_timeout=after==0 ? 1 : 25;
  if(enabled) {
   jiffies=wd.timer.expires; pending=false;
   run_handler();
   if(bounded==timeout) CHECK(panics==1);
   else {
    CHECK(panics==0 && wd.fatal);
    CHECK(wd.timer.expires==100+HZ*timeout);
    jiffies=wd.timer.expires; pending=false;
    run_handler();
    CHECK(panics==1);
   }
  }
  dpm_watchdog_clear(&wd);
  CHECK(!pending && !initialized); CHECK(deletes==enabled && destroys==enabled);
  cases++;
 }
 printf("{\"cases\":%u,\"failures\":%u}\n",cases,failures);
 return failures ? 1 : 0;
}
'''

def run(source,path):
    structure=re.search(r'struct dpm_watchdog \{.*?\n};',source,re.S).group()
    code='\n'.join(function(source,n) for n in ['dpm_watchdog_handler','dpm_watchdog_set','dpm_watchdog_clear'])
    path.with_suffix('.c').write_text(PRE+structure+code+MAIN)
    subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-O2',str(path.with_suffix('.c')),'-o',str(path)],check=True)
    p=subprocess.run([str(path)],text=True,capture_output=True)
    return p.returncode,json.loads(p.stdout),hashlib.sha256((structure+code).encode()).hexdigest()

if __name__=='__main__':
    source=(ROOT/FILE).read_text();old=subprocess.check_output(['git','show',ACK+':'+FILE],cwd=ROOT,text=True)
    with tempfile.TemporaryDirectory(prefix='dpm-watchdog-review-') as t:
        rc,current,digest=run(source,Path(t)/'current');old_rc,control,_=run(old,Path(t)/'original')
    assert rc==0 and not current['failures'],current
    assert old_rc==1 and control['failures']>0,control
    report=dict(path=FILE,extracted_sha256=digest,current=current,original_ack_control=control,
                scope='Real private structure and set/handler/clear functions with host timer lifecycle, panic and parameter observers. All 1..25 timeout/warning pairs, enable transitions, subsequent parameter changes, bounded warning/deadline behavior and cleanup. Initial warning>timeout models independently observed values during concurrent updates.',
                limits='No kernel timers, actual PM callback, sysctl usercopy, parallel parameter writes, interrupts or panic. READ_ONCE is a host access shim; per-instance clamping ensures bounded values but does not make the two global sysctl reads atomic. The existing sysctl handlers are not claimed to serialize simultaneous writers.',remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/dpm-watchdog-state-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
