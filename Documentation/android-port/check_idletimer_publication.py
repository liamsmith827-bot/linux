#!/usr/bin/env python3
"""Check extracted idle-timer construction and suspend callbacks with host shims."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;R=D.parents[1];p='net/netfilter/xt_IDLETIMER.c';A='23112ce1886ea26b19be03207c0227a06a6ca009'
names=['idletimer_resume','idletimer_tg_create','idletimer_tg_create_v1']
def extract(s,n):
 start=s.index('static int '+n+'(');end=s.index('\n}',start)+2;return s[start:end]
pre=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#define GFP_KERNEL 0
#define NOTIFY_DONE 0
#define PM_SUSPEND_PREPARE 1
#define PM_POST_SUSPEND 2
#define XT_IDLETIMER_ALARM 1
#define ALARM_BOOTTIME 1
#define KOBJ_ADD 0
#define KERN_WARNING ""
#define pr_debug(...) ((void)0)
#define printk(...) ((void)0)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define time_after(a,b) ((long)((b)-(a))<0)
#define sysfs_attr_init(a) ((void)0)
#define list_add(a,b) ((void)0)
struct timespec64 { long tv_sec,tv_nsec; };
typedef long ktime_t;
struct work_struct { bool initialized; };
struct timer_list { bool initialized; unsigned long expires; };
struct alarm { bool initialized; void *data; };
struct notifier_block { int (*notifier_call)(struct notifier_block *,unsigned long,void *); };
struct device_attribute { struct { char *name; int mode; } attr; void *show; };
struct idletimer_tg {
 struct timer_list timer; struct alarm alarm; struct work_struct work;
 struct notifier_block pm_nb; struct device_attribute attr;
 struct timespec64 delayed_timer_trigger,last_modified_timer,last_suspend_time;
 int entry,timeout,uid; unsigned refcnt,timer_type;
 bool work_pending,send_nl_msg,active,suspend_time_valid;
};
struct idletimer_tg_info { char label[28];unsigned timeout;struct idletimer_tg *timer; };
struct idletimer_tg_info_v1 { char label[28];unsigned timeout,timer_type,send_nl_msg;struct idletimer_tg *timer; };
static int phase,allocations,registrations,bad_publication,operations,locked;
static int timestamp_lock,idletimer_tg_list,idletimer_tg_kobj;
static unsigned long jiffies=1000;
static long boottime;
static void *kzalloc(size_t n,int flags) { (void)flags;if(phase==1)return NULL;allocations++;return calloc(1,n); }
static char *kstrdup(const char *s,int flags) { (void)flags;if(phase==3)return NULL;allocations++;return strdup(s); }
static void kfree(void *p) { if(p)allocations--;free(p); }
static int idletimer_check_sysfs_name(const char *s,size_t n) { (void)s;(void)n;return phase==2?-EINVAL:0; }
static int sysfs_create_file(int k,void *a) { (void)k;(void)a;return phase==4?-EIO:0; }
static void kobject_uevent(int k,int event) { (void)k;(void)event; }
static int idletimer_tg_show;
static int idletimer_tg_work,idletimer_tg_expired,idletimer_tg_alarmproc;
#define INIT_WORK(w,fn) ((void)(fn),(w)->initialized=true)
#define timer_setup(t,fn,flags) ((void)(fn),(void)(flags),(t)->initialized=true)
#define alarm_init(a,type,fn) ((void)(type),(void)(fn),(a)->initialized=true)
static unsigned long secs_to_jiffies(unsigned n) { return n*250UL; }
static int mod_timer(struct timer_list *t,unsigned long when) { assert(t->initialized);t->expires=when;return 0; }
static void alarm_start_relative(struct alarm *a,ktime_t t) { (void)t;assert(a->initialized); }
static ktime_t ktime_set(long s,long ns) { (void)ns;return s; }
static ktime_t ktime_get_boottime(void) { return boottime; }
static struct timespec64 ktime_to_timespec64(ktime_t t) {return (struct timespec64){t,0};}
static struct timespec64 timespec64_sub(struct timespec64 a,struct timespec64 b) {return (struct timespec64){a.tv_sec-b.tv_sec,0};}
static unsigned long timespec64_to_jiffies(struct timespec64 *t) {return t->tv_sec*250UL;}
static void spin_lock_bh(int *p) {(void)p;assert(!locked);locked=1;}
static void spin_unlock_bh(int *p) {(void)p;assert(locked);locked=0;}
static void mod_timer_pending(struct timer_list *t,unsigned long when) {operations++;assert(t->initialized);t->expires=when;}
static void timer_delete(struct timer_list *t) {operations++;if(!t->initialized)bad_publication++;}
static void schedule_work(struct work_struct *w) {operations++;if(!w->initialized)bad_publication++;}
static int register_pm_notifier(struct notifier_block *nb)
{
 struct idletimer_tg *t=container_of(nb,struct idletimer_tg,pm_nb);registrations++;
 if(!t->work.initialized || (t->timer_type? !t->alarm.initialized:!t->timer.initialized))bad_publication++;
 /* Invoke immediately at publication, modeling a callback on another CPU. */
 nb->notifier_call(nb,PM_SUSPEND_PREPARE,NULL);boottime+=10;
 nb->notifier_call(nb,PM_POST_SUSPEND,NULL);
 return 0;
}
'''
main=r'''
int main(void)
{
 unsigned cases=0;
 for(int version=0;version<2;version++)
 for(int type=0;type<(version?2:1);type++)
 for(unsigned notify=0;notify<2;notify++)
 for(unsigned timeout=1;timeout<=3;timeout++)
 for(phase=0;phase<5;phase++) {
  struct idletimer_tg_info a={.label="test",.timeout=timeout};
  struct idletimer_tg_info_v1 b={.label="test",.timeout=timeout,.timer_type=type,.send_nl_msg=notify};
  registrations=0;boottime=0;operations=0;
  int rc=version?idletimer_tg_create_v1(&b):idletimer_tg_create(&a);
  if(phase) {assert(rc<0 && !registrations && !allocations);}
  else {
   struct idletimer_tg *t=version?b.timer:a.timer;
   assert(rc==0 && registrations==1 && allocations==2);
   if(type)assert(!operations);
   kfree(t->attr.attr.name);kfree(t);
  }
  cases++;
 }
 /* Alarm callback must not inspect/operate on the unused jiffies timer. */
 struct idletimer_tg t={.timer_type=XT_IDLETIMER_ALARM,.active=true,
                       .timer.expires=2000};
 operations=0;boottime=0;
 idletimer_resume(&t.pm_nb,PM_SUSPEND_PREPARE,NULL);boottime=10;
 idletimer_resume(&t.pm_nb,PM_POST_SUSPEND,NULL);
 if(operations)bad_publication++;
 cases++;
 printf("%u cases; %d publication/callback violations\n",cases,bad_publication);
 return bad_publication?1:0;
}
'''
# The show field is only assigned in the extracted constructors.
pre=pre.replace('static int idletimer_tg_show;', 'static void idletimer_tg_show(void) {}')
results={};current=(R/p).read_text();original=subprocess.check_output(['git','show',A+':'+p],cwd=R,text=True)
with tempfile.TemporaryDirectory(prefix='idletimer-publication-') as td:
 for name,s in [('current',current),('original_ack',original)]:
  c=Path(td)/(name+'.c');e=Path(td)/name
  c.write_text(pre+'\n'+'\n'.join(extract(s,n) for n in names)+'\n'+main)
  subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-variable','-Wno-unused-parameter','-Werror',str(c),'-o',str(e)],check=True)
  r=subprocess.run([str(e)],capture_output=True,text=True);results[name]={'exit_code':r.returncode,'output':r.stdout.strip(),'stderr':r.stderr.strip()}
assert results['current']['exit_code']==0,results
assert results['original_ack']['exit_code']!=0,results
out={'source_path':p,'function_sha256':{n:hashlib.sha256(extract(current,n).encode()).hexdigest() for n in names},'original_ack':A,'results':results,'scope':'Extracted constructors/resume function with host allocation, timer, work and notifier shims. Registration invokes callback immediately. Includes allocation/name/sysfs errors and alarm no-jiffies-operation check. No live suspend, timers, concurrency, notifier API, netfilter or sysfs test.'}
(D/'evidence/idletimer-publication-check.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
