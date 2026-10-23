#!/usr/bin/env python3
"""Extracted report formatting/read-side-contract check; not a kernel race test."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_wakeup_reason_names import function

ROOT=Path(__file__).resolve().parents[2]
FILE='drivers/base/power/wakeup.c'
ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
C=r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#define MAX_SUSPEND_ABORT_LEN 256
struct wakeup_source { struct wakeup_source *next; const char *name; bool active; long long last_time; };
static struct wakeup_source *wakeup_sources;
static int wakeup_srcu, readers, failures, cases, pm_abort_suspend;
static unsigned saved_count;
static bool events_check_enabled;
static char log_message[512];
#define CHECK(x) do { if(!(x)) failures++; } while(0)
static int srcu_read_lock(int *domain) { CHECK(domain==&wakeup_srcu); readers++; return 7; }
static void srcu_read_unlock(int *domain,int index) { CHECK(domain==&wakeup_srcu && index==7 && readers==1); readers--; }
static __attribute__((unused)) void rcu_read_lock(void) { failures++; }
static __attribute__((unused)) void rcu_read_unlock(void) {}
static bool check_readers(void) { CHECK(readers==1); return true; }
#define list_for_each_entry_rcu_locked(p,head,member) for((p)=*(head); check_readers() && (p); (p)=(p)->next)
#define list_for_each_entry_rcu(p,head,member) list_for_each_entry_rcu_locked(p,head,member)
#define ktime_to_ns(t) (t)
#define raw_spin_lock_irqsave(lock,flags) ((void)((flags)=0))
#define raw_spin_unlock_irqrestore(lock,flags) ((void)(flags))
#define atomic_read(p) (*(p))
#define pm_pr_dbg(...) ((void)0)
#define pr_info(...) ((void)0)
static void split_counters(unsigned *cnt,unsigned *inpr) { *cnt=1; *inpr=0; }
static void pm_print_active_wakeup_sources(void) {}
static int scnprintf(char *s,size_t size,const char *fmt,...) {
 va_list args; va_start(args,fmt); int n=vsnprintf(s,size,fmt,args); va_end(args);
 return !size ? 0 : n<(int)size ? n : (int)size-1;
}
static void log_suspend_abort_reason(const char *fmt,...) {
 /* Observe the format contract without evaluating unsafe old varargs. */
 va_list args; va_start(args,fmt);
 if(!strcmp(fmt,"%s")) snprintf(log_message,sizeof(log_message),"%s",va_arg(args,const char *));
 else { failures++; snprintf(log_message,sizeof(log_message),"%s",fmt); }
 va_end(args);
}
'''
MAIN=r'''
int main(void) {
 const size_t lengths[]={0,1,2,8,23,24,25,63,64,127,255,256};
 const char *names[]={"plain", "%s-%px-%%", "", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"};
 struct wakeup_source nodes[3]; char expected[512];
 for(int n=0;n<4;n++) for(int mode=0;mode<5;mode++) {
  nodes[0]=(struct wakeup_source){.next=&nodes[1],.name=names[n],.active=mode>=3,.last_time=9};
  nodes[1]=(struct wakeup_source){.next=&nodes[2],.name="second",.active=mode==4,.last_time=20};
  nodes[2]=(struct wakeup_source){.name="third",.last_time=10};
  wakeup_sources=mode ? nodes : NULL;
  if(mode==1) nodes[0].next=NULL;
  switch(mode) {
   case 0: expected[0]=0; break;
   case 1: snprintf(expected,sizeof(expected),"Last active Wakeup Source: %s",names[n]); break;
   case 2: strcpy(expected,"Last active Wakeup Source: second"); break;
   case 3: snprintf(expected,sizeof(expected),"Pending Wakeup Sources: %s ",names[n]); break;
   case 4: snprintf(expected,sizeof(expected),"Pending Wakeup Sources: %s second ",names[n]); break;
  }
  for(size_t k=0;k<sizeof(lengths)/sizeof(lengths[0]);k++) {
   size_t max=lengths[k]; unsigned char buffer[258]; memset(buffer,0xa5,sizeof(buffer));
   pm_get_active_wakeup_sources((char *)buffer+1,max);
   CHECK(buffer[0]==0xa5 && buffer[max+1]==0xa5 && readers==0);
   if(max) { size_t wanted=strlen(expected); if(wanted>=max) wanted=max-1;
    CHECK(!memcmp(buffer+1,expected,wanted)); CHECK(buffer[wanted+1]==0);
   } else CHECK(buffer[1]==0xa5);
   cases++;
  }
 }
 /* Exercise the real pending-wakeup caller with literal percent-bearing data. */
 for(int n=0;n<4;n++) {
  nodes[0]=(struct wakeup_source){.name=names[n],.active=true}; wakeup_sources=nodes;
  snprintf(expected,sizeof(expected),"Pending Wakeup Sources: %s ",names[n]);
  events_check_enabled=true; saved_count=0; pm_abort_suspend=0; log_message[0]=0;
  CHECK(pm_wakeup_pending()); CHECK(!events_check_enabled);
  CHECK(!strcmp(log_message,expected)); cases++;
 }
 printf("{\"cases\":%d,\"failures\":%d}\n",cases,failures);
 return failures ? 1 : 0;
}
'''

def run(source, path):
    extracted='\n'.join(function(source,n) for n in ['pm_get_active_wakeup_sources','pm_wakeup_pending'])
    path.with_suffix('.c').write_text(C+extracted+MAIN)
    subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-function',str(path.with_suffix('.c')),'-o',str(path)],check=True)
    result=subprocess.run([str(path)],capture_output=True,text=True)
    return result.returncode,json.loads(result.stdout),hashlib.sha256(extracted.encode()).hexdigest()

if __name__=='__main__':
    source=(ROOT/FILE).read_text()
    old=subprocess.check_output(['git','show',ACK+':'+FILE],cwd=ROOT,text=True)
    with tempfile.TemporaryDirectory(prefix='wakeup-source-review-') as t:
        rc,current,digest=run(source,Path(t)/'current')
        old_rc,control,_=run(old,Path(t)/'original')
    assert rc==0 and not current['failures'],current
    assert old_rc==1 and control['failures']>0,control
    report=dict(path=FILE,extracted_sha256=digest,current=current,original_ack_control=control,
                scope='Actual report helper and pending-wakeup caller; host bounded-format/list/SRCU-domain/counter shims. Empty list, zero/short/full output buffers, active/last-active selection, literal percent-bearing names, canaries, balanced native read-side-domain contract and constant-format caller.',
                limits='No actual RCU grace period, SRCU scheduling, concurrent wakeup-source removal, kernel format implementation or suspend. Wrong-domain failures are explicit shim observations; old variadic misuse is detected without evaluating missing arguments or claiming an exploit.',remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/wakeup-source-report-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
