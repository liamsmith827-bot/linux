#!/usr/bin/env python3
"""Exercise the extracted sysfs show function, including an absent timer.

This uses host shims, not live sysfs, timer callbacks or concurrent deletion.
The original ACK function is a negative control; a child process confines its
expected null-pointer fault and disables core dumps.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

D = Path(__file__).resolve().parent
R = D.parents[1]
path = 'net/netfilter/xt_IDLETIMER.c'
ack = '23112ce1886ea26b19be03207c0227a06a6ca009'

def function(source):
    start = source.index('static ssize_t idletimer_tg_show(')
    end = source.index('\n}', start) + 2
    return source[start:end]

current = function((R/path).read_text())
original = function(subprocess.check_output(['git', 'show', ack+':'+path], cwd=R, text=True))
assert 'timer->' not in current.split('mutex_unlock(&list_mutex);')[1]
preamble = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#define XT_IDLETIMER_ALARM 1
struct device { int unused; };
struct device_attribute { struct { const char *name; } attr; };
struct timespec64 { long tv_sec; long tv_nsec; };
typedef long ktime_t;
struct idletimer_tg {
    bool send_nl_msg;
    unsigned int timer_type;
    struct { unsigned long expires; } timer;
    long alarm;
};
static struct idletimer_tg *selected;
static unsigned long jiffies;
static int list_mutex, locked;
static void mutex_lock(int *p) { (void)p; assert(!locked); locked = 1; }
static void mutex_unlock(int *p) { (void)p; assert(locked); locked = 0; }
static struct idletimer_tg *__idletimer_tg_find_by_label(const char *name)
{ (void)name; assert(locked); return selected; }
static ktime_t alarm_expires_remaining(long *alarm) { assert(locked); return *alarm; }
static struct timespec64 ktime_to_timespec64(ktime_t t)
{ return (struct timespec64){.tv_sec=t}; }
static unsigned int jiffies_to_msecs(unsigned long j) { return (unsigned int)(j * 4); }
#define time_after(a,b) ((long)((b)-(a)) < 0)
static int sysfs_emit(char *buf, const char *format, ...)
{
    va_list ap; int n;
    assert(!locked);
    va_start(ap,format); n=vsnprintf(buf,4096,format,ap); va_end(ap); return n;
}
'''
main = r'''
int main(void)
{
    struct rlimit lim={0,0}; assert(!setrlimit(RLIMIT_CORE,&lim));
    char buf[4096],want[4096];
    struct device_attribute attr={.attr.name="test"};
    struct idletimer_tg timer;
    unsigned count=0;
    const long delta[]={-500,-250,-1,0,1,249,250,500};
    const long alarm[]={-2,-1,0,1,2};
    for (unsigned i=0;i<4;i++) {
        pid_t pid=fork(); assert(pid>=0);
        if (!pid) {
            selected=NULL; jiffies=i*1000;
            int n=idletimer_tg_show(NULL,&attr,buf);
            _exit(n==2 && !strcmp(buf,"0\n") ? 0 : 2);
        }
        int status; assert(waitpid(pid,&status,0)==pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
            printf("absent-timer failure: signal=%d exit=%d\n",
                   WIFSIGNALED(status)?WTERMSIG(status):0,
                   WIFEXITED(status)?WEXITSTATUS(status):-1);
            return 1;
        }
        count++;
    }
    for (unsigned now=1000;now<=4000;now+=1000)
    for (unsigned notify=0;notify<2;notify++)
    for (unsigned type=0;type<2;type++)
    for (unsigned i=0;i<sizeof(delta)/sizeof(delta[0]);i++)
    for (unsigned j=0;j<sizeof(alarm)/sizeof(alarm[0]);j++) {
        timer=(struct idletimer_tg){.send_nl_msg=notify,.timer_type=type,
                                  .timer.expires=now+delta[i],.alarm=alarm[j]};
        selected=&timer; jiffies=now;
        if ((!type && delta[i]>0) || (type && alarm[j]>0))
            snprintf(want,sizeof(want),"%ld\n",type?alarm[j]:delta[i]*4/1000);
        else if (notify)
            snprintf(want,sizeof(want),"0 %ld\n",type?(long)now*4/1000:-delta[i]*4/1000);
        else
            snprintf(want,sizeof(want),"0\n");
        int n=idletimer_tg_show(NULL,&attr,buf);
        if (n!=(int)strlen(want) || strcmp(buf,want)) {
            fprintf(stderr,"mismatch: got %s wanted %s",buf,want); return 2;
        }
        count++;
    }
    printf("%u cases passed\n",count);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='idletimer-show-') as td:
    td=Path(td);results={}
    for name,body in [('current',current),('original_ack',original)]:
        c=td/(name+'.c');exe=td/name;c.write_text(preamble+'\n'+body+'\n'+main)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-parameter','-Werror',str(c),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],text=True,capture_output=True)
        results[name]={'exit_code':r.returncode,'output':r.stdout.strip(),'stderr':r.stderr.strip()}
    assert results['current']['exit_code']==0,results
    assert results['original_ack']['exit_code']!=0 and 'signal=11' in results['original_ack']['output'],results
report={'source_path':path,'source_function_sha256':hashlib.sha256(current.encode()).hexdigest(),
        'original_ack':ack,'results':results,
        'scope':'Extracted function with host HZ=250 conversion and mutex/lookup/output shims. Four absent-timer cases and 640 existing-timer cases cover alarm/non-alarm, notification mode, active/expired and subsecond formatting. Original ACK negative control faults on absent timer. Does not execute live sysfs, kernel timer APIs, concurrency or authorization.',
        'post_unlock_pointer_check':'No timer dereference after list_mutex unlock in current function.'}
(D/'evidence/idletimer-show-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
