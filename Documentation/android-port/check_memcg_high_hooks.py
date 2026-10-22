#!/usr/bin/env python3
"""Exercise the extracted memory.high control path with host policy shims.

Checks hook removal between retries, native reclaim resumption, PSI policy,
bounded default penalties and reference cleanup. No kernel reclaim, pressure
measurement, cgroup syscall or Android LMK execution is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
path = 'mm/memcontrol.c'
baseline = '623c51beadea'
baseline = subprocess.check_output(['git', 'rev-parse', baseline], cwd=root, text=True).strip()
source = (root / path).read_text()
old = subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)

def function(text):
    start = text.index('void __mem_cgroup_handle_over_high(')
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#define MAX_RECLAIM_RETRIES 2
#define SWAP_CLUSTER_MAX 32
#define MEMCG_MAX_HIGH_DELAY_JIFFIES 1000UL
#define HZ 100
#define min(a,b) ((a)<(b)?(a):(b))
typedef unsigned int gfp_t;
struct mem_cgroup {int css;};
struct task {void *mm; unsigned int memcg_nr_pages_over_high;};
static struct task task;
static struct task *current=&task;
static struct mem_cgroup group;
static unsigned int hook_calls,reclaims,checks,css_releases,sleeps,psi_enter,psi_leave;
static unsigned long slept,delay;
static int mode;
static bool record,dying;
static struct mem_cgroup *get_mem_cgroup_from_mm(void *mm) {(void)mm;return &group;}
static bool task_is_dying(void) {return ++checks>8 || dying;}
static void trace_android_vh_mem_cgroup_over_high_reclaim(struct mem_cgroup *m,
    unsigned int n,bool retry,unsigned long *reclaimed,bool *skip) {
    (void)m;(void)n;(void)retry;hook_calls++;
    if (mode==1 && hook_calls==1) {*skip=true;*reclaimed=1;}
    if (mode==2) {*skip=true;}
}
static unsigned long reclaim_high(struct mem_cgroup *m,unsigned int n,gfp_t gfp) {
    (void)m;(void)n;(void)gfp;reclaims++;return 0;
}
static unsigned long mem_find_max_overage(struct mem_cgroup *m) {(void)m;return 1;}
static unsigned long swap_find_max_overage(struct mem_cgroup *m) {(void)m;return 0;}
static unsigned long calculate_high_delay(struct mem_cgroup *m,unsigned int n,unsigned long over) {
    (void)m;(void)n;return over?delay:0;
}
static void trace_android_vh_mem_cgroup_over_high_penalty(struct mem_cgroup *m,
    unsigned int n,unsigned long *penalty,bool *force) {
    (void)m;(void)n;if (mode==3) {*penalty=17;*force=true;}
}
static void trace_android_vh_mem_cgroup_handle_over_high(bool *r) {if(record)*r=true;}
static void psi_memstall_enter(unsigned long *flags) {*flags=42;psi_enter++;}
static void psi_memstall_leave(unsigned long *flags) {assert(*flags==42);psi_leave++;}
static void schedule_timeout_killable(unsigned long n) {sleeps++;slept=n;}
static void css_put(int *css) {assert(css==&group.css);css_releases++;}
'''

tests = r'''
static void setup(int m,bool rec) {
    mode=m;record=rec;dying=false;delay=200;
    hook_calls=reclaims=checks=css_releases=sleeps=psi_enter=psi_leave=0;slept=0;
    task.memcg_nr_pages_over_high=100;
}
int main(void) {
    for (int rec=0;rec<2;rec++) {
        setup(0,rec);__mem_cgroup_handle_over_high(0);
        assert(reclaims==3 && sleeps==1 && slept==200 && css_releases==1);
        assert(psi_enter==(unsigned)rec && psi_leave==(unsigned)rec);
        assert(task.memcg_nr_pages_over_high==0);
        setup(1,rec);__mem_cgroup_handle_over_high(0);
        assert(hook_calls==4 && reclaims==3 && sleeps==1 && css_releases==1);
        assert(psi_enter==(unsigned)rec && psi_leave==(unsigned)rec);
        setup(2,rec);__mem_cgroup_handle_over_high(0);
        assert(hook_calls==3 && reclaims==0 && sleeps==1 && css_releases==1);
        setup(3,rec);__mem_cgroup_handle_over_high(0);
        assert(reclaims==1 && sleeps==1 && slept==17 && css_releases==1);
        setup(0,rec);delay=100000;__mem_cgroup_handle_over_high(0);
        assert(slept==MEMCG_MAX_HIGH_DELAY_JIFFIES && css_releases==1);
        setup(0,rec);delay=1;__mem_cgroup_handle_over_high(0);
        assert(reclaims==1 && sleeps==0 && css_releases==1);
        setup(0,rec);dying=true;__mem_cgroup_handle_over_high(0);
        assert(reclaims==0 && sleeps==0 && css_releases==1);
        setup(1,rec);old_mem_cgroup_handle_over_high(0);
        assert(checks==9 && reclaims==0 && sleeps==0 && css_releases==1);
    }
    printf("14 policy/retry/cleanup cases passed; 2 old-source stale-bypass controls reproduced\n");
}
'''

with tempfile.TemporaryDirectory(prefix='ack-memcg-high-') as t:
    c = Path(t) / 'check.c'
    binary = Path(t) / 'check'
    c.write_text(shim + function(source) + function(old).replace(
        '__mem_cgroup_handle_over_high', 'old_mem_cgroup_handle_over_high', 1) + tests)
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', str(c), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
report = {
    'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
    'baseline': baseline,
    'result': result.stdout.strip(),
    'limits': 'Extracted function with host policy/reclaim shims and UBSan; no kernel memory pressure, cgroup syscall, race or Android LMK tested.',
}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(report['result'])
