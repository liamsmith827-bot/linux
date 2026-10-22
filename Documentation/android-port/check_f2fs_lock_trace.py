#!/usr/bin/env python3
"""Exercise extracted lock wrappers; compare caller code before instrumentation.

Host shims do not test kernel locking, scheduling, tracing or filesystem I/O.
"""
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
BASE = '6d054c066004'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True)

def function(source, name):
    m = re.search(r'^.*\b' + name + r'\([^;{]*\)\n\{', source, re.M)
    assert m, name
    start = m.start()
    depth = 1
    i = m.end()
    while depth:
        depth += (source[i] == '{') - (source[i] == '}')
        i += 1
    return source[start:i] + '\n'

source = (ROOT / 'fs/f2fs/checkpoint.c').read_text()
names = ['get_lock_elapsed_time', 'trace_lock_elapsed_time_start',
         'trace_lock_elapsed_time_end', 'need_uplift_priority',
         'uplift_priority', 'restore_priority', 'f2fs_down_read_trace',
         'f2fs_down_read_trylock_trace', 'f2fs_up_read_trace',
         'f2fs_down_write_trace', 'f2fs_down_write_trylock_trace',
         'f2fs_up_write_trace']
body = '\n'.join(function(source, n) for n in names)
prefix = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define CONFIG_64BIT 1
#define CONFIG_SCHED_INFO 1
#define CONFIG_SCHEDSTATS 1
#define CONFIG_TASK_DELAY_ACCT 1
#define NSEC_PER_MSEC 1000000
#define BIT(n) (1UL << (n))
#define PRIO_TO_NICE(p) ((p) - 120)
#define NICE_TO_PRIO(n) ((n) + 120)
#define f2fs_bug_on(s, c) do { if (c) abort(); } while (0)
enum { LOCK_NAME_NONE, LOCK_NAME_CP_RWSEM, LOCK_NAME_NODE_CHANGE,
       LOCK_NAME_NODE_WRITE, LOCK_NAME_GC_LOCK, LOCK_NAME_CP_GLOBAL,
       LOCK_NAME_IO_RWSEM, LOCK_NAME_NAT_TREE_LOCK, LOCK_NAME_MAX };
struct f2fs_time_stat { unsigned long long total_time, running_time,
                       runnable_time, io_sleep_time; };
struct f2fs_lock_context { struct f2fs_time_stat ts; int orig_nice, new_nice;
                          bool lock_trace, need_restore; };
struct f2fs_sb_info { unsigned adjust_lock_priority, lock_duration_priority;
                     unsigned long long max_lock_elapsed_time; };
struct f2fs_rwsem { struct f2fs_sb_info *sbi; unsigned name; int held; };
struct delays { unsigned long long blkio_delay; };
struct task { int nice; bool rt; struct { unsigned long long sum_exec_runtime; } se;
              struct { unsigned long long run_delay; } sched_info;
              struct delays *delays; } task;
#define current (&task)
static unsigned long long now;
static int try_success, trace_on, traces, changes, assertions, failures;
static unsigned long long last_io;
static unsigned long long ktime_get(void) { return now; }
static unsigned long long div_u64(unsigned long long x, unsigned d) { return x/d; }
static int trace_f2fs_lock_elapsed_time_enabled(void) { return trace_on; }
static int get_current_ioprio(void) { return 0; }
static int task_nice(struct task *t) { return t->nice; }
static int rt_task(struct task *t) { return t->rt; }
static void set_user_nice(struct task *t, int n) { t->nice=n; changes++; }
#define trace_f2fs_priority_uplift(...) ((void)0)
#define trace_f2fs_priority_restore(...) ((void)0)
static void trace_f2fs_lock_elapsed_time(struct f2fs_sb_info *s, unsigned name,
        bool wr, struct task *t, int p, unsigned long long total,
        unsigned long long running, unsigned long long runnable,
        unsigned long long io, unsigned long long other)
{ traces++; last_io=io; }
static void f2fs_down_read(struct f2fs_rwsem *s) { s->held++; }
static void f2fs_down_write(struct f2fs_rwsem *s) { s->held++; }
static void f2fs_up_read(struct f2fs_rwsem *s) { s->held--; }
static void f2fs_up_write(struct f2fs_rwsem *s) { s->held--; }
static int f2fs_down_read_trylock(struct f2fs_rwsem *s)
{ if (try_success) s->held++; return try_success; }
static int f2fs_down_write_trylock(struct f2fs_rwsem *s)
{ if (try_success) s->held++; return try_success; }
#define CHECK(c) do { assertions++; if (!(c)) { failures++; \
    fprintf(stderr,"failed line %d: %s\n",__LINE__,#c); } } while(0)
'''
suffix = r'''
int main(void) {
    struct f2fs_sb_info sbi = {0, 110, 500};
    struct f2fs_rwsem sem = {&sbi, LOCK_NAME_CP_RWSEM, 0};
    struct f2fs_lock_context lc, inner;
    struct delays delay = {12000000};
    struct f2fs_time_stat ts;
    memset(&ts, 0xa5, sizeof(ts));
    get_lock_elapsed_time(&ts);
    CHECK(ts.io_sleep_time == 0);
    task.delays=&delay; get_lock_elapsed_time(&ts);
    CHECK(ts.io_sleep_time == delay.blkio_delay);
    task.delays=NULL;
    for (unsigned name=LOCK_NAME_CP_RWSEM; name<LOCK_NAME_MAX; name++) {
        for (int wr=0; wr<2; wr++) {
            sem.name=name; sbi.adjust_lock_priority=0; task.nice=10;
            changes=0; memset(&lc, 0xa5, sizeof(lc));
            if (wr) f2fs_down_write_trace(&sem,&lc);
            else f2fs_down_read_trace(&sem,&lc);
            CHECK(task.nice==10 && !lc.need_restore && sem.held==1);
            if (wr) f2fs_up_write_trace(&sem,&lc);
            else f2fs_up_read_trace(&sem,&lc);
            CHECK(sem.held==0 && changes==0);
            sbi.adjust_lock_priority=BIT(name-1); try_success=0;
            int ret=wr ? f2fs_down_write_trylock_trace(&sem,&lc) :
                         f2fs_down_read_trylock_trace(&sem,&lc);
            CHECK(!ret && !sem.held && task.nice==10);
            try_success=1;
            ret=wr ? f2fs_down_write_trylock_trace(&sem,&lc) :
                     f2fs_down_read_trylock_trace(&sem,&lc);
            bool boost=!(wr && name<=LOCK_NAME_NODE_WRITE);
            CHECK(ret && sem.held==1 && task.nice==(boost ? -10 : 10));
            if (wr) f2fs_up_write_trace(&sem,&lc);
            else f2fs_up_read_trace(&sem,&lc);
            CHECK(!sem.held && task.nice==10);
        }
    }
    sem.name=LOCK_NAME_CP_RWSEM; sbi.adjust_lock_priority=1;
    task.rt=true; task.nice=10;
    f2fs_down_read_trace(&sem,&lc); CHECK(task.nice==10 && !lc.need_restore);
    f2fs_up_read_trace(&sem,&lc); task.rt=false;
    task.nice=-15;
    f2fs_down_read_trace(&sem,&lc); CHECK(task.nice==-15 && !lc.need_restore);
    f2fs_up_read_trace(&sem,&lc);
    task.nice=10;
    f2fs_down_read_trace(&sem,&lc); f2fs_down_read_trace(&sem,&inner);
    f2fs_up_read_trace(&sem,&inner); CHECK(task.nice==-10 && sem.held==1);
    f2fs_up_read_trace(&sem,&lc); CHECK(task.nice==10 && !sem.held);
    f2fs_down_read_trace(&sem,&lc); task.nice=5;
    f2fs_up_read_trace(&sem,&lc); CHECK(task.nice==5);
    trace_on=1; task.nice=10; now=0;
    memset(&lc,0xa5,sizeof(lc));
    f2fs_down_read_trace(&sem,&lc); now=600000000;
    f2fs_up_read_trace(&sem,&lc); CHECK(traces==1 && last_io==0);
    printf("assertions=%d failures=%d\n",assertions,failures);
    return failures ? 1 : 0;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-lock-check-') as tmp:
    tmp = Path(tmp)
    runs = {}
    for label, extracted in [('port', body), ('ack-control', body.replace(
            function(source, 'get_lock_elapsed_time'),
            function(git('show', ACK + ':fs/f2fs/checkpoint.c'),
                     'get_lock_elapsed_time')))]:
        c = tmp / (label + '.c'); exe = tmp / label
        c.write_text(prefix + extracted + suffix)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', str(c), '-o', str(exe)], check=True)
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        runs[label] = {'returncode': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr}
    assert runs['port']['returncode'] == 0, runs
    assert runs['ack-control']['returncode'] != 0, runs

def normalize_callers(s):
    s = re.sub(r'\bstruct f2fs_lock_context [^;{}]+;\n', '', s)
    s = re.sub(r'\bstruct f2fs_lock_context \*lc,\s*', '', s)
    s = re.sub(r',\s*struct f2fs_lock_context \*lc', '', s)
    s = re.sub(r',\s*&(?:[cgn]?lc|gc_control(?:\.|->)lc)\b', '', s)
    s = re.sub(r',\s*lc\b', '', s)
    s = re.sub(r'\bf2fs_(down_read|up_read|down_write|up_write|down_read_trylock|down_write_trylock)_trace\b', r'f2fs_\1', s)
    s = re.sub(r'init_f2fs_rwsem_trace\(([^,]+),\s*sbi,\s*LOCK_NAME_\w+\)', r'init_f2fs_rwsem(\1)', s)
    s = re.sub(r'\s*set_user_nice\(gc_th->f2fs_gc_task,\s*PRIO_TO_NICE\(sbi->critical_task_priority\)\);', '', s)
    return re.sub(r'\s+', '', s)

callers = ['compress', 'data', 'file', 'gc', 'inline', 'inode', 'namei',
           'node', 'recovery', 'segment', 'xattr']
for name in callers:
    path = 'fs/f2fs/' + name + '.c'
    before = normalize_callers(git('show', BASE + ':' + path))
    after = normalize_callers((ROOT / path).read_text())
    if before != after:
        raise AssertionError('Unexpected caller difference: ' + path + '\n' +
                             '\n'.join(difflib.unified_diff(
                                 before.split(';'), after.split(';'))))
report = {'baseline': git('rev-parse', BASE).strip(),
          'source_head': git('rev-parse', 'HEAD').strip(),
          'checkpoint_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
          'extracted_functions': names, 'runs': runs,
          'caller_comparisons': callers,
          'comparison_scope': 'Whole caller files equal after removing lock-context declarations/arguments, normalizing wrapper/init names, and removing the explicitly reviewed GC-thread nice setter. Whitespace ignored; no control-flow changes hidden.',
          'scope': __doc__}
(D / 'evidence/f2fs-lock-trace-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(runs['port']['stdout'].strip(), '; ACK control rejected; caller files:', len(callers))
