#!/usr/bin/env python3
"""Exercise extracted F2FS callback control flow with host shims, not real I/O."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]

def function(src, name):
    m = re.search(r'^.*\b' + name + r'\([^;{]*\)\n\{', src, re.M)
    assert m, name
    i, depth = m.end(), 1
    while depth:
        depth += (src[i] == '{') - (src[i] == '}')
        i += 1
    return src[m.start():i] + '\n'

sources = {p: (ROOT/p).read_text() for p in
           ['fs/f2fs/f2fs.h', 'fs/f2fs/file.c', 'fs/f2fs/checkpoint.c']}
body = function(sources['fs/f2fs/f2fs.h'], 'f2fs_down_read')
body += function(sources['fs/f2fs/file.c'], 'f2fs_buffered_write_iter')
cp = function(sources['fs/f2fs/checkpoint.c'], 'f2fs_issue_checkpoint')
start = cp.index('\tckpt_task = get_ckpt_task(cprc);')
end = cp.index('\n\tif (unlikely(req.delta_time', start)
body += function(sources['fs/f2fs/checkpoint.c'], 'get_ckpt_task')
body += 'static void checkpoint_wait(struct ckpt_req_control *cprc) {\n'
body += 'struct request req; struct f2fs_sb_info *sbi = NULL; struct task_struct *ckpt_task;\n' + cp[start:end] + '\n}\n'
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#define IOCB_NOWAIT 1
#define APP_BUFFERED_IO 1
#define READ_ONCE(x) (x)
struct rw_semaphore { int held; };
typedef struct { int initialized; } wait_queue_head_t;
struct f2fs_rwsem {
    struct rw_semaphore internal_rwsem;
#ifdef CONFIG_F2FS_UNFAIR_RWSEM
    wait_queue_head_t read_waiters;
#endif
};
struct f2fs_sb_info {};
struct inode {};
struct file { struct inode *inode; };
struct kiocb { struct file *ki_filp; unsigned ki_flags; };
struct iov_iter {};
struct task_struct { int prio, refs; };
struct ckpt_req_control { struct task_struct *f2fs_issue_ckpt; int stat_lock; };
struct request { int wait; };
static unsigned failures, assertions, cases;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
 if (failures<10) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while (0)
static int mode, calls, locks, writes, stats, bytes, waits, restores, flushes;
static ssize_t write_result;
static struct task_struct *expected_task;
static struct ckpt_req_control *expected_control;
static bool stop_during_wait;
static void down_read(struct rw_semaphore *r) { CHECK(!r->held); r->held++; locks++; }
static int down_read_trylock(struct rw_semaphore *r) { down_read(r); return 1; }
#define wait_event(q, cond) do { CHECK((q).initialized); CHECK(cond); } while (0)
static void _trace_android_rvh_f2fs_down_read(wait_queue_head_t *w,
        struct rw_semaphore *r, bool *skip) {
    calls++; CHECK(!r->held && !*skip);
#ifdef CONFIG_F2FS_UNFAIR_RWSEM
    CHECK(w && w->initialized);
#else
    CHECK(!w);
#endif
    if (mode) { down_read(r); *skip=true; }
}
static struct inode *file_inode(struct file *f) { return f->inode; }
#define F2FS_I_SB(i) NULL
static void trace_android_rvh_f2fs_buffer_write(struct kiocb *i,
        struct iov_iter *v, ssize_t *r, bool *done) {
    calls++; CHECK(!*done);
    if (mode) { *done=true; if (mode==1) *r=write_result; }
}
static ssize_t generic_perform_write(struct kiocb *i, struct iov_iter *v) {
    writes++; return write_result;
}
static void f2fs_update_iostat(struct f2fs_sb_info *s, struct inode *i, int t, ssize_t n) {
    CHECK(t==APP_BUFFERED_IO && n>0); stats++; bytes=n;
}
static void trace_android_vh_f2fs_improve_priority(struct task_struct *p, int *saved, bool *changed) {
    CHECK(p==expected_task && !*changed); calls++;
    if (mode) { if (mode==1) *saved=p->prio; p->prio=100; *changed=true; }
}
static void spin_lock(int *lock) { CHECK(!(*lock)++); }
static void spin_unlock(int *lock) { CHECK(--(*lock)==0); }
static void get_task_struct(struct task_struct *p) {
    CHECK(expected_control->stat_lock && p->refs>0); p->refs++;
}
static void put_task_struct(struct task_struct *p) {
    CHECK(p==expected_task && p->refs>0); p->refs--;
}
static void wait_for_completion(int *w) {
    waits++;
    if (stop_during_wait) {
        spin_lock(&expected_control->stat_lock);
        expected_control->f2fs_issue_ckpt=NULL;
        spin_unlock(&expected_control->stat_lock);
        put_task_struct(expected_task);
    }
}
static void trace_android_vh_f2fs_restore_priority(struct task_struct *p, int saved) {
    CHECK(p==expected_task && waits==1 && p->refs>0); restores++; p->prio=saved;
}
static void flush_remained_ckpt_reqs(struct f2fs_sb_info *s, struct request *r) { flushes++; }
'''
suffix = r'''
int main(void) {
    for (mode=0;mode<2;mode++) {
        struct f2fs_rwsem sem={0};
#ifdef CONFIG_F2FS_UNFAIR_RWSEM
        sem.read_waiters.initialized=1;
#endif
        calls=locks=0; f2fs_down_read(&sem);
        CHECK(calls==1 && locks==1 && sem.internal_rwsem.held==1); cases++;
    }
    ssize_t results[]={-EIO,-ENOSPC,0,1,4096};
    for (mode=0;mode<3;mode++) for (int nowait=0;nowait<2;nowait++)
    for (unsigned n=0;n<sizeof(results)/sizeof(results[0]);n++) {
        struct inode inode; struct file f={&inode}; struct kiocb i={&f,nowait};
        struct iov_iter v; calls=writes=stats=bytes=0; write_result=results[n];
        ssize_t want=nowait ? -EOPNOTSUPP : mode==2 ? -EIO : write_result;
        CHECK(f2fs_buffered_write_iter(&i,&v)==want);
        CHECK(calls==!nowait && writes==(!nowait && !mode));
        CHECK(stats==(want>0) && bytes==(want>0 ? want:0)); cases++;
    }
    for (mode=0;mode<3;mode++) for (int present=0;present<2;present++)
    for (int stop=0;stop<2;stop++) {
        struct task_struct task={125,1}; expected_task=&task;
        struct ckpt_req_control c={.f2fs_issue_ckpt=present ? &task:NULL};
        expected_control=&c; stop_during_wait=stop;
        calls=waits=restores=flushes=0; checkpoint_wait(&c);
        CHECK(calls==present && waits==present && flushes==!present);
        CHECK(restores==(present && mode) && task.prio==125);
        CHECK(task.refs==!(present && stop) && !c.stat_lock); cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
variants = {
    'port': body,
    'false_write_success_control': body.replace('ssize_t ret = -EIO;', 'ssize_t ret = 0;'),
    'duplicate_read_lock_control': body.replace('\tif (skip)\n\t\treturn;', ''),
    'unreferenced_task_control': body.replace('get_task_struct(task);', '(void)task;').replace('put_task_struct(ckpt_task);', '(void)ckpt_task;'),
    'lost_priority_restore_control': body.replace('if (prio_changed)', 'if (false && prio_changed)'),
}
runs = {}
with tempfile.TemporaryDirectory(prefix='f2fs-hook-check-') as tmp:
    for unfair in (False, True):
        for name, code in variants.items():
            label = name + ('_unfair' if unfair else '_fair')
            c, exe = Path(tmp)/(label+'.c'), Path(tmp)/label
            c.write_text(prefix+code+suffix)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror',
                            '-Wno-unused-function', '-Wno-unused-parameter',
                            '-fsanitize=undefined', '-fno-sanitize-recover=all',
                            *(['-DCONFIG_F2FS_UNFAIR_RWSEM'] if unfair else []),
                            str(c), '-o', str(exe)], check=True)
            p = subprocess.run([str(exe)], capture_output=True, text=True)
            assert (p.returncode == 0) == (name == 'port'), (label,p.stdout,p.stderr)
            runs[label] = dict(exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr)
report = dict(scope=__doc__, source_sha256={p:hashlib.sha256(s.encode()).hexdigest()
              for p,s in sources.items()}, runs=runs, remote_resources=[])
(D/'evidence/f2fs-hook-contracts-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(runs['port_fair']['stdout'].strip(), '(fair)')
print(runs['port_unfair']['stdout'].strip(), '(unfair)')
print('All eight regression controls rejected')
