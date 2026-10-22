#!/usr/bin/env python3
"""Exercise extracted checkpoint/writeback control flow with host shims.

No actual filesystem, storage, kernel locking, or concurrent writeback is tested.
"""
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

sources = {p: (ROOT / p).read_text() for p in ['fs/f2fs/data.c', 'fs/f2fs/super.c']}
body = '\n'.join(function(sources[p], n) for p, n in [
    ('fs/f2fs/data.c', 'update_skipped_write'),
    ('fs/f2fs/data.c', '__f2fs_write_data_pages'),
    ('fs/f2fs/super.c', 'f2fs_enable_checkpoint')])
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
enum { F2FS_DIRTY_META, F2FS_DIRTY_NODES, F2FS_DIRTY_DATA,
       F2FS_SKIPPED_WRITE, NR_COUNT };
enum { SBI_ENABLE_CHECKPOINT, SBI_CP_DISABLED, SBI_IS_DIRTY, SBI_POR_DOING };
enum { WB_SYNC_NONE, WB_SYNC_ALL };
enum iostat_type { FS_DATA_IO };
#define DATA 0
#define DIRTY_DENTS 0
#define FI_SKIP_WRITES 1
#define MAX_FLUSH_RETRY_COUNT 3
#define DEFAULT_SCHEDULE_TIMEOUT 1
#define unlikely(c) (c)
#define S_ISDIR(m) ((m)==1)
#define IS_NOQUOTA(i) ((i)->quota)
struct f2fs_lock_context { int unused; };
struct f2fs_sb_info;
struct super_block { struct f2fs_sb_info *owner; };
struct f2fs_sb_info { int nr_pages[NR_COUNT], wb_sync_req[1], writepages,
                     gc_lock; unsigned flags; struct super_block *sb; };
struct inode { struct f2fs_sb_info *sbi; int dirty, i_mode; bool quota, skip; };
struct address_space { struct inode *host; };
struct writeback_control { int sync_mode; long pages_skipped; };
struct blk_plug { int unused; };
static struct { struct blk_plug *plug; } task;
#define current (&task)
#define F2FS_I_SB(i) ((i)->sbi)
static unsigned assertions, failures, cases;
#define CHECK(c) do { assertions++; if (!(c)) { failures++; \
    if (failures<15) fprintf(stderr,"line %d: %s\n",__LINE__,#c); } } while(0)
static int syncs, drains, flushes, sleeps, io_error, serialize;
static int hook_mode, hook_status, write_status, removed, accounted, native_calls;
static long skipped;
static int plan;
static long long ticks;
static void atomic_add(int n, int *p) { *p+=n; }
static void atomic_set(int *p, int n) { *p=n; }
static void atomic_inc(int *p) { ++*p; }
static void atomic_dec(int *p) { --*p; }
static int atomic_read(int *p) { return *p; }
static long long get_pages(struct f2fs_sb_info *s, int n) { return s->nr_pages[n]; }
static void set_sbi_flag(struct f2fs_sb_info *s, int n) { s->flags |= 1U<<n; }
static void clear_sbi_flag(struct f2fs_sb_info *s, int n) { s->flags &= ~(1U<<n); }
static bool is_sbi_flag_set(struct f2fs_sb_info *s, int n) { return s->flags & (1U<<n); }
static int get_dirty_pages(struct inode *i) { return i->dirty; }
static int nr_pages_to_skip(struct f2fs_sb_info *s, int type) { return 4; }
static bool f2fs_available_free_memory(struct f2fs_sb_info *s, int t) { return true; }
static bool is_inode_flag_set(struct inode *i, int f) { return i->skip; }
static void trace_f2fs_writepages(struct inode *i, struct writeback_control *w, int t) {}
static void mutex_lock(int *m) { CHECK(!(*m)++); }
static void mutex_unlock(int *m) { CHECK(--(*m)==0); }
static bool __should_serialize_io(struct inode *i, struct writeback_control *w)
{ return serialize; }
static void account_writeback(struct inode *i, bool inc) { accounted += inc?1:-1; }
static void blk_start_plug(struct blk_plug *p) {}
static void blk_finish_plug(struct blk_plug *p) {}
static void trace_android_rvh_f2fs_write_cache_pages(struct address_space *m,
        struct writeback_control *w, int *ret, bool *done)
{ if (hook_mode) { *done=true; w->pages_skipped+=skipped;
                  if (hook_mode==1) *ret=hook_status; } }
static int f2fs_write_cache_pages(struct address_space *m,
        struct writeback_control *w, enum iostat_type t)
{ native_calls++; w->pages_skipped+=skipped; return write_status; }
static void f2fs_remove_dirty_inode(struct inode *i) { removed++; }
static void f2fs_info(struct f2fs_sb_info *s, const char *fmt, ...) {}
static void f2fs_warn(struct f2fs_sb_info *s, const char *fmt, ...) {}
static void f2fs_err(struct f2fs_sb_info *s, const char *fmt, ...) {}
static long long ktime_get(void) { return ticks++; }
static long long ktime_ms_delta(long long a, long long b) { return a-b; }
static void sync_inodes_sb(struct super_block *sb);
static void f2fs_io_schedule_timeout(int n) { CHECK(n==1); sleeps++; }
static void f2fs_down_write_trace(int *m, struct f2fs_lock_context *l) { mutex_lock(m); }
static void f2fs_up_write_trace(int *m, struct f2fs_lock_context *l) { mutex_unlock(m); }
static void f2fs_dirty_to_prefree(struct f2fs_sb_info *s)
{ CHECK(s->gc_lock && is_sbi_flag_set(s,SBI_CP_DISABLED)); drains++; }
static int f2fs_sync_fs(struct super_block *sb, int wait)
{ CHECK(!is_sbi_flag_set(sb->owner,SBI_CP_DISABLED)); CHECK(wait==1); return io_error; }
static void f2fs_flush_ckpt_thread(struct f2fs_sb_info *s) { flushes++; }
'''
suffix = r'''
static void sync_inodes_sb(struct super_block *sb)
{
    struct f2fs_sb_info *s=sb->owner;
    CHECK(is_sbi_flag_set(s,SBI_ENABLE_CHECKPOINT));
    CHECK(is_sbi_flag_set(s,SBI_CP_DISABLED)); syncs++;
    struct inode inode={.sbi=s,.dirty=5};
    struct address_space mapping={&inode};
    struct writeback_control w={.sync_mode=WB_SYNC_ALL};
    hook_mode=(plan==2 || plan==4); hook_status=0;
    write_status=plan==3 ? -EIO:0;
    skipped=plan>=2 ? 5:0;
    __f2fs_write_data_pages(&mapping,&w,FS_DATA_IO);
    if (plan==0 || (plan==4 && syncs==2)) s->nr_pages[F2FS_DIRTY_DATA]=0;
}
static void reset(void)
{
    syncs=drains=flushes=sleeps=io_error=serialize=0;
    hook_mode=hook_status=write_status=removed=accounted=native_calls=0;
    skipped=0;
}
int main(void)
{
    /* Existing dirty pages cleared, new concurrent dirties, persistent
       skipped writes (hook/native error), and a second-pass success. */
    const int expected[]={1,1,4,4,2};
    for (plan=0;plan<5;plan++) for (int err=0;err<2;err++) {
        reset(); cases++;
        struct f2fs_sb_info s={0}; struct super_block sb={&s}; s.sb=&sb;
        s.nr_pages[F2FS_DIRTY_DATA]=5; set_sbi_flag(&s,SBI_CP_DISABLED);
        io_error=err ? -EIO:0;
        CHECK(f2fs_enable_checkpoint(&s)==io_error);
        CHECK(syncs==expected[plan] && sleeps==expected[plan]);
        CHECK(flushes==1 && drains==1 && !s.gc_lock && !s.writepages);
        CHECK(!is_sbi_flag_set(&s,SBI_ENABLE_CHECKPOINT));
        CHECK(!is_sbi_flag_set(&s,SBI_CP_DISABLED) && is_sbi_flag_set(&s,SBI_IS_DIRTY));
        CHECK(!s.nr_pages[F2FS_SKIPPED_WRITE] && !s.wb_sync_req[0] && !accounted);
    }
    /* Callback bypasses native retries. Count skips even with success,
       including the explicit default result when only wb_done is written. */
    for (int enabled=0;enabled<2;enabled++) for (int sync=0;sync<2;sync++)
    for (int mode=0;mode<3;mode++) for (int err=0;err<2;err++) {
        reset(); cases++; serialize=1; skipped=7;
        hook_mode=mode; hook_status=write_status=err ? -EIO:0;
        struct f2fs_sb_info s={0};
        if (enabled) set_sbi_flag(&s,SBI_ENABLE_CHECKPOINT);
        struct inode i={.sbi=&s,.dirty=8}; struct address_space m={&i};
        struct writeback_control w={.sync_mode=sync};
        int ret=__f2fs_write_data_pages(&m,&w,FS_DATA_IO);
        CHECK(ret==(mode==2 ? -EIO:write_status));
        CHECK(s.nr_pages[F2FS_SKIPPED_WRITE]==
              (enabled && sync && (mode || err) ? 7:0));
        CHECK(native_calls==(mode==0) && removed==1);
        CHECK(!s.writepages && !s.wb_sync_req[0] && !accounted);
    }
    for (int enabled=0;enabled<2;enabled++) for (int sync=0;sync<2;sync++) {
        reset(); cases++;
        struct f2fs_sb_info s={0};
        if (enabled) set_sbi_flag(&s,SBI_ENABLE_CHECKPOINT);
        struct inode i={.sbi=&s,.dirty=8,.skip=true}; struct address_space m={&i};
        struct writeback_control w={.sync_mode=sync};
        CHECK(!__f2fs_write_data_pages(&m,&w,FS_DATA_IO));
        CHECK(w.pages_skipped==8 && !native_calls);
        CHECK(s.nr_pages[F2FS_SKIPPED_WRITE]==(enabled && sync ? 8:0));
    }
    printf("cases=%u assertions=%u failures=%u\n",cases,assertions,failures);
    return failures ? 1:0;
}
'''
runs = {}
with tempfile.TemporaryDirectory(prefix='f2fs-checkpoint-check-') as tmp:
    tmp = Path(tmp)
    for label, code in [('port', body), ('unadapted-callback-control',
                                       body.replace('if (ret || wb_done)', 'if (ret)'))]:
        c = tmp / (label + '.c'); exe = tmp / label
        c.write_text(prefix + code + suffix)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', str(c), '-o', str(exe)], check=True)
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        runs[label] = dict(returncode=r.returncode, stdout=r.stdout, stderr=r.stderr)
assert runs['port']['returncode'] == 0, runs
assert runs['unadapted-callback-control']['returncode'] != 0, runs
evidence = dict(source_sha256={p: hashlib.sha256(s.encode()).hexdigest()
                              for p, s in sources.items()}, runs=runs,
                limits='Deterministic extracted-function host checks. Does not '
                       'establish storage persistence, kernel concurrency, '
                       'scheduler behavior or a remount time bound.', remote_resources=[])
(D / 'evidence/f2fs-checkpoint-check.json').write_text(json.dumps(evidence, indent=2)+'\n')
print(json.dumps(runs, indent=2))
