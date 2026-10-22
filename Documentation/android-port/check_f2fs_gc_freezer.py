#!/usr/bin/env python3
"""Check actual GC summary-reference cleanup with deterministic host shims."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

D = Path(__file__).resolve().parent
source = (D.parents[1] / 'fs/f2fs/gc.c').read_text()
start = source.index('static int do_garbage_collect(')
end = source.index('\nint f2fs_gc(', start)
body = source[start:end]
control = body.replace('''\t\t/* Drain references to every prefetched summary when freezing. */
\t\tif (unlikely(freezing(current)) ||
\t\t    !folio_test_uptodate(sum_folio) ||''', '''\t\tif (!folio_test_uptodate(sum_folio) ||''')
control = control.replace('''\t\t\tif (unlikely(freezing(current)))
\t\t\t\tgoto next_block;''', '''\t\t\tif (unlikely(freezing(current))) {
\t\t\t\tfolio_put_refs(sum_folio, 2);
\t\t\t\tgoto stop;
\t\t\t}''')
control = control.replace('\n\tif (submitted)\n', '\nstop:\n\tif (submitted)\n')
assert control != body
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
enum { DATA, NODE, SUM_TYPE_DATA=DATA, SUM_TYPE_NODE=NODE, BG_GC=0, FG_GC=1 };
enum { META_SSA, STOP_CP_REASON_CORRUPTED_SUMMARY };
#define NULL_SEGNO (~0U)
#define current ((void *)0)
#define unlikely(x) (x)
#define rounddown(x,n) ((x)/(n)*(n))
#define DIV_ROUND_UP(x,n) (((x)+(n)-1)/(n))
#define IS_ERR(p) (!(p))
#define PTR_ERR(p) (-EIO)
#define IS_DATASEG(t) ((t)==DATA)
#define SEGS_PER_SEC(s) ((s)->segs_per_sec)
#define GET_SEC_FROM_SEG(s,n) ((n)/(s)->segs_per_sec)
#define GET_SUM_BLOCK(s,n) ((n)/(s)->sums_per_block)
#define META_MAPPING(s) (s)
#define SUM_BLK_PAGE_ADDR(s,f,n) (&(f)->summary)
#define sum_footer(s,b) (&(b)->type)
#define GET_SUM_TYPE(p) (*(p))
struct f2fs_summary_block { int entries[1]; int type; };
struct folio { int refs; bool locked, uptodate; struct f2fs_summary_block summary; };
struct seg_entry { int type; };
struct f2fs_sb_info {
    unsigned segs_per_sec, sums_per_block, migration_window_granularity;
    unsigned migration_granularity, gc_mode, next_victim_seg[2], gc_reclaimed_segs[1];
    struct { unsigned boost_zoned_gc_percent, boost_gc_multiple; } gc_thread;
};
struct gc_inode_list { int unused; };
struct blk_plug { int unused; };
static struct folio folios[64];
static struct seg_entry entry;
static unsigned cases, assertions, failures;
static int visited, threshold, fail_index, bad_index, active_plugs, submissions;
#define CHECK(c) do { assertions++; if (!(c)) { failures++; \
    if (failures<12) fprintf(stderr,"line %d: %s\n",__LINE__,#c); } } while (0)
static bool __is_large_section(struct f2fs_sb_info *s) { return s->segs_per_sec>1; }
static bool f2fs_sb_has_blkzoned(struct f2fs_sb_info *s) { return false; }
static unsigned f2fs_usable_segs_in_sec(struct f2fs_sb_info *s) { return s->segs_per_sec; }
static bool has_enough_free_blocks(struct f2fs_sb_info *s, unsigned n) { return true; }
static struct seg_entry *get_seg_entry(struct f2fs_sb_info *s,unsigned n) { return &entry; }
static void sanity_check_seg_type(struct f2fs_sb_info *s,unsigned n) {}
static void f2fs_ra_meta_pages(struct f2fs_sb_info *s,unsigned b,int n,int t,bool sync) {}
static struct folio *f2fs_get_sum_folio(struct f2fs_sb_info *s,unsigned n)
{
    unsigned i=GET_SUM_BLOCK(s,n);
    if ((int)i==fail_index) return NULL;
    CHECK(!folios[i].refs && !folios[i].locked);
    folios[i].refs++; folios[i].locked=true;
    folios[i].uptodate=(int)i!=bad_index;
    folios[i].summary.type=entry.type;
    return &folios[i];
}
static struct folio *filemap_get_folio(struct f2fs_sb_info *s,unsigned i)
{ CHECK(folios[i].refs==1); folios[i].refs++; return &folios[i]; }
static void folio_put_refs(struct folio *f,unsigned n) { f->refs-=n; CHECK(f->refs==0); }
static void folio_unlock(struct folio *f) { CHECK(f->locked); f->locked=false; }
static bool folio_test_uptodate(struct folio *f) { return f->uptodate; }
static bool freezing(void *task) { return threshold>=0 && visited>=threshold; }
static bool f2fs_cp_error(struct f2fs_sb_info *s) { return false; }
static bool is_cursec(struct f2fs_sb_info *s,unsigned n) { return false; }
static unsigned get_valid_blocks(struct f2fs_sb_info *s,unsigned n,bool sec) { return 1; }
static void f2fs_err(struct f2fs_sb_info *s,const char *fmt,...) {}
static void f2fs_bug_on(struct f2fs_sb_info *s,bool b) { CHECK(!b); }
static void f2fs_stop_checkpoint(struct f2fs_sb_info *s,bool end,unsigned reason) {}
static int gc_node_segment(struct f2fs_sb_info *s,int *e,unsigned n,int type,struct blk_plug *plug)
{ visited++; return 1; }
static int gc_data_segment(struct f2fs_sb_info *s,int *e,struct gc_inode_list *l,
                          unsigned n,int type,bool force,struct blk_plug *plug)
{ visited++; return 1; }
static void stat_inc_gc_seg_count(struct f2fs_sb_info *s,int d,int t) {}
static void stat_inc_gc_sec_count(struct f2fs_sb_info *s,int d,int t) {}
static void blk_start_plug(struct blk_plug *p) { CHECK(!active_plugs++); }
static void blk_finish_plug(struct blk_plug *p) { CHECK(--active_plugs==0); }
static void f2fs_submit_merged_write(struct f2fs_sb_info *s,int t) { submissions++; }
'''
suffix = r'''
int main(void)
{
    for (unsigned width=1;width<=8;width*=2)
    for (unsigned start=0;start<=32;start+=16)
    for (int type=0;type<2;type++)
    for (int gc=0;gc<2;gc++)
    for (threshold=-1;threshold<=17;threshold++) {
        memset(folios,0,sizeof(folios)); visited=active_plugs=submissions=0;
        fail_index=bad_index=-1; entry.type=type; cases++;
        struct f2fs_sb_info s={.segs_per_sec=16,.sums_per_block=width,
                              .migration_window_granularity=8,.migration_granularity=16};
        struct gc_inode_list list={0};
        CHECK(do_garbage_collect(&s,start,&list,gc,false,false)==0);
        int available=gc==BG_GC ? 8:16;
        int expected=threshold<0 || threshold>available ? available:threshold;
        CHECK(visited==expected);
        CHECK(!active_plugs && submissions==(visited>0));
        for (int i=0;i<64;i++) CHECK(!folios[i].refs && !folios[i].locked);
    }
    /* Prefetch failure and non-uptodate summaries must retain cleanup. */
    for (unsigned width=1;width<=8;width*=2)
    for (int index=0;index<16/(int)width;index++)
    for (int fail=0;fail<2;fail++) {
        memset(folios,0,sizeof(folios)); visited=active_plugs=submissions=0;
        threshold=-1; entry.type=DATA; cases++;
        fail_index=fail ? index:-1; bad_index=fail ? -1:index;
        struct f2fs_sb_info s={.segs_per_sec=16,.sums_per_block=width,
                              .migration_window_granularity=16,.migration_granularity=16};
        struct gc_inode_list list={0};
        CHECK(do_garbage_collect(&s,0,&list,FG_GC,false,false)==(fail ? -EIO:0));
        CHECK(visited==(fail ? 0:16-(int)width));
        CHECK(!active_plugs && submissions==(visited>0));
        for (int i=0;i<64;i++) CHECK(!folios[i].refs && !folios[i].locked);
    }
    printf("cases=%u assertions=%u failures=%u\n",cases,assertions,failures);
    return failures ? 1:0;
}
'''
runs = {}
with tempfile.TemporaryDirectory(prefix='f2fs-gc-freezer-') as tmp:
    tmp = Path(tmp)
    for label, code in [('port', body), ('ack-early-exit-control', control)]:
        src = tmp / (label + '.c'); exe = tmp / label
        src.write_text(prefix + code + suffix)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-Wno-sign-compare', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', str(src), '-o', str(exe)], check=True)
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        runs[label] = dict(returncode=r.returncode, stdout=r.stdout, stderr=r.stderr)
assert runs['port']['returncode'] == 0, runs
assert runs['ack-early-exit-control']['returncode'] != 0, runs
(D / 'evidence/f2fs-gc-freezer-check.json').write_text(json.dumps(dict(
    source_sha256=hashlib.sha256(source.encode()).hexdigest(), runs=runs,
    limits='Extracted full GC function with deterministic host shims. Checks summary '
           'reference/plug/submission control flow; no real reclaim, storage, locking, '
           'concurrency or suspend runtime is exercised.', remote_resources=[]), indent=2)+'\n')
print(json.dumps(runs, indent=2))
