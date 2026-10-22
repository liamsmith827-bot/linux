#!/usr/bin/env python3
"""Check extracted write completion dispatch/lifetime and native body identity."""
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
src = (ROOT/'fs/f2fs/data.c').read_text()
base = '4903c005559456c193cd6e2107ccbeb5594b1f4b'
old = subprocess.check_output(['git','show',base+':fs/f2fs/data.c'], cwd=ROOT, text=True)
expected = function(old, 'f2fs_write_end_io').replace('f2fs_write_end_io(', 'f2fs_write_end_bio(')
expected = expected.replace('struct f2fs_sb_info *sbi;', 'struct f2fs_sb_info *sbi = bio->bi_private;')
expected = expected.replace('\tiostat_update_and_unbind_ctx(bio);\n\tsbi = bio->bi_private;\n\n', '')
assert function(src, 'f2fs_write_end_bio') == expected, 'Native completion behavior changed'
body = '\n'.join(function(src, n) for n in ['f2fs_write_end_io_work', 'f2fs_write_end_io',
                                           'f2fs_init_wq', 'f2fs_destroy_wq'])
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>
#define WQ_UNBOUND 1
#define WQ_HIGHPRI 2
#define WQ_MEM_RECLAIM 4
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
struct work_struct { void (*fn)(struct work_struct *); };
struct workqueue_struct { unsigned flags; bool live; };
struct f2fs_sb_info { unsigned max_atc_write_bio_size; struct workqueue_struct *wq, *write_wq; };
struct bio { void *bi_private; struct { unsigned bi_size; } bi_iter; int bi_status; };
struct f2fs_bio { struct work_struct work; struct bio bio; };
static unsigned cases, assertions, failures;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
    if (failures < 10) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
#define INIT_WORK(w,f) ((w)->fn=(f))
static struct workqueue_struct queues[2];
static int allocs, fail_at, destroyed, unbound, finished;
static bool atomic_context;
static struct work_struct *pending;
static struct f2fs_sb_info *expected_sbi;
static struct bio *expected_bio;
static int expected_status;
static int num_online_cpus(void) { return 4; }
static struct workqueue_struct *alloc_workqueue(const char *name, unsigned flags, int n) {
    int i=allocs++; if (allocs==fail_at) return NULL;
    CHECK(i<2); queues[i]=(struct workqueue_struct){flags,true}; return &queues[i];
}
static void destroy_workqueue(struct workqueue_struct *q) {
    CHECK(q && q->live); q->live=false; destroyed++;
}
static bool in_atomic(void) { return atomic_context; }
static void iostat_update_and_unbind_ctx(struct bio *bio) {
    CHECK(!unbound++); bio->bi_private=expected_sbi;
}
static void f2fs_write_end_bio(struct bio *bio) {
    CHECK(unbound==1); CHECK(bio==expected_bio);
    CHECK(bio->bi_private==expected_sbi); CHECK(bio->bi_status==expected_status);
    CHECK(!finished++);
}
static void queue_work(struct workqueue_struct *q, struct work_struct *w) {
    CHECK(q==expected_sbi->write_wq && q!=expected_sbi->wq);
    CHECK(q->live && (q->flags & WQ_MEM_RECLAIM)); CHECK(!pending); pending=w;
}
'''
suffix = r'''
int main(void) {
    for (int failure=0; failure<=2; failure++) {
        struct f2fs_sb_info sbi={0};
        allocs=destroyed=0; fail_at=failure;
        CHECK(f2fs_init_wq(&sbi)==(failure ? -ENOMEM:0));
        if (!failure) f2fs_destroy_wq(&sbi);
        CHECK(destroyed==(failure ? failure-1:2));
        for (int i=0;i<allocs;i++) CHECK(!queues[i].live); cases++;
    }
    struct f2fs_sb_info sbi={0}; allocs=0; fail_at=0;
    CHECK(f2fs_init_wq(&sbi)==0); expected_sbi=&sbi;
    unsigned sizes[]={0,1,4096,8192,UINT_MAX};
    for (int a=0;a<2;a++) for (int i=0;i<5;i++) for (int j=0;j<5;j++)
    for (int error=0;error<2;error++) {
        struct f2fs_bio b={.bio={.bi_private=&b, .bi_iter.bi_size=sizes[i], .bi_status=error}};
        expected_bio=&b.bio; expected_status=error; atomic_context=a;
        sbi.max_atc_write_bio_size=sizes[j]; unbound=finished=0; pending=NULL;
        f2fs_write_end_io(&b.bio);
        bool deferred=a && sizes[i]>sizes[j];
        CHECK(!!pending==deferred); CHECK(finished==!deferred); CHECK(unbound==1);
        if (pending) { pending->fn(pending); pending=NULL; }
        CHECK(finished==1 && unbound==1); cases++;
    }
    f2fs_destroy_wq(&sbi);
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-write-completion-') as tmp:
    results={}
    for name, code in {'port':body, 'shared_queue_control':body.replace('queue_work(sbi->write_wq, w)', 'queue_work(sbi->wq, w)')}.items():
        c, exe=Path(tmp)/(name+'.c'), Path(tmp)/name
        c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter',
                        '-Wno-misleading-indentation','-fsanitize=undefined','-fno-sanitize-recover=all',
                        str(c),'-o',str(exe)],check=True)
        p=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (p.returncode==0)==(name=='port'), (name,p.stdout,p.stderr)
        results[name]={'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
report={'scope':'Host dispatch and workqueue lifetime with shims; no actual kernel scheduling, memory pressure or I/O.',
        'native_body_matches_after_wrapper_extraction':base,
        'source_sha256':hashlib.sha256(src.encode()).hexdigest(),'results':results}
(D/'evidence/f2fs-deferred-completion-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip())
print('Native completion body preserved; shared-queue control rejected')
