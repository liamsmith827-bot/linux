#!/usr/bin/env python3
"""Extracted F2FS flush ownership and stream bounds checks; no device I/O."""
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
sources = {p: (ROOT / p).read_text() for p in ['fs/f2fs/segment.c', 'fs/f2fs/file.c']}
body = '\n'.join(function(sources[p], n) for p, n in [
    ('fs/f2fs/segment.c', 'f2fs_flush_end_io'),
    ('fs/f2fs/segment.c', 'submit_flush_wait'),
    ('fs/f2fs/segment.c', 'f2fs_io_type_to_write_stream'),
    ('fs/f2fs/file.c', 'f2fs_valid_write_stream')])
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned nid_t;
typedef unsigned char u8;
enum page_type { DATA, NODE, META };
enum temp_type { HOT, WARM, COLD, NR_TEMP_TYPE };
#define MAX_DEVICES 8
#define BIT(i) (1UL << (i))
#define GFP_NOFS 1
#define __GFP_NOFAIL 2
#define REQ_OP_WRITE 1
#define REQ_SYNC 2
#define REQ_PREFLUSH 4
#define FLUSH_INO 1
#define FS_FLUSH_IO 1
#define NOBARRIER 1
#define FLUSH_MERGE 2
#define array_size(a,b) ((a)*(b))
#define test_opt(s,o) 0
struct block_device { int index; unsigned short streams; };
struct completion { int done; };
struct bio { struct block_device *dev; void *bi_private;
    void (*bi_end_io)(struct bio *); int bi_status; };
struct f2fs_flush_bio { struct bio bio; struct completion wait; };
struct super_block { struct block_device *s_bdev; };
struct f2fs_sb_info { int s_ndevs; struct super_block *sb;
    struct { struct block_device *bdev; } devs[MAX_DEVICES]; };
#define FDEV(i) sbi->devs[i]
static unsigned assertions, failures, cases;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
    if (failures < 10) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
static unsigned dirty, errors, submitted, waited, uninitialized;
static int allocations, deallocations, traced, counted, direct;
static struct bio *pending[MAX_DEVICES];
static int __submit_flush_wait(struct f2fs_sb_info *s, struct block_device *d) {
    direct++; return -37;
}
static bool f2fs_is_multi_device(struct f2fs_sb_info *s) { return s->s_ndevs > 1; }
static bool f2fs_is_dirty_device(struct f2fs_sb_info *s, nid_t ino, int i, int type) {
    return dirty & BIT(i);
}
static void *kmalloc(size_t n, int flags) { allocations++; return calloc(1, n); }
static void kfree(void *p) { CHECK(waited == submitted); deallocations++; free(p); }
static void bio_init(struct bio *b, struct block_device *d, void *v, int n, int op) {
    CHECK(op == (REQ_OP_WRITE | REQ_SYNC | REQ_PREFLUSH));
    b->dev = d; b->bi_status = 0;
}
static void init_completion(struct completion *c) { c->done = 0; }
static void complete(struct completion *c) { CHECK(!c->done); c->done = 1; }
static void submit_bio(struct bio *b) {
    int i = b->dev->index;
    CHECK(!(submitted & BIT(i))); submitted |= BIT(i); pending[i] = b;
    b->bi_status = errors & BIT(i) ? -(i+1) : 0;
    /* Alternate inline completion with completion during wait. */
    if (i & 1) b->bi_end_io(b);
}
static void wait_for_completion(struct completion *c) {
    CHECK(submitted == dirty);
    for (int i = 0; i < MAX_DEVICES; i++) if (pending[i] && pending[i]->bi_private == c) {
        if (!c->done) pending[i]->bi_end_io(pending[i]);
        CHECK(c->done); waited |= BIT(i); return;
    }
    CHECK(false);
}
static int blk_status_to_errno(int status) { return status; }
static void bio_uninit(struct bio *b) {
    CHECK(waited & BIT(b->dev->index)); uninitialized |= BIT(b->dev->index);
}
static void trace_f2fs_issue_flush(struct block_device *d, int a, int b, int e) { traced++; }
static void f2fs_update_iostat(struct f2fs_sb_info *s, void *ino, int t, int n) { counted++; }
static unsigned short bdev_max_write_streams(struct block_device *d) { return d->streams; }
'''
suffix = r'''
int main(void) {
    struct block_device dev[MAX_DEVICES];
    struct super_block sb = { .s_bdev = dev };
    struct f2fs_sb_info sbi = { .sb = &sb };
    for (int i=0; i<MAX_DEVICES; i++) {
        dev[i].index = i; sbi.devs[i].bdev = &dev[i];
    }
    for (int n=2; n<=MAX_DEVICES; n++)
    for (unsigned d=0; d<(1U<<n); d++)
    for (unsigned e=0; e<(1U<<n); e++) {
        sbi.s_ndevs = n; dirty = d; errors = e;
        submitted = waited = uninitialized = 0;
        allocations = deallocations = traced = counted = direct = 0;
        memset(pending, 0, sizeof(pending));
        int expected = 0;
        for (int i=0; i<n; i++) if ((d&e&BIT(i)) && !expected) expected = -(i+1);
        CHECK(submit_flush_wait(&sbi, 17) == expected);
        CHECK(submitted == d && waited == d && uninitialized == d);
        CHECK(allocations == 1 && deallocations == 1 && direct == 0);
        CHECK(traced == __builtin_popcount(d));
        CHECK(counted == __builtin_popcount(d & ~e)); cases++;
    }
    sbi.s_ndevs = 0; CHECK(submit_flush_wait(&sbi, 17) == -37); CHECK(direct == 1); cases++;
    for (int nr=0; nr<8; nr++)
    for (int t=0; t<NR_TEMP_TYPE; t++)
    for (int p=DATA; p<=META; p++) {
        dev[0].streams = nr;
        int expected = p != DATA || nr == 0 ? 0 :
            nr == 1 ? 1 : nr == 2 ? (t == COLD ? 2 : 1) : t+1;
        CHECK(f2fs_io_type_to_write_stream(dev, p, t) == expected); cases++;
    }
    for (int n=0; n<=MAX_DEVICES; n++)
    for (int nr=0; nr<8; nr++)
    for (int stream=0; stream<10; stream++) {
        sbi.s_ndevs = n;
        for (int i=0; i<MAX_DEVICES; i++) dev[i].streams = nr + i;
        CHECK(f2fs_valid_write_stream(&sbi, stream) == (stream <= nr)); cases++;
        if (n>1) {
            dev[n-1].streams = 0;
            CHECK(f2fs_valid_write_stream(&sbi, stream) == !stream); cases++;
        }
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-flush-streams-') as tmp:
    results = {}
    variants = {'port': body,
                'skip_wait_after_error_control': body.replace('ret = err;', 'ret = err;\n\t\tif (ret) break;')}
    for name, code in variants.items():
        src, exe = Path(tmp)/(name+'.c'), Path(tmp)/name
        src.write_text(prefix + code + suffix)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-parameter',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        str(src), '-o', str(exe)], check=True)
        p = subprocess.run([str(exe)], capture_output=True, text=True)
        assert (p.returncode == 0) == (name == 'port'), (name,p.stdout,p.stderr)
        results[name] = {'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
report = {'scope': __doc__, 'source_sha256': {
    p: hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()}, 'results': results}
(D/'evidence/f2fs-flush-streams-check.json').write_text(json.dumps(report, indent=2)+'\n')
print(results['port']['stdout'].strip())
print('Incomplete-wait error control rejected')
