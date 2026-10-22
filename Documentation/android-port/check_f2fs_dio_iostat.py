#!/usr/bin/env python3
"""Check extracted direct-I/O statistics ownership; no real I/O or concurrency."""
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

sources = {p: (ROOT / p).read_text() for p in
           ['fs/f2fs/file.c', 'fs/f2fs/iostat.c', 'fs/f2fs/iostat.h']}
body = '\n'.join(function(sources[p], n) for p, n in [
    ('fs/f2fs/iostat.c', 'iostat_alloc_and_bind_ctx'),
    ('fs/f2fs/iostat.h', 'iostat_update_submit_ctx'),
    ('fs/f2fs/iostat.c', 'iostat_update_and_unbind_ctx'),
    ('fs/f2fs/file.c', 'f2fs_dio_end_bio'),
    ('fs/f2fs/file.c', 'f2fs_dio_iostat_start')])
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
enum page_type { DATA };
enum iostat_lat_type { READ_IO, WRITE_SYNC_IO, WRITE_ASYNC_IO };
#define REQ_SYNC 2
#define GFP_NOFS 0
#define bio_op(b) ((b)->bi_opf & 1)
#define op_is_write(op) ((op) == 1)
struct f2fs_sb_info { bool iostat_enable; void *sb; };
struct bio_post_read_ctx;
struct bio_iostat_ctx {
    struct f2fs_sb_info *sbi;
    unsigned long submit_ts;
    enum page_type type;
    struct bio_post_read_ctx *post_read_ctx;
};
struct bio {
    void *bi_private;
    void (*bi_end_io)(struct bio *);
    unsigned bi_opf;
    int bi_status;
};
static unsigned assertions, failures, cases;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
    if (failures < 10) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while (0)
static struct bio_iostat_ctx ctx;
static unsigned long jiffies = 137;
static void *bio_iostat_ctx_pool;
static void *expected_private;
static int active, allocations, frees, completions, hooks, updates;
static int expected_status, expected_type;
static bool hook_skip;
static void *mempool_alloc(void *pool, int flags) {
    CHECK(!active); active = 1; allocations++;
    memset(&ctx, 0xa5, sizeof(ctx)); return &ctx;
}
static void mempool_free(void *ptr, void *pool) {
    CHECK(ptr == &ctx && active); active = 0; frees++;
    memset(&ctx, 0xa5, sizeof(ctx));
}
static void trace_android_vh_f2fs_iostat_update(void *sb, struct bio *bio, bool *skip) {
    CHECK(active && bio->bi_private == &ctx);
    CHECK(sb == ctx.sbi->sb); CHECK(!*skip); *skip = hook_skip; hooks++;
}
static void __update_iostat_latency(struct bio_iostat_ctx *p, enum iostat_lat_type type) {
    CHECK(active && p == &ctx); CHECK(type == expected_type);
    CHECK(p->submit_ts == jiffies && p->type == DATA); updates++;
}
static void iomap_dio_bio_end_io(struct bio *bio) {
    CHECK(bio->bi_private == expected_private);
    CHECK(!active); CHECK(bio->bi_status == expected_status); completions++;
}
'''
suffix = r'''
int main(void) {
    for (int before = 0; before < 2; before++)
    for (int after = 0; after < 2; after++)
    for (int op = 0; op < 4; op++)
    for (int skip = 0; skip < 2; skip++)
    for (int error = 0; error < 2; error++) {
        int native_context = 7;
        struct f2fs_sb_info sbi = { .iostat_enable = before, .sb = &native_context };
        struct bio bio = { .bi_private = &native_context,
            .bi_end_io = iomap_dio_bio_end_io, .bi_opf = op, .bi_status = error };
        active = allocations = frees = completions = hooks = updates = 0;
        expected_private = &native_context; expected_status = error;
        expected_type = op & 1 ? (op & REQ_SYNC ? WRITE_SYNC_IO : WRITE_ASYNC_IO) : READ_IO;
        hook_skip = skip;
        f2fs_dio_iostat_start(&sbi, &bio);
        CHECK(allocations == before); CHECK(active == before);
        CHECK(bio.bi_end_io == (before ? f2fs_dio_end_bio : iomap_dio_bio_end_io));
        sbi.iostat_enable = after;
        bio.bi_end_io(&bio);
        CHECK(completions == 1); CHECK(frees == before); CHECK(!active);
        CHECK(hooks == before); CHECK(updates == (before && !skip)); cases++;
    }
    printf("%u cases, %u assertions, %u failures\n", cases, assertions, failures);
    return !!failures;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-dio-iostat-') as tmp:
    results = {}
    variants = {
        'port': body,
        'missing_iomap_restore_control': body.replace('\tbio->bi_private = orig_bi_private;', '\t(void)orig_bi_private;'),
        'disabled_allocation_control': body.replace('\tif (!sbi->iostat_enable)\n\t\treturn;', ''),
    }
    for name, code in variants.items():
        src, exe = Path(tmp) / (name + '.c'), Path(tmp) / name
        src.write_text(prefix + code + suffix)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-parameter',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        str(src), '-o', str(exe)], check=True)
        p = subprocess.run([str(exe)], capture_output=True, text=True)
        assert (p.returncode == 0) == (name == 'port'), (name, p.stdout, p.stderr)
        results[name] = {'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
report = {'scope': __doc__, 'source_sha256': {
    p: hashlib.sha256(s.encode()).hexdigest() for p, s in sources.items()}, 'results': results}
(D / 'evidence/f2fs-dio-iostat-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(results['port']['stdout'].strip())
print('Both negative controls rejected')
