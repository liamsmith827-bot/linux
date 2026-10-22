#!/usr/bin/env python3
"""Exercise extracted Merkle-prefetch geometry and cache ownership; no real I/O."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]


def function(src, name):
    m = re.search(r'^void ' + name + r'\([^;{]*\)\n\{', src, re.M)
    assert m, name
    i, depth = m.end(), 1
    while depth:
        depth += (src[i] == '{') - (src[i] == '}')
        i += 1
    return src[m.start():i] + '\n'


paths = ['fs/verity/verify.c', 'fs/verity/pagecache.c']
sources = {p: (ROOT / p).read_text() for p in paths}
geometry = function(sources[paths[0]], 'fsverity_readahead')
cache = function(sources[paths[1]], 'generic_readahead_merkle_tree')
prefix = r'''
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stddef.h>
typedef uint64_t u64;
typedef int64_t loff_t;
typedef unsigned long pgoff_t;
#define PAGE_SIZE 4096UL
#define DIV_ROUND_UP_ULL(x,d) (((x)+(d)-1)/(d))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define FGP_ACCESSED 1
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
struct inode;
struct merkle_tree_params {
    unsigned block_size, log_blocks_per_page, log_arity, num_levels;
    unsigned long level_start[16];
};
struct fsverity_info { struct merkle_tree_params tree_params; };
struct ops { void (*readahead_merkle_tree)(struct inode *,pgoff_t,unsigned long); };
struct super_block { struct ops *s_vop; };
struct address_space { int invalidate_lock; };
struct inode {
    struct fsverity_info *vi;
    struct super_block *i_sb;
    struct address_space *i_mapping;
    loff_t size;
};
struct folio { int refs, uptodate; };
struct readahead_control { struct address_space *mapping; pgoff_t index; };
#define DEFINE_READAHEAD(n,f,r,m,i) struct readahead_control n={m,i}
static unsigned long recorded[32];
static unsigned calls, failures, lookups, drops;
static long error;
static struct folio cached;
static struct address_space mapping;
static pgoff_t expect_index;
static unsigned long expect_count;
#define CHECK(x) do { if (!(x)) failures++; } while (0)
#define lockdep_assert_held(p) CHECK(*(p)==1)
static struct fsverity_info *fsverity_get_info(struct inode *i) { return i->vi; }
static loff_t i_size_read(struct inode *i) { return i->size; }
static void record(struct inode *i,pgoff_t idx,unsigned long nr) {
    CHECK(calls<16 && nr>0);
    if (calls<16) { recorded[2*calls]=idx; recorded[2*calls+1]=nr; }
    calls++;
}
static struct folio *__filemap_get_folio(struct address_space *m,pgoff_t i,int f,int g) {
    lookups++; CHECK(m==&mapping && i==expect_index && f==FGP_ACCESSED && !g);
    if (error) return ERR_PTR(error);
    cached.refs++; return &cached;
}
static bool folio_test_uptodate(struct folio *f) { CHECK(f==&cached); return f->uptodate; }
static void folio_put(struct folio *f) { CHECK(f==&cached && f->refs==1); drops++; f->refs--; }
static void page_cache_ra_unbounded(struct readahead_control *r,unsigned long n,unsigned l) {
    CHECK(r->mapping==&mapping && mapping.invalidate_lock==1);
    CHECK(r->index==expect_index && n==expect_count && !l); calls++;
}
'''
suffix = r'''
unsigned run_geometry(int64_t size,unsigned long index,unsigned long nr,
                      unsigned block,unsigned logblocks,unsigned logarity,
                      unsigned levels,unsigned long *starts,int info,int callback,
                      unsigned long *out) {
    struct fsverity_info vi={.tree_params={block,logblocks,logarity,levels,{0}}};
    for (unsigned i=0;i<levels;i++) vi.tree_params.level_start[i]=starts[i];
    struct ops ops={callback?record:NULL}; struct super_block sb={&ops};
    struct inode inode={info?&vi:NULL,&sb,&mapping,size};
    calls=failures=0;
    fsverity_readahead(&inode,index,nr);
    for (unsigned i=0;i<calls*2 && i<32;i++) out[i]=recorded[i];
    return failures ? 999 : calls;
}
unsigned run_cache(long e,int up,unsigned long nr) {
    mapping.invalidate_lock=1; cached=(struct folio){0,up}; error=e;
    calls=failures=lookups=drops=0; expect_index=11; expect_count=nr;
    struct inode inode={.i_mapping=&mapping};
    generic_readahead_merkle_tree(&inode,expect_index,nr);
    CHECK(lookups==!!nr);
    CHECK(calls==(nr && (e==-ENOENT || (!e && !up))));
    CHECK(drops==(nr && !e)); CHECK(cached.refs==0);
    CHECK(mapping.invalidate_lock==1);
    return failures;
}
'''


def topology(size, block, digest):
    blocks = (max(size, 0) + block - 1) // block
    counts = []
    while blocks > 1:
        blocks = (blocks + block // digest - 1) // (block // digest)
        counts.append(blocks)
    return [sum(counts[level + 1:]) for level in range(len(counts))]


def expected(size, index, nr, block, digest, starts, info, callback):
    if not info or not callback or size <= 0 or not nr or index * 4096 >= size:
        return []
    first = index * 4096 // block
    last = (min(size, (index + nr) * 4096) - 1) // block
    answer = []
    # Divide the covered data-block interval into each level's hash buckets.
    for start in starts:
        first //= block // digest
        last //= block // digest
        low = (start + first) * block // 4096
        high = (start + last) * block // 4096
        answer.append((low, high - low + 1))
    return answer


def exercise(lib):
    ul = C.c_ulong
    lib.run_geometry.argtypes = [C.c_int64, ul, ul, C.c_uint, C.c_uint,
                                 C.c_uint, C.c_uint, C.POINTER(ul), C.c_int,
                                 C.c_int, C.POINTER(ul)]
    lib.run_geometry.restype = C.c_uint
    lib.run_cache.argtypes = [C.c_long, C.c_int, ul]
    lib.run_cache.restype = C.c_uint
    cases = failures = 0
    maximum = (1 << 64) - 1
    for block in (1024, 2048, 4096):
        for digest in (32, 64):
            sizes = [-1, 0, 1, block, block+1, 4095, 4096, 4097,
                     65535, 65536, 65537, 1000001, (1 << 32) + 7]
            # Native sub-page bitmap limits exclude gigantic sub-page trees.
            if block == 4096:
                sizes += [(1 << 63) - 1]
            for size in sizes:
                starts = topology(size, block, digest)
                pages = (max(size, 0) + 4095) // 4096
                indices = sorted({0, 1, 15, 16, max(0, pages-1), pages,
                                  pages+1, maximum})
                for index in indices:
                    for nr in (0, 1, 2, 17, 1024, maximum):
                        for info, callback in ((1, 1), (0, 1), (1, 0)):
                            out = (ul * 32)()
                            count = lib.run_geometry(size, index, nr, block,
                                12-(block.bit_length()-1),
                                (block//digest).bit_length()-1, len(starts),
                                (ul * len(starts))(*starts), info, callback, out)
                            got = [(out[2*i], out[2*i+1]) for i in range(min(count,16))]
                            want = expected(size,index,nr,block,digest,starts,info,callback)
                            failures += count > 16 or got != want
                            cases += 1
    for err in (0, -2, -12, -5, -11):
        for up in (0, 1):
            for nr in (0, 1, 2, 128):
                failures += bool(lib.run_cache(err, up, nr))
                cases += 1
    return dict(cases=cases, failed_cases=failures)


variants = {
    'port': geometry + cache,
    'zero_range_control': geometry.replace(' || !nr_pages ||', ' ||') + cache,
    'unbounded_range_control': geometry.replace(
        'nr_pages = min_t(u64, nr_pages, data_pages - index);', '').replace(
        'end_hidx = min_t(u64,\n\t\t(((u64)index + nr_pages) << params->log_blocks_per_page) - 1,\n\t\tDIV_ROUND_UP_ULL((u64)size, params->block_size) - 1);',
        'end_hidx = (((u64)index + nr_pages) << params->log_blocks_per_page) - 1;') + cache,
    'cache_reference_leak_control': geometry + cache.replace('folio_put(folio);','(void)folio;'),
    'retry_other_errors_control': geometry + cache.replace(
        'folio == ERR_PTR(-ENOENT) ||', 'IS_ERR(folio) ||'),
}
runs = {}
with tempfile.TemporaryDirectory(prefix='verity-prefetch-') as tmp:
    for name, body in variants.items():
        c, so = Path(tmp)/(name+'.c'), Path(tmp)/(name+'.so')
        c.write_text(prefix + body + suffix)
        subprocess.run(['cc','-std=gnu11','-shared','-fPIC','-O2','-Wall','-Werror',
                        '-Wno-unused-parameter','-Wno-unused-function',str(c),'-o',str(so)],check=True)
        runs[name] = exercise(C.CDLL(str(so)))
        assert (runs[name]['failed_cases'] == 0) == (name == 'port'), (name,runs[name])

# Removing the new helper leaves every existing verification line unchanged.
baseline = subprocess.check_output(['git','show','6cd9fcdf600d:fs/verity/verify.c'],
                                   cwd=ROOT,text=True)
current = sources[paths[0]]
start = current.index('/**\n * fsverity_readahead()')
end = current.index('EXPORT_SYMBOL_GPL(fsverity_readahead);', start)
current = current[:start] + current[end+len('EXPORT_SYMBOL_GPL(fsverity_readahead);\n\n'):]
assert current == baseline
result = dict(scope=__doc__ + ' 64-bit SDK page geometry; mock lookup, lock and references, not live concurrent I/O.',
              source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},
              native_verification_unchanged_from='6cd9fcdf600d',
              runs=runs, remote_resources=[])
(D/'evidence/verity-prefetch-check.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(runs,indent=2))
