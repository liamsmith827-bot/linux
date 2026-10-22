#!/usr/bin/env python3
"""Check extracted Merkle page readers with modeled cache/error/reference states."""
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

sources = {f'fs/{fs}/verity.c': (ROOT/f'fs/{fs}/verity.c').read_text()
           for fs in ['ext4','f2fs']}
body = '\n'.join(function(sources[f'fs/{fs}/verity.c'], fs+'_read_merkle_tree_page')
                 for fs in ['ext4','f2fs'])
prefix = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef unsigned long pgoff_t;
#define PAGE_SHIFT 12
#define FGP_ACCESSED 1
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_CAST(p) ((void *)(p))
struct address_space { int locked; };
struct inode { struct address_space *i_mapping; unsigned long metadata; };
struct page { int unused; };
struct folio { bool uptodate; int refs; struct page page; };
struct readahead_control { struct address_space *mapping; pgoff_t index; };
#define DEFINE_READAHEAD(n,f,r,m,i) struct readahead_control n={m,i}
static unsigned failures, assertions, cases;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
 if (failures<10) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while (0)
static struct folio cached, loaded;
static struct address_space *mapping;
static long lookup_error, read_error;
static unsigned reads, readaheads, locks;
static pgoff_t expected_index;
static unsigned long expected_count;
static unsigned long ext4_verity_metadata_pos(struct inode *i) { return i->metadata; }
static unsigned long f2fs_verity_metadata_pos(struct inode *i) { return i->metadata; }
static struct folio *__filemap_get_folio(struct address_space *m, pgoff_t i, int flags, int gfp) {
    CHECK(m==mapping && i==expected_index && flags==FGP_ACCESSED);
    if (lookup_error) return ERR_PTR(lookup_error);
    cached.refs++; return &cached;
}
static bool folio_test_uptodate(struct folio *f) { CHECK(!IS_ERR(f)); return f->uptodate; }
static void folio_put(struct folio *f) { CHECK(f->refs==1); f->refs--; }
static void filemap_invalidate_lock_shared(struct address_space *m) { CHECK(!m->locked++); locks++; }
static void filemap_invalidate_unlock_shared(struct address_space *m) { CHECK(--m->locked==0); }
static void page_cache_ra_unbounded(struct readahead_control *r, unsigned long nr, unsigned lookahead) {
    CHECK(r->mapping==mapping && mapping->locked && r->index==expected_index);
    CHECK(nr==expected_count && !lookahead); readaheads++;
}
static struct folio *read_mapping_folio(struct address_space *m, pgoff_t i, void *data) {
    CHECK(m==mapping && !m->locked && i==expected_index && !cached.refs); reads++;
    if (read_error) return ERR_PTR(read_error);
    loaded.refs++; return &loaded;
}
static struct page *folio_file_page(struct folio *f, pgoff_t index) {
    CHECK(!IS_ERR(f) && f->refs==1 && index==expected_index); return &f->page;
}
'''
suffix = r'''
int main(void) {
    long errors[]={0,-ENOENT,-ENOMEM,-EIO,-EAGAIN};
    unsigned long counts[]={0,1,2,16};
    for (int fs=0;fs<2;fs++) for (unsigned e=0;e<5;e++)
    for (int up=0;up<2;up++) for (int failure=0;failure<2;failure++)
    for (unsigned n=0;n<4;n++) {
        struct address_space m={0}; struct inode inode={&m,8UL<<PAGE_SHIFT};
        mapping=&m; expected_index=11; expected_count=counts[n];
        cached=(struct folio){.uptodate=up}; loaded=(struct folio){.uptodate=true};
        lookup_error=errors[e]; read_error=failure ? -EIO:0; reads=readaheads=locks=0;
        struct page *p=fs ? f2fs_read_merkle_tree_page(&inode,3,counts[n]):
                           ext4_read_merkle_tree_page(&inode,3,counts[n]);
        bool terminal=lookup_error && lookup_error!=-ENOENT;
        bool fetch=!terminal && (lookup_error || !up);
        long err=terminal ? lookup_error : fetch ? read_error:0;
        CHECK(IS_ERR(p)==!!err);
        if (err) CHECK(PTR_ERR(p)==err);
        else CHECK(p==(fetch ? &loaded.page:&cached.page));
        CHECK(reads==fetch);
        CHECK(readaheads==(lookup_error==-ENOENT && counts[n]>1));
        CHECK(locks==readaheads && !m.locked);
        CHECK(cached.refs==(!err && !fetch)); CHECK(loaded.refs==(!err && fetch));
        if (cached.refs) folio_put(&cached);
        if (loaded.refs) folio_put(&loaded);
        cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
variants = {
    'port': body,
    'non_enoent_retry_control': body.replace(
        'folio == ERR_PTR(-ENOENT) ||\n\t    (!IS_ERR(folio) && !folio_test_uptodate(folio))',
        'IS_ERR(folio) || !folio_test_uptodate(folio)'),
    'missing_reference_drop_control': body.replace('folio_put(folio);', '(void)folio;'),
}
runs = {}
with tempfile.TemporaryDirectory(prefix='verity-reader-check-') as tmp:
    for name, code in variants.items():
        c, exe = Path(tmp)/(name+'.c'), Path(tmp)/name
        c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',
                        str(c),'-o',str(exe)],check=True)
        p=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (p.returncode==0)==(name=='port'),(name,p.stdout,p.stderr)
        runs[name]=dict(exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr)
(D/'evidence/verity-read-errors-check.json').write_text(json.dumps(dict(
    scope=__doc__+' No real I/O, memory pressure, verification or concurrency.',
    source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},
    runs=runs,remote_resources=[]),indent=2)+'\n')
print(runs['port']['stdout'].strip())
print('Both regression controls rejected')
