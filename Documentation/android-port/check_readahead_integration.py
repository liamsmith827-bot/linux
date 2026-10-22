#!/usr/bin/env python3
"""Exercise extracted readahead and filesystem callers with host lifetime/lock shims.

Simulates reclaim during read_pages, failed reference acquisition, callback
enablement and allocation failures. Exercises complete ext4/F2FS Merkle-tree
readers and F2FS redirty_blocks, asserting the unbounded-read lock contract.
Old-source controls reproduce an ASan use-after-free and three missing locks.
This does not execute kernel locking, actual filesystems, I/O or an emulator.
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
baseline = '69eb820a7f4c5ff40bfccf2bd9fe7409d4353430'

def function(text, name):
    start = text.index(name)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

units = [('mm/readahead.c', 'void page_cache_ra_unbounded('),
         ('fs/ext4/verity.c', 'static struct page *ext4_read_merkle_tree_page('),
         ('fs/f2fs/verity.c', 'static struct page *f2fs_read_merkle_tree_page('),
         ('fs/f2fs/file.c', 'static int redirty_blocks(')]
excerpts = []
for path, signature in units:
    for prefix in ['', 'old_']:
        text = (root/path).read_text() if not prefix else subprocess.check_output(
            ['git', 'show', baseline + ':' + path], cwd=root, text=True)
        name = signature.rsplit(' ', 1)[-1].lstrip('*')
        body = function(text, signature)
        if prefix:
            body = body.replace(name, prefix + name, 1)
        if path != 'mm/readahead.c':
            body = body.replace('page_cache_ra_unbounded(', 'checked_ra(')
        excerpts.append(body)

shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CONFIG_ANDROID_VENDOR_OEM_DATA 1
#define PAGE_SHIFT 12
#define FGP_ACCESSED 1
#define DATA 0
#define page folio
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define ERR_CAST(p) ((void *)(p))
#define PTR_ERR(p) ((intptr_t)(p))
#define round_up(n,m) (((n)+(m)-1)&~((m)-1))
#define lockdep_assert_held(p) assert(*(p)>0)
typedef unsigned long pgoff_t;
typedef unsigned int gfp_t;
struct folio { int refs; bool uptodate; pgoff_t index; };
struct address_space { struct folio *i_pages; int invalidate_lock; void *host; };
struct inode { struct address_space *i_mapping; };
struct readahead_control {
    struct address_space *mapping;
    unsigned long _index, _nr_pages, android_oem_data1;
    bool _workingset;
};
#define DEFINE_READAHEAD(n,f,r,m,i) struct readahead_control n = {.mapping=(m),._index=(i)}
static bool enabled, drop_during_read, lookup_missing, alloc_failure, add_failure;
static unsigned int callbacks, lookups, lock_calls, unlock_calls, unchecked, ra_calls;
static unsigned int live;
static int cache_mode, read_error;
static struct folio *make_folio(int refs) {
    struct folio *f=calloc(1,sizeof(*f));assert(f);f->refs=refs;live++;return f;
}
static void folio_put(struct folio *f) { assert(f->refs>0);if (!--f->refs) {free(f);live--;} }
static void folio_put_refs(struct folio *f,int n) { assert(f->refs==n);free(f);live--; }
static void filemap_invalidate_lock_shared(struct address_space *m) {assert(!m->invalidate_lock);m->invalidate_lock++;lock_calls++;}
static void filemap_invalidate_unlock_shared(struct address_space *m) {assert(m->invalidate_lock==1);m->invalidate_lock--;unlock_calls++;}
static void checked_ra(struct readahead_control *r,unsigned long n,unsigned long look) {
    (void)n;(void)look;ra_calls++;if (!r->mapping->invalidate_lock)unchecked++;
}
static bool xa_is_value(struct folio *f) {return f==(void *)1;}
static struct folio *xa_load(struct folio **entry,unsigned long i) {(void)i;return *entry;}
static unsigned long readahead_index(struct readahead_control *r) {return r->_index;}
static gfp_t readahead_gfp_mask(struct address_space *m) {(void)m;return 0;}
static unsigned int mapping_min_folio_nrpages(struct address_space *m) {(void)m;return 1;}
static unsigned int mapping_min_folio_order(struct address_space *m) {(void)m;return 0;}
static unsigned long mapping_align_index(struct address_space *m,unsigned long i) {(void)m;return i;}
static unsigned int memalloc_nofs_save(void) {return 0;}
static void memalloc_nofs_restore(unsigned int n) {(void)n;}
static void trace_page_cache_ra_unbounded(void *h,unsigned long i,unsigned long n,unsigned long look) {(void)h;(void)i;(void)n;(void)look;}
static bool trace_android_vh_page_cache_ra_unbounded_enabled(void) {return enabled;}
static struct folio *filemap_get_folio(struct address_space *m,unsigned long i) {
    (void)i;lookups++;
    if (lookup_missing || !m->i_pages || xa_is_value(m->i_pages))return ERR_PTR(-ENOENT);
    assert(m->i_pages->refs>0);m->i_pages->refs++;return m->i_pages;
}
static void trace_android_vh_page_cache_ra_unbounded(struct address_space *m,struct folio *f,unsigned long *oem) {
    (void)m;(void)oem;if(enabled){assert(f->refs>0);callbacks++;}
}
static void read_pages(struct readahead_control *r) {
    if(drop_during_read && r->mapping->i_pages && !xa_is_value(r->mapping->i_pages)) {
        struct folio *f=r->mapping->i_pages;r->mapping->i_pages=NULL;folio_put(f);
    }
    r->_index+=r->_nr_pages;r->_nr_pages=0;
}
static struct folio *ractl_alloc_folio(struct readahead_control *r,gfp_t g,unsigned int o) {
    (void)r;(void)g;(void)o;return alloc_failure?NULL:make_folio(1);
}
static int filemap_add_folio(struct address_space *m,struct folio *f,unsigned long i,gfp_t g) {
    (void)g;if(add_failure)return -ENOMEM;m->i_pages=f;f->index=i;return 0;
}
static void trace_android_vh_io_statistics(struct address_space *m,unsigned long i,int n,bool a,bool b) {(void)m;(void)i;(void)n;(void)a;(void)b;}
static void trace_android_vh_readahead_add_folio(struct folio *f,struct address_space *m) {(void)f;(void)m;}
static void trace_android_vh_page_cache_ra_mark(struct folio *f,unsigned long mark,unsigned long i) {(void)f;(void)mark;(void)i;}
static void folio_set_readahead(struct folio *f) {(void)f;}
static bool folio_test_workingset(struct folio *f) {(void)f;return false;}
static bool folio_test_uptodate(struct folio *f) {return f->uptodate;}
static unsigned long ext4_verity_metadata_pos(struct inode *i) {(void)i;return 8192;}
static unsigned long f2fs_verity_metadata_pos(struct inode *i) {(void)i;return 8192;}
static struct folio *__filemap_get_folio(struct address_space *m,unsigned long i,int flags,gfp_t g) {
    (void)m;(void)i;(void)flags;(void)g;
    if(!cache_mode)return ERR_PTR(-ENOENT);
    struct folio *f=make_folio(1);f->uptodate=cache_mode==2;return f;
}
static struct folio *read_mapping_folio(struct address_space *m,unsigned long i,void *unused) {
    (void)unused;assert(!m->invalidate_lock);if(read_error)return ERR_PTR(-EIO);
    struct folio *f=make_folio(1);f->index=i;return f;
}
static struct folio *folio_file_page(struct folio *f,unsigned long i) {(void)i;return f;}
static unsigned int folio_nr_pages(struct folio *f) {(void)f;return 1;}
static unsigned long folio_next_index(struct folio *f) {return f->index+1;}
static struct folio *read_cache_folio(struct address_space *m,unsigned long i,void *a,void *b) {
    (void)a;struct folio *f=read_mapping_folio(m,i,b);if(!IS_ERR(f))m->i_pages=f;return f;
}
static struct folio *filemap_lock_folio(struct address_space *m,unsigned long i) {(void)i;assert(m->i_pages);m->i_pages->refs++;return m->i_pages;}
#define F2FS_I_SB(i) (i)
#define f2fs_bug_on(s,c) assert(!(c))
static void f2fs_folio_wait_writeback(struct folio *f,int d,bool a,bool b) {(void)f;(void)d;(void)a;(void)b;}
static void folio_mark_dirty(struct folio *f) {(void)f;}
static void folio_set_f2fs_gcing(struct folio *f) {(void)f;}
static void folio_unlock(struct folio *f) {(void)f;}
'''
checks = r'''
int main(int argc,char **argv) {
    struct address_space m={.invalidate_lock=1};
    struct readahead_control r={.mapping=&m};
    if(argc>1 && !strcmp(argv[1],"old-uaf")) {
        m.i_pages=make_folio(1);enabled=drop_during_read=true;
        old_page_cache_ra_unbounded(&r,1,0);return 0;
    }
    for(int mode=0;mode<7;mode++) {
        enabled=mode!=1;lookup_missing=mode==2;alloc_failure=mode==4;add_failure=mode==5;
        drop_during_read=true;callbacks=lookups=0;r=(struct readahead_control){.mapping=&m};
        m.i_pages=mode<3?make_folio(1):mode==6?(void *)1:NULL;
        page_cache_ra_unbounded(&r,1,0);
        assert(!live && m.invalidate_lock==1);
        assert(callbacks==(unsigned int)(mode==0 || mode==3 || mode==6));
        assert(lookups==(unsigned int)(mode==0 || mode==2));
    }
    struct inode inode={&m};m.invalidate_lock=0;
    for(int fs=0;fs<2;fs++)for(cache_mode=0;cache_mode<3;cache_mode++)
    for(read_error=0;read_error<2;read_error++)for(unsigned long n=0;n<4;n++) {
        lock_calls=unlock_calls=unchecked=ra_calls=0;
        struct folio *f=fs?f2fs_read_merkle_tree_page(&inode,0,n):ext4_read_merkle_tree_page(&inode,0,n);
        assert(!unchecked && !m.invalidate_lock && lock_calls==unlock_calls);
        assert(ra_calls==(unsigned int)(cache_mode==0 && n>1) && lock_calls==ra_calls);
        assert(IS_ERR(f)==(cache_mode!=2 && read_error));if(!IS_ERR(f))folio_put(f);
        assert(!live);
    }
    for(read_error=0;read_error<2;read_error++) {
        lock_calls=unlock_calls=unchecked=ra_calls=0;m.i_pages=NULL;
        assert(redirty_blocks(&inode,0,1)==(read_error?-EIO:0));
        assert(lock_calls==1 && unlock_calls==1 && !unchecked && !live && !m.invalidate_lock);
    }
    cache_mode=read_error=0;unchecked=0;
    folio_put(old_ext4_read_merkle_tree_page(&inode,0,2));
    folio_put(old_f2fs_read_merkle_tree_page(&inode,0,2));
    assert(!old_redirty_blocks(&inode,0,1));assert(unchecked==3 && !live);
    puts("Readahead lifetime and filesystem lock checks passed; three old missing-lock controls reproduced");
}
'''
program = shim + ''.join(excerpts) + checks
with tempfile.TemporaryDirectory(prefix='readahead-integration-') as tmp:
    src = Path(tmp)/'check.c'
    binary = Path(tmp)/'check'
    src.write_text(program)
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-sign-compare',
             '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(['cc', *flags, str(src), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout)
    old = subprocess.run([str(binary), 'old-uaf'], capture_output=True, text=True, timeout=15)
    assert old.returncode and 'heap-use-after-free' in old.stderr, old.stderr
record = {
    'source_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
    'negative_control_commit': baseline,
    'excerpts_sha256': hashlib.sha256(''.join(excerpts).encode()).hexdigest(),
    'compiler_flags': flags, 'result': result.stdout.strip(),
    'negative_control_asan_heap_use_after_free': True, 'scope': __doc__.strip(),
}
a.output.write_text(json.dumps(record, indent=2)+'\n')
print(record['result'])
