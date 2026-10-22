#!/usr/bin/env python3
"""Extract F2FS reader/completion code and exercise deterministic bio schedules.

Host shims test control flow and accounting, not kernel I/O, crypto or locking.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'

def function(source, name):
    m = re.search(r'^.*\b' + name + r'\([^;{]*\)\n\{', source, re.M)
    assert m, name
    depth, i = 1, m.end()
    while depth:
        depth += (source[i] == '{') - (source[i] == '}')
        i += 1
    return source[m.start():i] + '\n'

source = (ROOT / 'fs/f2fs/data.c').read_text()
ack = subprocess.check_output(['git', '-C', str(ROOT), 'show',
                              ACK + ':fs/f2fs/data.c'], text=True)
names = ['ffs_complete_read', 'f2fs_finish_read_bio',
         'f2fs_read_data_large_folio']
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define F2FS_BLKSIZE PAGE_SIZE
#ifndef EFSCORRUPTED
#define EFSCORRUPTED EUCLEAN
#endif
#define F2FS_MAP_MAPPED 1
#define NO_CHECK_TYPE 0
#define F2FS_GET_BLOCK_DEFAULT 0
#define DATA_GENERIC_ENHANCE_READ 0
#define F2FS_RD_DATA 0
#define FS_DATA_READ_IO 0
#define DATA 0
#define NODE_TYPE_REGULAR 0
#define BLK_STS_OK 0
#define BLK_STS_IOERR 1
typedef unsigned long pgoff_t;
typedef unsigned long sector_t;
struct f2fs_folio_state { int state_lock; unsigned read_pages_pending;
                         bool read_failed; };
struct folio { void *private; unsigned index, pages, ends;
               bool locked, uptodate, node, compressed; };
struct f2fs_sb_info { int node_inode; } sb;
struct inode { bool immutable, compressed; };
struct folio_iter { struct folio *folio; unsigned length; };
struct bio { int bi_status; void *bi_private; unsigned n, cursor, start;
             struct folio_iter vec[16]; };
struct bio_post_read_ctx { bool decompression_attempted; };
struct readahead_control { struct folio **folios; unsigned n, cursor, count; };
struct f2fs_map_blocks { unsigned m_flags, m_seg_type;
                       pgoff_t m_lblk, m_len, m_pblk, *m_next_pgofs; };
static unsigned assertions, failures, cases;
#define CHECK(c) do { assertions++; if (!(c)) { failures++; \
    if (failures < 12) fprintf(stderr, "line %d: %s\n", __LINE__, #c); } } while (0)
#define WARN_ON_ONCE(c) CHECK(!(c))
#define spin_lock_irqsave(l,f) do { (f)=0; CHECK(!(*(l))++); } while (0)
#define spin_unlock_irqrestore(l,f) do { (void)(f); CHECK(--(*(l))==0); } while (0)
#define spin_lock_irq(l) do { CHECK(!(*(l))++); } while (0)
#define spin_unlock_irq(l) do { CHECK(--(*(l))==0); } while (0)
#define F2FS_I_SB(i) (&sb)
#define F2FS_F_SB(f) (&sb)
#define IS_IMMUTABLE(i) ((i)->immutable)
#define bio_for_each_folio_all(fi,b) \
    for ((b)->cursor=0; (b)->cursor<(b)->n && \
         (((fi)=(b)->vec[(b)->cursor]),1); (b)->cursor++)
static int kinds[16], io_failure, immediate, capacity, contiguous;
static int io_count, bios, frees, zeros[16], added[16], verifications[16];
static struct bio *queue[32];
static unsigned queued;
static void *bio_post_read_ctx_pool;
static bool folio_test_large(struct folio *f) { return f->pages>1; }
static unsigned folio_nr_pages(struct folio *f) { return f->pages; }
static bool f2fs_compressed_file(struct inode *i) { return i->compressed; }
static void folio_unlock(struct folio *f) { CHECK(f->locked); f->locked=false; }
static void folio_end_read(struct folio *f, bool ok)
{ CHECK(f->locked); f->locked=false; f->uptodate=ok; f->ends++; }
static bool f2fs_is_compressed_page(struct folio *f)
{ CHECK(!folio_test_large(f)); return f->compressed; }
static void f2fs_end_read_compressed_page(struct folio *f, bool e, int n, bool t)
{ CHECK(f->compressed && e); }
static void f2fs_put_folio_dic(struct folio *f, bool t) { CHECK(f->compressed); }
static int __read_io_type(struct folio *f) { return 0; }
static void dec_page_count(struct f2fs_sb_info *s, int type) { io_count--; }
static void inc_page_count(struct f2fs_sb_info *s, int type) { io_count++; }
static bool is_node_folio(struct folio *f) { return f->node; }
static bool f2fs_sanity_check_node_footer(struct f2fs_sb_info *s,
        struct folio *f, unsigned index, int type, bool check) { return f->node; }
static void mempool_free(void *p, void *pool) { free(p); frees++; }
static void bio_put(struct bio *b) { bios--; free(b); }
static struct f2fs_folio_state *ffs_find_or_alloc(struct folio *f)
{ if (!f->private) f->private=calloc(1,sizeof(struct f2fs_folio_state));
  return f->private; }
static unsigned readahead_count(struct readahead_control *r) { return r->count; }
static struct folio *readahead_folio(struct readahead_control *r)
{ return r->cursor<r->n ? r->folios[r->cursor++] : NULL; }
static void f2fs_update_read_folio_count(struct f2fs_sb_info *s, struct folio *f)
{ CHECK(f->locked); }
static int f2fs_map_blocks(struct inode *i, struct f2fs_map_blocks *m, int type)
{
    CHECK(m->m_len>0); unsigned index=m->m_lblk;
    if (kinds[index]==2) return -EIO;
    if (kinds[index]==0 || kinds[index]==4) {
        *m->m_next_pgofs=index+1;
        while (*m->m_next_pgofs<16 && kinds[*m->m_next_pgofs]==0)
            (*m->m_next_pgofs)++;
    } else {
        m->m_flags=F2FS_MAP_MAPPED;
        m->m_pblk=100+index*(contiguous ? 1 : 2); m->m_len=1;
    }
    return 0;
}
static bool f2fs_is_valid_blkaddr(struct f2fs_sb_info *s, sector_t b, int t)
{ return kinds[(b-100)/(contiguous ? 1 : 2)]!=3; }
static void folio_zero_range(struct folio *f, unsigned offset, unsigned len)
{ CHECK(f->locked); CHECK(len==PAGE_SIZE && offset/PAGE_SIZE<f->pages);
  zeros[f->index+offset/PAGE_SIZE]++; }
static bool f2fs_need_verity(struct inode *i, pgoff_t p) { return true; }
static bool fsverity_verify_blocks(struct folio *f, unsigned len, unsigned off)
{ CHECK(f->locked && len==PAGE_SIZE); unsigned index=f->index+off/PAGE_SIZE;
  CHECK(zeros[index]==1); verifications[index]++; return kinds[index]!=4; }
static bool page_is_mergeable(struct f2fs_sb_info *s, struct bio *b,
                              sector_t last, sector_t next) { return last+1==next; }
static bool f2fs_crypt_mergeable_bio(struct bio *b, struct inode *i,
                                    pgoff_t index, void *p) { return true; }
static void f2fs_finish_read_bio(struct bio *, bool);
static void f2fs_submit_read_bio(struct f2fs_sb_info *s, struct bio *b, int type)
{ if (!b) return; CHECK(b->n>0); if (immediate) f2fs_finish_read_bio(b,true);
  else { CHECK(queued<32); queue[queued++]=b; } }
static struct bio *f2fs_grab_read_bio(struct inode *i, sector_t b,
                 unsigned nr, int flags, pgoff_t index, bool wr)
{ CHECK(nr>0); struct bio *bio=calloc(1,sizeof(*bio)); bios++;
  bio->start=index; bio->bi_private=calloc(1,sizeof(struct bio_post_read_ctx));
  return bio; }
static int f2fs_ra_op_flags(struct readahead_control *r) { return 0; }
static void f2fs_wait_on_block_writeback(struct inode *i, sector_t b) { }
static bool bio_add_folio(struct bio *b, struct folio *f, unsigned len, unsigned off)
{ CHECK(f->locked); CHECK(off/PAGE_SIZE<f->pages && len==PAGE_SIZE);
  if (b->n==(unsigned)capacity) return false;
  unsigned index=f->index+off/PAGE_SIZE; added[index]++;
  b->vec[b->n++]=(struct folio_iter){f,len};
  if ((int)index==io_failure) b->bi_status=BLK_STS_IOERR;
  return true; }
static void f2fs_update_iostat(struct f2fs_sb_info *s, struct inode *i,
                              int type, unsigned n) { }
static void trace_f2fs_read_folio(struct folio *f, int t) { CHECK(f->locked); }
'''
suffix = r'''
static void reset(void)
{
    CHECK(!bios && !io_count && !queued);
    memset(kinds,0,sizeof(kinds)); memset(zeros,0,sizeof(zeros));
    memset(added,0,sizeof(added)); memset(verifications,0,sizeof(verifications));
    io_failure=-1; immediate=0; capacity=2; contiguous=0;
}
static void drain(bool reverse)
{
    unsigned n=queued; queued=0;
    for (unsigned i=0;i<n;i++) f2fs_finish_read_bio(queue[reverse?n-1-i:i],true);
}
static void release(struct folio *f)
{
    if (f->private) {
        CHECK(!((struct f2fs_folio_state *)f->private)->read_pages_pending);
        free(f->private);
    }
}
int main(void)
{
    struct inode inode={true,false};
    /* All 4-subpage combinations: holes, data, map error, invalid block,
       hole-verity error; each I/O-error position and three completion orders. */
    for (unsigned pattern=0;pattern<625;pattern++)
    for (int mode=0;mode<3;mode++)
    for (int fail=-1;fail<4;fail++) {
        reset(); cases++; unsigned p=pattern; bool bad=false; int expected=0;
        for (unsigned j=0;j<4;j++) { kinds[j]=p%5; p/=5; }
        for (int j=0;j<4;j++) {
            if (kinds[j]>=2) { expected=kinds[j]==3 ? -EFSCORRUPTED:-EIO;
                              bad=true; break; }
            if (kinds[j]==1 && j==fail) bad=true;
        }
        io_failure=fail; immediate=mode==0;
        struct folio f={.pages=4,.locked=true};
        int ret=f2fs_read_data_large_folio(&inode,NULL,&f);
        CHECK(ret==expected); drain(mode==2);
        CHECK(f.ends==1 && !f.locked && f.uptodate==!bad);
        CHECK(!bios && !io_count); release(&f);
    }
    /* Coalescing, bio capacity retry, state reuse and order-0 mixed readahead. */
    for (int mode=0;mode<3;mode++)
    for (int cap=1;cap<=4;cap++) {
        reset(); cases++; immediate=mode==0; contiguous=1; capacity=cap;
        for (int j=0;j<4;j++) kinds[j]=1;
        struct folio f={.pages=4,.locked=true};
        CHECK(!f2fs_read_data_large_folio(&inode,NULL,&f)); drain(mode==2);
        CHECK(f.ends==1 && f.uptodate);
        f.locked=true; f.uptodate=false; io_failure=0;
        CHECK(!f2fs_read_data_large_folio(&inode,NULL,&f)); drain(mode==2);
        CHECK(f.ends==2 && !f.uptodate); release(&f);
        reset(); immediate=mode==0;
        struct folio a={.pages=1,.locked=true}, b={.index=1,.pages=1,.locked=true};
        struct folio c={.index=4,.pages=4,.locked=true};
        struct folio *fs[]={&a,&b,&c};
        struct readahead_control rac={fs,3,0,6}; kinds[0]=1; kinds[4]=1;
        CHECK(!f2fs_read_data_large_folio(&inode,&rac,NULL)); drain(mode==2);
        CHECK(a.ends==1 && b.ends==1 && c.ends==1);
        CHECK(a.uptodate && b.uptodate && c.uptodate); release(&c);
    }
    /* A later folio failing before insertion must flush the earlier bio,
       stop readahead, and end the failed folio exactly once. */
    for (int mode=0;mode<3;mode++)
    for (int kind=2;kind<=4;kind++)
    for (unsigned pages=1;pages<=4;pages*=4) {
        reset(); cases++; immediate=mode==0;
        kinds[0]=1; kinds[4]=kind;
        struct folio a={.pages=4,.locked=true};
        struct folio b={.index=4,.pages=pages,.locked=true};
        struct folio c={.index=8,.pages=1,.locked=true};
        struct folio *fs[]={&a,&b,&c};
        struct readahead_control rac={fs,3,0,5+pages};
        CHECK(f2fs_read_data_large_folio(&inode,&rac,NULL)==
              (kind==3 ? -EFSCORRUPTED:-EIO));
        drain(mode==2);
        CHECK(a.ends==1 && a.uptodate && b.ends==1 && !b.uptodate);
        CHECK(c.locked && !c.ends && rac.cursor==2);
        release(&a); release(&b);
    }
    reset(); cases++;
    struct readahead_control empty={0};
    CHECK(!f2fs_read_data_large_folio(&inode,&empty,NULL));
    for (int kind=0;kind<2;kind++) {
        struct folio f={.pages=4,.locked=true};
        inode.immutable=kind!=0; inode.compressed=kind!=0;
        CHECK(f2fs_read_data_large_folio(&inode,NULL,&f)==-EOPNOTSUPP);
        CHECK(!f.locked && !f.private);
    }
    /* Native node-footer failure must still invalidate order-0 reads. */
    reset(); sb.node_inode=1;
    struct folio f={.pages=1,.locked=true,.node=true};
    struct bio *bio=calloc(1,sizeof(*bio)); bios++; io_count++;
    bio->n=1; bio->vec[0]=(struct folio_iter){&f,PAGE_SIZE};
    f2fs_finish_read_bio(bio,true); CHECK(f.ends==1 && !f.uptodate);
    CHECK(!bios && !io_count);
    printf("cases=%u assertions=%u failures=%u\n",cases,assertions,failures);
    return failures ? 1:0;
}
'''
control = r'''
int main(void) {
    struct f2fs_folio_state state={.read_pages_pending=4};
    struct folio f={.private=&state,.pages=4,.locked=true};
    io_count=4;
    for (unsigned i=0;i<2;i++) {
        struct bio *b=calloc(1,sizeof(*b)); bios++;
        b->n=1; b->vec[0]=(struct folio_iter){&f,2*PAGE_SIZE};
        b->bi_status=i==0 ? BLK_STS_IOERR:BLK_STS_OK;
        f2fs_finish_read_bio(b,true);
    }
    CHECK(f.ends==1 && !f.uptodate && !io_count);
    printf("cases=%u assertions=%u failures=%u\n",++cases,assertions,failures);
    return failures ? 1:0;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-largefolio-check-') as tmp:
    tmp = Path(tmp)
    runs = {}
    bodies = {
        'port-reader': '\n'.join(function(source, n) for n in names) + suffix,
        'port-error-control': function(source, names[0]) +
                              function(source, names[1]) + control,
        'ack-error-control': function(ack, names[1]) + control,
    }
    for label, body in bodies.items():
        c = tmp / (label + '.c'); exe = tmp / label
        c.write_text(prefix + body)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-Wno-unused-function',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        str(c), '-o', str(exe)], check=True)
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        runs[label] = {'returncode': r.returncode, 'stdout': r.stdout,
                       'stderr': r.stderr}
    assert runs['port-reader']['returncode'] == 0, runs
    assert runs['port-error-control']['returncode'] == 0, runs
    assert runs['ack-error-control']['returncode'] != 0, runs
evidence = {
    'source': 'fs/f2fs/data.c',
    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
    'extracted_functions': names,
    'ack_control': ACK,
    'runs': runs,
    'limits': 'Deterministic host shims; no kernel I/O, crypto, real concurrency, '
              'filesystem mount or runtime test. Native node-footer check exercised '
              'with a stub failure. Actual crypto/verity failure production is not tested.',
    'remote_resources': [],
}
(D / 'evidence/f2fs-largefolio-check.json').write_text(json.dumps(evidence, indent=2)+'\n')
print(json.dumps(runs, indent=2))
