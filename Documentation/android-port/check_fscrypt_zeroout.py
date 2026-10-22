#!/usr/bin/env python3
"""Check extracted inline-crypto zeroout batching, sectors, errors and ownership."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
source = (ROOT/'fs/crypto/bio.c').read_text()
start = source.index('struct fscrypt_zero_done {')
end = source.index('/**\n * fscrypt_zeroout_range()', start)
body = source[start:end]
prefix = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PAGE_SHIFT 12
#define SECTOR_SHIFT 9
#define BIO_MAX_VECS 256
#define REQ_OP_WRITE 1
#define GFP_NOFS 1
#define ZERO_PAGE(x) ((void *)0)
#define min(a,b) ((a)<(b)?(a):(b))
#define WARN_ON_ONCE(x) (CHECK(!(x)),(x))
typedef uint64_t sector_t;
typedef unsigned long pgoff_t;
typedef unsigned char blk_status_t;
typedef int atomic_t;
struct completion { int count; };
#define ATOMIC_INIT(x) (x)
#define COMPLETION_INITIALIZER_ONSTACK(x) {0}
static bool atomic_dec_and_test(atomic_t *p) { return --*p==0; }
static void atomic_inc(atomic_t *p) { ++*p; }
#define cmpxchg(p,old,new) ({ __typeof__(*(p)) v=*(p); if (v==(old)) *(p)=(new); v; })
struct super_block { int *s_bdev; };
struct inode { unsigned i_blkbits; struct super_block *i_sb; };
struct bio {
    struct { sector_t bi_sector; } bi_iter;
    void *bi_private;
    void (*bi_end_io)(struct bio *);
    blk_status_t bi_status;
    pgoff_t lblk;
    unsigned bytes, pages, submitted;
};
static unsigned failures, assertions, cases;
#define CHECK(x) (++assertions, ((x)?0:(failures++,0)))
static struct bio *pending[2048];
static unsigned nr_pending, outstanding, allocs, frees, submitted, bytes_seen;
static int completion_mode, error_mode;
static bool in_submit, wrap32;
static uint32_t hashed_ino;
static unsigned blkbits;
static pgoff_t expected_lblk;
static sector_t expected_sector;
static unsigned expected_bytes, completed_error;
static void complete(struct completion *c) {
    CHECK(!in_submit && !outstanding); CHECK(++c->count==1);
}
static struct bio *bio_alloc(int *dev,unsigned n,unsigned op,unsigned gfp) {
    CHECK(n==BIO_MAX_VECS && op==REQ_OP_WRITE && gfp==GFP_NOFS);
    allocs++; return calloc(1,sizeof(struct bio));
}
static void bio_put(struct bio *bio) { CHECK(bio->submitted==1); frees++; free(bio); }
static void fscrypt_set_bio_crypt_ctx(struct bio *bio,const struct inode *i,pgoff_t lblk,unsigned gfp) {
    CHECK(!bio->bytes && i->i_blkbits==blkbits && gfp==GFP_NOFS); bio->lblk=lblk;
}
static void __bio_add_page(struct bio *b,void *page,unsigned bytes,unsigned offset) {
    CHECK(!page && !offset && bytes && bytes<=4096 && !(bytes% (1U<<blkbits)));
    CHECK(b->pages<BIO_MAX_VECS); b->pages++; b->bytes+=bytes;
}
static bool fscrypt_mergeable_bio(struct bio *b,const struct inode *i,pgoff_t next) {
    CHECK(next==b->lblk+(b->bytes>>blkbits));
    return !wrap32 || (uint64_t)(uint32_t)(hashed_ino+b->lblk)+(b->bytes>>blkbits)<=UINT32_MAX;
}
static int blk_status_to_errno(blk_status_t s) { return s ? -(int)s:0; }
static void finish(struct bio *b) {
    CHECK(outstanding>0); outstanding--;
    if (b->bi_status && !completed_error) completed_error=b->bi_status;
    b->bi_end_io(b);
}
static void submit_bio(struct bio *b) {
    CHECK(!b->submitted && b->bytes && b->pages<=BIO_MAX_VECS);
    CHECK(b->bi_iter.bi_sector==expected_sector && b->lblk==expected_lblk);
    if (wrap32) CHECK((uint64_t)(uint32_t)(hashed_ino+b->lblk)+(b->bytes>>blkbits)<=((uint64_t)UINT32_MAX+1));
    expected_sector+=b->bytes>>SECTOR_SHIFT; expected_lblk+=b->bytes>>blkbits;
    bytes_seen+=b->bytes; b->submitted=1; outstanding++;
    b->bi_status=error_mode==0 ? 0 : error_mode==1 ? (submitted==0 ? 5:0) :
                 error_mode==2 ? (submitted%2 ? 12:5) : (bytes_seen==expected_bytes ? 11:0);
    submitted++;
    in_submit=true;
    if (completion_mode==0 || (completion_mode==2 && submitted%2)) finish(b);
    else { CHECK(nr_pending<2048); pending[nr_pending++]=b; }
    in_submit=false;
}
static void wait_for_completion(struct completion *c) {
    while (nr_pending) finish(pending[--nr_pending]);
    CHECK(c->count==1 && outstanding==0 && allocs==frees);
}
'''
suffix = r'''
int main(void) {
    const unsigned lengths[]={0,1,2,3,4,17,255,256,257,1025,2049};
    const uint32_t hashes[]={0,UINT32_MAX-37,UINT32_MAX-38,UINT32_MAX-54};
    for (blkbits=10;blkbits<=12;blkbits++)
    for (unsigned n=0;n<sizeof(lengths)/sizeof(*lengths);n++)
    for (unsigned h=0;h<sizeof(hashes)/sizeof(*hashes);h++)
    for (completion_mode=0;completion_mode<3;completion_mode++)
    for (error_mode=0;error_mode<4;error_mode++) {
        struct super_block sb={0}; struct inode inode={blkbits,&sb};
        allocs=frees=outstanding=nr_pending=submitted=bytes_seen=completed_error=0;
        in_submit=false; wrap32=blkbits==12; hashed_ino=hashes[h];
        expected_lblk=37; expected_sector=(1ULL<<33)+13;
        expected_bytes=lengths[n]<<blkbits;
        int result=fscrypt_zeroout_range_inline_crypt(&inode,expected_lblk,expected_sector,lengths[n]);
        CHECK(result==-(int)completed_error);
        CHECK(bytes_seen==expected_bytes && allocs==frees && !outstanding && !nr_pending);
        CHECK(expected_lblk==37+lengths[n]);
        CHECK(expected_sector==((1ULL<<33)+13)+(expected_bytes>>SECTOR_SHIFT));
        cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
variants = {
    'port': body,
    'missing_producer_reference_control': body.replace('ATOMIC_INIT(1)', 'ATOMIC_INIT(0)'),
    'wrong_sector_units_control': body.replace('sector += (bytes_this_page >> SECTOR_SHIFT);','sector += blocks_this_page;'),
    'missing_error_control': body.replace('cmpxchg(&done->status, 0, bio->bi_status);','(void)bio;'),
    'missing_dun_split_control': body.replace('!len || !fscrypt_mergeable_bio(bio, inode, lblk)','!len'),
}
runs = {}
with tempfile.TemporaryDirectory(prefix='fscrypt-zeroout-') as tmp:
    for name, code in variants.items():
        c, exe = Path(tmp)/(name+'.c'), Path(tmp)/name
        c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Werror','-Wno-unused-parameter',
                        '-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=all',
                        str(c),'-o',str(exe)],check=True)
        p=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (p.returncode==0)==(name=='port'),(name,p.stdout,p.stderr)
        runs[name]=dict(exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr)
(D/'evidence/fscrypt-zeroout-check.json').write_text(json.dumps(dict(
    scope=__doc__+' Modeled immediate, deferred reverse-order and mixed completions; not real concurrent I/O or encryption.',
    source_sha256=hashlib.sha256(source.encode()).hexdigest(),runs=runs,remote_resources=[]),indent=2)+'\n')
print(runs['port']['stdout'].strip())
print('Four regression controls rejected')
