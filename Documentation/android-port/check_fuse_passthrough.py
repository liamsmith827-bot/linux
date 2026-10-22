#!/usr/bin/env python3
"""Exercise extracted FUSE mode ownership, registration and read-error paths.

Host shims model references and ordered callbacks; no live FUSE, LSM or race test.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]

def function(source, name):
    m = re.search(r'^.*\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    assert m, name
    return source[m.start():source.index('\n}', m.end()) + 2] + '\n'

common = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
static unsigned assertions, cases, failures;
#define CHECK(x) (++assertions, ((x) ? 0 : (failures++, 0)))
#define WARN_ON(x) CHECK(!(x))
#define WARN_ON_ONCE(x) CHECK(!(x))
#define READ_ONCE(x) (x)
#define pr_debug(...) ((void)0)
#define GFP_KERNEL 0
'''
mode_prefix = common + r'''
enum { IOM_NONE, IOM_CACHED, IOM_UNCACHED, IOM_PASSTHROUGH };
enum { FUSE_I_CACHE_IO_MODE };
struct fuse_backing { int refs; };
struct fuse_inode { int lock, iocachectr, iopassctr, direct_io_waitq; unsigned long state; struct fuse_backing *backing; };
struct inode { struct fuse_inode *fi; };
struct fuse_file { void *args; int iomode; };
#define get_fuse_inode(i) ((i)->fi)
static void spin_lock(int *lock) { CHECK(!*lock); ++*lock; }
static void spin_unlock(int *lock) { CHECK(*lock==1); --*lock; }
static void set_bit(int n,unsigned long *s) { *s|=1UL<<n; }
static void clear_bit(int n,unsigned long *s) { *s&=~(1UL<<n); }
static void wake_up(int *q) { ++*q; }
static struct fuse_backing *fuse_inode_backing(struct fuse_inode *fi) { return fi->backing; }
static struct fuse_backing *fuse_inode_backing_set(struct fuse_inode *fi,struct fuse_backing *b) {
    CHECK(fi->lock); struct fuse_backing *old=fi->backing; fi->backing=b; return old;
}
static void fuse_backing_put(struct fuse_backing *b) { if (b) { CHECK(b->refs>0); --b->refs; } }
static struct fuse_inode *waiting_inode;
static unsigned waits;
void fuse_inode_uncached_io_end(struct fuse_inode *fi);
static void finish_dio(void) {
    CHECK(waiting_inode && !waiting_inode->lock && waiting_inode->iocachectr<0);
    while (waiting_inode->iocachectr<0) fuse_inode_uncached_io_end(waiting_inode);
}
#define wait_event(q,c) do { CHECK(!(c)); ++waits; finish_dio(); CHECK(c); } while (0)
'''
mode_main = r'''
int main(void) {
 for (int p=0;p<5;p++) for (int d=0;d<5;d++) for(int cache=0;cache<5;cache++) for(int order=0;order<2;order++) {
    struct fuse_inode fi={0}; struct inode inode={.fi=&fi};
    struct fuse_backing a={.refs=1}, b={.refs=1};
    struct fuse_file pf[5]={0}, cf[5]={0};
    for(int j=0;j<p;j++) { ++a.refs; CHECK(!fuse_file_uncached_io_open(&inode,&pf[j],&a)); }
    CHECK(fi.iopassctr==p && !fi.iocachectr && a.refs==1+(p>0));
    if(p) { ++b.refs; CHECK(fuse_inode_uncached_io_start(&fi,&b)==-EBUSY); fuse_backing_put(&b); CHECK(b.refs==1); }
    for(int j=0;j<d;j++) CHECK(!fuse_inode_uncached_io_start(&fi,NULL));
    CHECK(fi.iocachectr==-d && fuse_is_io_cache_wait(&fi)==(d>0));
    if(order) for(int j=0;j<p;j++) fuse_file_passthrough_io_release(&pf[j],&fi);
    unsigned oldwait=waits;
    for(int j=0;j<cache;j++) { cf[j].args=&inode; waiting_inode=&fi; CHECK(!fuse_file_cached_io_open(&inode,&cf[j])); }
    if(cache) { CHECK(fi.iocachectr==cache); CHECK(waits-oldwait==(d>0)); CHECK(fi.state==1); CHECK(fuse_inode_uncached_io_start(&fi,NULL)==-ETXTBSY); }
    else while(fi.iocachectr<0) fuse_inode_uncached_io_end(&fi);
    CHECK(fi.iopassctr==(order?0:p));
    CHECK(fi.backing==((!order && p)?&a:NULL));
    CHECK(a.refs==1+(!order && p));
    for(int j=0;j<cache;j++) fuse_file_cached_io_release(&cf[j],&fi);
    if(!order) for(int j=0;j<p;j++) fuse_file_passthrough_io_release(&pf[j],&fi);
    CHECK(!fi.iocachectr && !fi.iopassctr && !fi.backing && a.refs==1 && !fi.lock && !fi.state);
    cases++;
 }
 printf("%u %u %u\n",cases,assertions,failures); return !!failures;
}
'''
registration_prefix = common + r'''
struct cred { int live; };
struct super_block { int s_stack_depth; };
struct inode { struct super_block *i_sb; };
struct dentry { int type; };
struct path { struct dentry *dentry; };
struct file { struct path f_path; struct inode *inode; int refs; };
struct fuse_backing { struct file *file; struct cred *cred; int count; };
struct fuse_conn { int passthrough, max_stack_depth; struct fuse_backing *registered; };
struct fuse_backing_map { int fd, flags, padding; };
static struct super_block sb; static struct inode ino={.i_sb=&sb};
static struct dentry de; static struct file lower={.f_path={.dentry=&de},.inode=&ino};
static int fail_alloc, fail_creds, fail_id, files, objects, creds;
static struct file *fget_raw(int fd) { if(fd!=5) return NULL; lower.refs++; files++; return &lower; }
static void fput(struct file *f) { CHECK(f==&lower && f->refs>0); --f->refs; --files; }
static void *kmalloc(size_t n,unsigned flags) { if(fail_alloc) return NULL; objects++; return calloc(1,n); }
static void kfree(void *p) { CHECK(p && objects>0); objects--; free(p); }
#define kfree_rcu(p,field) kfree(p)
static struct cred *prepare_creds(void) { if(fail_creds) return NULL; creds++; return calloc(1,sizeof(struct cred)); }
static void put_cred(struct cred *c) { CHECK(c && creds>0); if(c) { creds--; free(c); } }
static void refcount_set(int *p,int v) { *p=v; }
static bool refcount_dec_and_test(int *p) { CHECK(*p>0); return !--*p; }
#define file_inode(f) ((f)->inode)
#define d_is_dir(d) ((d)->type==2)
#define d_is_reg(d) ((d)->type==1)
static int fuse_backing_id_alloc(struct fuse_conn *fc,struct fuse_backing *fb) { if(fail_id) return -ENOSPC; CHECK(!fc->registered); fc->registered=fb; return 1; }
static struct fuse_backing *fuse_backing_id_remove(struct fuse_conn *fc,int id) { if(id!=1) return NULL; struct fuse_backing *fb=fc->registered; fc->registered=NULL; return fb; }
'''
registration_main = r'''
int main(void) {
 for(int enabled=0;enabled<2;enabled++) for(int flags=0;flags<2;flags++) for(int pad=0;pad<2;pad++)
 for(int validfd=0;validfd<2;validfd++) for(int type=0;type<3;type++) for(int depth=0;depth<3;depth++)
 for(int fault=0;fault<4;fault++) {
   struct fuse_conn fc={.passthrough=enabled,.max_stack_depth=2};
   struct fuse_backing_map map={.fd=validfd?5:-1,.flags=flags,.padding=pad};
   de.type=type; sb.s_stack_depth=depth;
   fail_alloc=fault==1;fail_creds=fault==2;fail_id=fault==3;
   int want=!enabled?-EPERM:(flags||pad)?-EINVAL:!validfd?-EBADF:type==2?-EISDIR:type!=1?-EINVAL:depth>=2?-ELOOP:(fail_alloc||fail_creds)?-ENOMEM:fail_id?-ENOSPC:1;
   int ret=fuse_backing_open(&fc,&map); CHECK(ret==want);
   if(ret>0) { CHECK(objects==1 && creds==1 && files==1 && fc.registered); CHECK(!fuse_backing_close(&fc,ret)); }
   CHECK(!fc.registered && !objects && !creds && !files && !lower.refs);
   CHECK(fuse_backing_close(&fc,0)==(enabled?-EINVAL:-EPERM));
   CHECK(fuse_backing_close(&fc,123)==(enabled?-ENOENT:-EPERM)); cases++;
 }
 printf("%u %u %u\n",cases,assertions,failures); return !!failures;
}
'''
read_prefix = common + r'''
#include <sys/types.h>
struct inode { int marker; };
struct file { void *private_data; struct inode *inode; };
struct fuse_file { struct file *passthrough; void *cred; };
struct kiocb { struct file *ki_filp; loff_t ki_pos; int ki_flags; };
struct iov_iter { size_t count; };
struct pipe_inode_info { int unused; };
struct backing_file_ctx { void *cred; void (*accessed)(struct file *); };
static int flush_result, reads, flushes;
#define file_inode(f) ((f)->inode)
#define fuse_file_passthrough(ff) ((ff)->passthrough)
#define iov_iter_count(i) ((i)->count)
static void fuse_file_accessed(struct file *f) { }
static int write_inode_now(struct inode *i,int sync) { CHECK(sync==1 && i->marker==42); flushes++; return flush_result; }
static void init_sync_kiocb(struct kiocb *k,struct file *f) { *k=(struct kiocb){.ki_filp=f}; }
static ssize_t backing_file_read_iter(struct file *f,struct iov_iter *i,struct kiocb *k,int flags,struct backing_file_ctx *ctx) { reads++; CHECK(!flush_result && flushes==1); k->ki_pos+=i->count; return i->count; }
static ssize_t backing_file_splice_read(struct file *f,struct kiocb *k,struct pipe_inode_info *p,size_t len,unsigned flags,struct backing_file_ctx *ctx) { reads++; CHECK(!flush_result && flushes==1); k->ki_pos+=len; return len; }
'''
read_main = r'''
int main(void) {
 int errors[]={0,-EIO,-ENOSPC,-EINTR};
 for(unsigned e=0;e<4;e++) for(int n=0;n<4;n++) for(int splice=0;splice<2;splice++) {
    struct inode inode={.marker=42}; struct file backing={0};
    struct fuse_file ff={.passthrough=&backing}; struct file file={.private_data=&ff,.inode=&inode};
    struct kiocb k={.ki_filp=&file,.ki_pos=77};struct iov_iter iter={.count=n};loff_t pos=77;
    reads=flushes=0;flush_result=errors[e];
    ssize_t ret=splice?fuse_passthrough_splice_read(&file,&pos,NULL,n,0):fuse_passthrough_read_iter(&k,&iter);
    bool empty=!splice && !n;
    CHECK(ret==(empty?0:flush_result?flush_result:n));
    CHECK(reads==(!empty && !flush_result)); CHECK(flushes==!empty);
    CHECK((splice?pos:k.ki_pos)==77+((!empty && !flush_result)?n:0)); cases++;
 }
 printf("%u %u %u\n",cases,assertions,failures); return !!failures;
}
'''

specs = [
 ('io_modes', 'fs/fuse/iomode.c', ['fuse_is_io_cache_wait','fuse_file_cached_io_open','fuse_file_cached_io_release','fuse_inode_uncached_io_start','fuse_file_uncached_io_open','fuse_inode_uncached_io_end','fuse_inode_passthrough_io_end','fuse_file_passthrough_io_release'], mode_prefix, mode_main),
 ('registration', 'fs/fuse/backing.c', ['fuse_backing_free','fuse_backing_put','fuse_backing_open','fuse_backing_close'], registration_prefix, registration_main),
 ('read_errors', 'fs/fuse/passthrough.c', ['fuse_passthrough_read_iter','fuse_passthrough_splice_read'], read_prefix, read_main),
]
results=[]
with tempfile.TemporaryDirectory(prefix='fuse-passthrough-check-') as tmp:
    td=Path(tmp)
    def run(label, body, prefix, main, must_pass):
        src=td/(label+'.c'); exe=td/label;src.write_text(prefix+'\n'+body+'\n'+main)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-parameter',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True,capture_output=True,text=True)
        p=subprocess.run([str(exe)],capture_output=True,text=True)
        values=list(map(int,p.stdout.split()))
        assert len(values)==3,(label,p.stdout,p.stderr)
        assert (p.returncode==0)==must_pass,(label,p.returncode,p.stdout,p.stderr)
        return {'name':label,'cases':values[0],'assertions':values[1],'failures':values[2], 'expected_failure':not must_pass}
    for label,path,names,prefix,main in specs:
        source=(ROOT/path).read_text()
        body='\n'.join(function(source,n) for n in names)
        result=run(label,body,prefix,main,True)
        result.update(source=path,functions=names,extracted_sha256=hashlib.sha256(body.encode()).hexdigest())
        controls=[]
        if label=='io_modes':
            controls.append(('ignore_dio_with_backing',body.replace('READ_ONCE(fi->iocachectr) < 0;', 'READ_ONCE(fi->iocachectr) < 0 && !fuse_inode_backing(fi);')))
            controls.append(('drop_backing_at_dio_end',body.replace('wake_up(&fi->direct_io_waitq);', 'wake_up(&fi->direct_io_waitq);\n\tif (!fi->iocachectr) fuse_backing_put(fuse_inode_backing_set(fi, NULL));')))
        elif label=='registration':
            controls.append(('accept_unnegotiated',body.replace('if (!fc->passthrough)', 'if (false)')))
            controls.append(('accept_missing_creds',body.replace('if (!fb->cred)', 'if (false)')))
        else:
            controls.append(('ignore_writeback_error',body.replace('if (ret)\n\t\treturn ret;', 'if (false)\n\t\treturn ret;')))
        for name,variant in controls:
            assert variant!=body,name
            run(label+'_'+name,variant,prefix,main,False)
        result['negative_controls_rejected']=[n for n,_ in controls]
        results.append(result)
out={'checks':results,'scope':__doc__,'compiler':'host cc with undefined-behavior sanitizer'}
(D/'evidence/fuse-passthrough-check.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
