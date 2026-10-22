#!/usr/bin/env python3
"""Check extracted Android FUSE lookup reference and error handling with host shims."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
def function(s,n):
    m=re.search(r'^.*\b'+n+r'\([^;{}]*\)\n\{',s,re.M)
    assert m,n
    return s[m.start():s.index('\n}',m.end())+2]+'\n'
sources={p:(ROOT/p).read_text() for p in ['fs/fuse/dir.c','fs/fuse/fuse_bpf_backing.c']}
body='\n'.join(function(sources[p],n) for p,n in [
    ('fs/fuse/dir.c','fuse_entry_bpf_release'),
    ('fs/fuse/fuse_bpf_backing.c','fuse_handle_backing'),
    ('fs/fuse/fuse_bpf_backing.c','fuse_handle_bpf_prog'),
    ('fs/fuse/fuse_bpf_backing.c','fuse_lookup_finalize')])
prefix=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint64_t u64;
static unsigned assertions,cases,failures;
#define CHECK(x) (++assertions,((x)?0:(failures++,0)))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define atomic_read(p) (*(p))
#define xchg(p,v) ({ __typeof__(*(p)) _old=*(p); *(p)=(v); _old; })
enum { FUSE_ACTION_KEEP,FUSE_ACTION_REMOVE,FUSE_ACTION_REPLACE };
struct bpf_prog { int refs; };
struct inode;
struct fuse_inode { u64 nodeid; struct inode *backing_inode; struct bpf_prog *bpf; };
struct fuse_conn { int epoch; };
struct inode { void *i_sb; struct fuse_inode fi; struct fuse_conn *fc; int refs; };
struct dentry;
struct path { struct dentry *dentry; };
struct fuse_dentry { struct path backing_path; struct bpf_prog *bpf; };
struct dentry { struct inode *d_inode; struct fuse_dentry *fd; struct dentry *d_parent; unsigned long d_time; int refs; };
struct file { struct inode *f_inode; struct path f_path; struct bpf_prog *prog; int refs; };
struct fuse_entry_bpf_out { u64 backing_action,bpf_action; };
struct fuse_entry_bpf { struct fuse_entry_bpf_out out; struct file *backing_file,*bpf_file; };
struct fuse_entry_out { u64 nodeid; };
struct fuse_arg { void *value; };
struct fuse_bpf_args { struct fuse_arg out_args[2]; };
static int alloc_fail,splice_error,splices,file_puts;
static struct inode acquired;
static struct inode *expected_child;
static struct fuse_inode *get_fuse_inode(struct inode *i) { CHECK(i && !IS_ERR(i)); return &i->fi; }
static struct fuse_dentry *get_fuse_dentry(struct dentry *d) { return d->fd; }
static struct fuse_conn *get_fuse_conn(struct inode *i) { return i->fc; }
static void ihold(struct inode *i) { CHECK(i && !IS_ERR(i)); i->refs++; }
static void iput(struct inode *i) { if(i) { CHECK(!IS_ERR(i) && i->refs>0); i->refs--; } }
static void path_get(struct path *p) { if(p->dentry) p->dentry->refs++; }
static void path_put(struct path *p) { if(p->dentry) { CHECK(p->dentry->refs>0); p->dentry->refs--; } }
static void fput(struct file *f) { CHECK(f && !IS_ERR(f)); if(IS_ERR_OR_NULL(f)) return; CHECK(f->refs>0); f->refs--; file_puts++; }
static void bpf_prog_inc(struct bpf_prog *b) { CHECK(b && b->refs>0); b->refs++; }
static void bpf_prog_put(struct bpf_prog *b) { CHECK(b && b->refs>0); b->refs--; }
static struct bpf_prog *fuse_get_bpf_prog(struct file *f) { struct bpf_prog *b=f->prog; if(b) bpf_prog_inc(b); fput(f); return b?b:ERR_PTR(-EINVAL); }
static struct inode *fuse_iget_backing(void *sb,u64 id,struct inode *b) { CHECK(b==expected_child); if(alloc_fail) return NULL; acquired.refs++; return &acquired; }
static struct dentry *d_splice_alias(struct inode *i,struct dentry *d) { CHECK(i==&acquired); splices++; iput(i); return splice_error?ERR_PTR(-EIO):NULL; }
'''
main=r'''
int main(void) {
 /* A rejected backing object must never be passed to fput; unused BPF fds must close. */
 for(int a=0;a<3;a++) for(int b=0;b<3;b++) {
    struct file f={.refs=1},g={.refs=1};
    struct fuse_entry_bpf e={.backing_file=a==0?NULL:a==1?ERR_PTR(-ELOOP):&f,.bpf_file=b==0?NULL:b==1?ERR_PTR(-EINVAL):&g};
    fuse_entry_bpf_release(&e);fuse_entry_bpf_release(&e);
    CHECK(!e.backing_file && !e.bpf_file && f.refs==(a!=2) && g.refs==(b!=2)); cases++;
 }
 /* Replacement/keep/removal own exactly one inode and path reference. */
 for(int action=0;action<4;action++) for(int slot=0;slot<2;slot++) for(int source=0;source<3;source++) {
    struct inode old={.refs=2},next={.refs=1}; struct dentry od={.refs=2},nd={.refs=1};
    struct inode *current=&old;struct path path={.dentry=&od};
    struct file f={.refs=1,.f_inode=&next,.f_path={.dentry=&nd}};
    struct fuse_entry_bpf e={.out={.backing_action=action},.backing_file=source==0?NULL:source==1?ERR_PTR(-ELOOP):&f};
    int ret=fuse_handle_backing(&e,slot?&current:NULL,&path);
    int want=action==3?-EINVAL:action==FUSE_ACTION_REPLACE?(source==0?-EINVAL:source==1?-ELOOP:0):0;
    CHECK(ret==want);
    if(!ret && action==FUSE_ACTION_REMOVE) { CHECK(!path.dentry); CHECK(!slot || !current); }
    if(!ret && action==FUSE_ACTION_REPLACE) { CHECK(path.dentry==&nd); CHECK(!slot || current==&next); }
    if(slot) iput(current);else iput(&old);
    path_put(&path);CHECK(old.refs==1 && next.refs==1 && od.refs==1 && nd.refs==1);cases++;
 }
 /* Allocation failure must be an error, not a negative lookup or success. */
 for(int positive=0;positive<2;positive++) for(int fail=0;fail<2;fail++) for(int splice=0;splice<2;splice++) for(int bad=0;bad<2;bad++) {
    struct fuse_conn fc={.epoch=9};struct inode dir={.fc=&fc},child={.refs=1};struct bpf_prog prog={.refs=1};
    struct dentry lower={.d_inode=positive?&child:NULL,.refs=1};
    struct fuse_dentry fd={.backing_path={.dentry=&lower}};
    struct dentry entry={.fd=&fd}; struct fuse_entry_out out={.nodeid=7};
    struct file bpf={.refs=1,.prog=&prog};
    struct fuse_entry_bpf e={.out={.backing_action=bad?FUSE_ACTION_REPLACE:FUSE_ACTION_KEEP,.bpf_action=FUSE_ACTION_REPLACE},.backing_file=bad?ERR_PTR(-ELOOP):NULL,.bpf_file=&bpf};
    struct fuse_bpf_args fa={.out_args={{.value=&out},{.value=&e.out}}};
    acquired=(struct inode){0};expected_child=&child;alloc_fail=fail;splice_error=splice;splices=0;
    struct dentry *ret=fuse_lookup_finalize(&fa,&dir,&entry,0);
    long expected=positive?(fail?-ENOMEM:bad?-ELOOP:splice?-EIO:0):0;
    CHECK(PTR_ERR(ret)==expected);CHECK(!acquired.refs && !bpf.refs && !e.bpf_file && !e.backing_file);
    CHECK(splices==(positive && !fail && !bad));
    if(splices && !splice) CHECK(entry.d_time==9);
    if(acquired.fi.bpf) bpf_prog_put(acquired.fi.bpf);
    if(fd.bpf) bpf_prog_put(fd.bpf);
    CHECK(prog.refs==1);cases++;
 }
 printf("%u %u %u\n",cases,assertions,failures);return !!failures;
}
'''
controls={
 'error_pointer_fput':body.replace('!IS_ERR_OR_NULL(arg->backing_file)','arg->backing_file'),
 'double_put_bpf_file':body.replace('feb->bpf_file = NULL;',''),
 'lookup_oom_as_negative':body.replace('ret = ERR_PTR(-ENOMEM);','ret = NULL;'),
 'double_put_splice_error':body.replace('inode = NULL;\n\t\tif (!IS_ERR(ret))', 'if (!IS_ERR(ret))\n\t\t\tinode = NULL;\n\t\tif (!IS_ERR(ret))'),
}
with tempfile.TemporaryDirectory(prefix='fuse-bpf-lifetime-') as tmp:
    td=Path(tmp)
    def run(name,text,pass_expected):
        src=td/(name+'.c');exe=td/name;src.write_text(prefix+text+main)
        compiled=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],capture_output=True,text=True)
        assert compiled.returncode == 0, compiled.stderr
        p=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (p.returncode==0)==pass_expected,(name,p.stdout,p.stderr)
        return p.stdout
    output=run('current',body,True)
    for name,text in controls.items():
        assert text!=body,name
        run(name,text,False)
counts=list(map(int,output.split()))
report={'cases':counts[0],'assertions':counts[1],'failures':counts[2], 'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'negative_controls_rejected':list(controls),'scope':__doc__+' Inode/path/file/program references and alias outcomes are modeled; no live BPF, VFS locks or concurrent lookup test.'}
(D/'evidence/fuse-bpf-lifetime-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
