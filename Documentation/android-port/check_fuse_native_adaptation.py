#!/usr/bin/env python3
"""Check extracted FUSE native-preservation and backing error paths with host shims.
No kernel, mount, BPF load, actual lock, permission or I/O operation is executed.
"""
import argparse,hashlib,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[2]
def function(s,n):
 m=re.search(r'^.*\b'+n+r'\([^;{}]*\)\n\{',s,re.M);assert m,n
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
paths=['fs/fuse/fuse_bpf_backing.c','fs/fuse/file.c','fs/fuse/dir.c','fs/fuse/inode.c','fs/fuse/fuse_i.h']
s={p:(root/p).read_text()for p in paths};B=s[paths[0]]
L='2ff600d29ee478d0a8d46ef8a58afb5e038fe692';old='3d59ee0c246b1e66136498c74eaa5e137a5fc09a'
native=subprocess.check_output(['git','show',L+':fs/fuse/inode.c'],cwd=root,text=True)
assert function(native,'fuse_init_inode')==function(s['fs/fuse/inode.c'],'fuse_init_inode')
assert '.rdev\t\t= new_encode_dev(fi->inode.i_rdev),'in s['fs/fuse/inode.c']
assert 'finalize_attr(idmap, inode, &outarg, attr_version, stat)'in s['fs/fuse/dir.c']
assert 'file ? &file->f_path : NULL'in s['fs/fuse/dir.c']
oldB=subprocess.check_output(['git','show',old+':fs/fuse/fuse_bpf_backing.c'],cwd=root,text=True)
body='\n'.join(function(B,n)for n in ['fuse_rename_backing_common','fuse_statfs_initialize','fuse_getxattr_backing','fuse_getxattr_finalize','fuse_open_finalize','fuse_create_open_finalize'])
body+=function(oldB,'fuse_rename_backing_common').replace('fuse_rename_backing_common','old_rename')
body+=function(oldB,'fuse_statfs_initialize').replace('fuse_statfs_initialize','old_statfs')
body+=function(s['fs/fuse/file.c'],'fuse_file_put')
body+=function(s['fs/fuse/fuse_i.h'],'finalize_attr')
shim=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint64_t u64;typedef unsigned short umode_t;
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define ATTR_TIMEOUT(o) 1
#define FUSE_STATFS 17
#define FUSE_RELEASE 18
#define FUSE_BPF_OUT_ARGVAR 64
#define GFP_KERNEL 0
#define __GFP_NOFAIL 0
struct mnt_idmap {int id;};static struct mnt_idmap nop_mnt_idmap;
struct fuse_open_out {u64 fh;};struct fuse_entry_out {u64 nodeid;};
struct fuse_attr {unsigned mode;};struct fuse_attr_out {struct fuse_attr attr;};
struct kstat {int unused;};struct fuse_kstatfs {u64 blocks[10];};
struct fuse_statfs_out {struct fuse_kstatfs st;};struct kstatfs {int unused;};
struct fuse_getxattr_out {unsigned size;};
struct fuse_bpf_arg {unsigned size;void *value;};
struct fuse_bpf_args {u64 nodeid;unsigned opcode,flags,out_numargs;struct fuse_bpf_arg in_args[5],out_args[3];int error_in;};
struct inode {struct inode *lower;unsigned i_mode;};
struct dentry {struct inode *inode;struct dentry *parent;int id;};
struct path {struct dentry *dentry;void *mnt;};
struct fuse_inode {struct inode *backing_inode;u64 nodeid;};struct fuse_dentry {struct path backing_path;};
static struct fuse_inode f_inode;static struct fuse_dentry f_dentry;
static int old_path_missing,new_path_missing,cross_mount,trap_kind,rename_error;
static int locks,refs,put_count,renames,unlocks,invalid;
static struct dentry *old_ent,*new_ent;
static void get_fuse_backing_path(struct dentry *d,struct path *p){
 *p=(struct path){.dentry=(d==old_ent?old_path_missing:new_path_missing)?NULL:d,.mnt=(void*)(uintptr_t)(1+(cross_mount && d==new_ent))};
 if(p->dentry)refs++;
}
static void path_put(struct path *p){assert(p->dentry);refs--;put_count++;}
static struct dentry *dget_parent(struct dentry *d){refs++;return d->parent;}
static void dput(struct dentry *d){assert(d);refs--;put_count++;}
static struct inode *d_inode(struct dentry *d){return d->inode;}
static struct fuse_inode *get_fuse_inode(struct inode *i){f_inode.backing_inode=i->lower;return &f_inode;}
static struct fuse_dentry *get_fuse_dentry(struct dentry *d){f_dentry.backing_path.dentry=d;return &f_dentry;}
static u64 get_node_id(struct inode *i){(void)i;return 1;}
static struct dentry *lock_rename(struct dentry *a,struct dentry *b){(void)a;(void)b;if(trap_kind==3)return ERR_PTR(-EXDEV);locks++;return trap_kind==1?old_ent:trap_kind==2?new_ent:NULL;}
static void unlock_rename(struct dentry *a,struct dentry *b){(void)a;(void)b;unlocks++;if(locks!=1){invalid++;return;}locks--;}
struct renamedata {struct mnt_idmap *mnt_idmap;struct dentry *old_parent,*old_dentry,*new_parent,*new_dentry;unsigned flags;};
static int vfs_rename(struct renamedata *r){(void)r;renames++;if(!locks)invalid++;return rename_error;}
static void fsstack_copy_attr_all(struct inode *a,struct inode *b){(void)a;(void)b;}
static ssize_t xattr_result;
static ssize_t vfs_getxattr(struct mnt_idmap *m,struct dentry *d,const char *n,void *v,size_t z){(void)m;(void)d;(void)n;(void)v;(void)z;return xattr_result;}
struct fuse_args {int opcode;void (*end)(struct fuse_args*,int);};
struct fuse_release_args {struct fuse_args args;struct inode *inode;};
union file_args {struct fuse_release_args release_args;};
struct fuse_conn {bool no_open,auto_submounts;};struct fuse_mount {struct fuse_conn *fc;};
struct file {struct inode *f_inode;void *private_data;};
struct fuse_file {struct file *backing_file;u64 fh,nodeid;int count;union file_args *args;struct fuse_mount *fm;};
static int mode_releases,end_calls,freed,sends,backing_puts,file_frees;
static void fput(struct file *f){assert(f);backing_puts++;}
static void fuse_file_free(struct fuse_file *f){assert(f);file_frees++;}
static bool refcount_dec_and_test(int *c){return --*c==0;}
static void fuse_file_io_release(struct fuse_file *f,struct inode *i){assert(f && i);mode_releases++;}
static void fuse_release_end(struct fuse_args *a,int e){assert(a);(void)e;end_calls++;}
static int fuse_simple_request(struct fuse_mount *m,struct fuse_args *a){(void)m;(void)a;sends++;return 0;}
static int fuse_simple_background(struct fuse_mount *m,struct fuse_args *a,int f){(void)m;(void)a;(void)f;sends++;return -1;}
static void kfree(void *p){assert(p);freed++;}
static int bad_attr,bad_type,marked_bad,attr_changes,filled_idmap;
static bool fuse_invalid_attr(struct fuse_attr *a){(void)a;return bad_attr;}
static bool inode_wrong_type(struct inode *i,unsigned m){(void)i;(void)m;return bad_type;}
static void fuse_make_bad(struct inode *i){(void)i;marked_bad++;}
static void fuse_change_attributes(struct inode *i,struct fuse_attr *a,void *x,int t,u64 v){(void)i;(void)a;(void)x;(void)t;(void)v;attr_changes++;}
static void fuse_fillattr(struct mnt_idmap *m,struct inode *i,struct fuse_attr *a,struct kstat *s){(void)i;(void)a;(void)s;filled_idmap=m->id;}
'''
main=r'''
int main(void){
 struct inode lower={0},ino={.lower=&lower};struct dentry parent={.inode=&ino};
 struct dentry old={.inode=&ino,.parent=&parent},new={.inode=&ino,.parent=&parent};old_ent=&old;new_ent=&new;
 int cases=0;
 for(int a=0;a<2;a++)for(int b=0;b<2;b++)for(int c=0;c<2;c++)for(int t=0;t<4;t++)for(int e=0;e<2;e++){
  old_path_missing=a;new_path_missing=b;cross_mount=c;trap_kind=t;rename_error=e?-EIO:0;
  locks=refs=put_count=renames=unlocks=invalid=0;
  int r=fuse_rename_backing_common(&ino,&old,&ino,&new,0);cases++;
  assert(!locks && !refs && !invalid);
  assert(r==(a?-EBADF:b||c?-EXDEV:t==3?-EXDEV:t==1?-EINVAL:t==2?-ENOTEMPTY:rename_error));
 }
 old_path_missing=new_path_missing=cross_mount=rename_error=0;
 locks=refs=invalid=0;trap_kind=1;old_rename(&ino,&old,&ino,&new,0);assert(locks==1); /* Old trap leaks lock. */
 locks=refs=invalid=0;trap_kind=3;old_rename(&ino,&old,&ino,&new,0);assert(invalid); /* Old ERR_PTR ignored. */
 struct fuse_bpf_args fa={0};struct fuse_statfs_out so;struct kstatfs sb;
 fuse_statfs_initialize(&fa,&so,&old,&sb);assert(fa.out_args[0].size==sizeof(so));
 old_statfs(&fa,&so,&old,&sb);assert(fa.out_args[0].size==sizeof(void*) && fa.out_args[0].size!=sizeof(so));
 char data[16];struct fuse_getxattr_out xo={0};
 for(int var=0;var<2;var++)for(int e=0;e<3;e++){
  xattr_result=e==0?-ENODATA:e==1?-ERANGE:8;
  fa=(struct fuse_bpf_args){.flags=var?FUSE_BPF_OUT_ARGVAR:0,.in_args[1]={.value="user.key"},.out_args[0]={.size=var?sizeof(data):sizeof(xo),.value=var?(void*)data:(void*)&xo}};
  unsigned original_size=fa.out_args[0].size;
  int r=fuse_getxattr_backing(&fa,&old,"user.key",var?(void*)data:NULL,var?sizeof(data):0);
  if(xattr_result<0){assert(r==xattr_result && fa.out_args[0].size==original_size);fa.error_in=r;assert(!fuse_getxattr_finalize(&fa,&old,"user.key",data,sizeof(data)));}
  else{assert(!r);assert(PTR_ERR(fuse_getxattr_finalize(&fa,&old,"user.key",data,sizeof(data)))==8);}
  cases++;
 }
 struct fuse_conn fc={0};struct fuse_mount fm={.fc=&fc};union file_args args;
 for(int mode=0;mode<3;mode++)for(int held=0;held<2;held++){
  args=(union file_args){.release_args={.args={.opcode=FUSE_RELEASE},.inode=held?&ino:NULL}};
  struct fuse_file f={.count=1,.args=&args,.fm=&fm};fc.no_open=mode==0;
  mode_releases=end_calls=freed=sends=0;fuse_file_put(&ino,&f,mode==1);
  assert(mode_releases==held && end_calls==1 && freed==1);cases++;
 }
 struct mnt_idmap id={.id=71};struct fuse_attr_out attr={0};struct kstat st;
 for(int bad=0;bad<3;bad++){
  bad_attr=bad==1;bad_type=bad==2;marked_bad=attr_changes=filled_idmap=0;
  int r=finalize_attr(&id,&ino,&attr,1,&st);
  if(bad)assert(r==-EIO && marked_bad==1 && !attr_changes && !filled_idmap);
  else assert(!r && attr_changes==1 && filled_idmap==71);
  cases++;
 }
 struct file lower_file={0};struct fuse_open_out oo={.fh=19};struct fuse_entry_out eo={.nodeid=23};
 for(int create=0;create<2;create++)for(int error=0;error<2;error++)for(int held=0;held<2;held++){
  struct fuse_file ff={.backing_file=&lower_file,.fh=1,.nodeid=2};
  struct file file={.f_inode=&ino,.private_data=held?&ff:NULL};f_inode.nodeid=7;
  fa=(struct fuse_bpf_args){.error_in=error?-EPERM:0,.out_args[0]={.value=create?(void*)&eo:(void*)&oo},.out_args[1]={.value=&oo}};
  backing_puts=file_frees=0;
  if(create)fuse_create_open_finalize(&fa,&ino,&old,&file,0,0);
  else fuse_open_finalize(&fa,&ino,&file,0);
  assert(backing_puts==(!create && error && held));assert(file_frees==backing_puts);
  assert(file.private_data==(!create && error?NULL:held?&ff:NULL));
  assert(ff.fh==(!error && held?19:1));
  if(create)assert(f_inode.nodeid==(error?7:23));
  cases++;
 }
 printf("%d rename/xattr/release/idmap/open cases and statfs controls passed; old lock/error/size failures reproduced\n",cases);
}
'''
program=shim+body+main
with tempfile.TemporaryDirectory(prefix='fuse-native-check-')as td:
 src=Path(td)/'check.c';exe=Path(td)/'check';src.write_text(program)
 flags=['-std=gnu11','-Wall','-Wextra','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-omit-frame-pointer']
 subprocess.run(['cc',*flags,str(src),'-o',str(exe)],check=True)
 result=subprocess.check_output([str(exe)],text=True)
a.output.write_text(json.dumps(dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),working_source_sha256={p:hashlib.sha256(s[p].encode()).hexdigest()for p in paths},native_init_inode_equal=True,native_lts=L,extracted_program_sha256=hashlib.sha256(program.encode()).hexdigest(),compiler_flags=flags,result=result.strip(),scope=__doc__),indent=2)+'\n')
print(result,end='')
