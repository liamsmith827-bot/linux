#!/usr/bin/env python3
"""Run extracted FUSE-BPF bounds/dispatch code under host ASan/UBSan.

Models allocation, verifier metadata and program execution, not the kernel BPF
verifier/JIT, live FUSE, VFS permissions, concurrency, or a runtime kernel test.
"""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[2]
def extract(s,name):
 pos=s.index(name+'(');start=s.rfind('\n',0,pos)+1;br=s.index('{',pos);depth=1;i=br+1
 while depth:
  depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[start:i]+'\n'
b=(root/'fs/fuse/fuse_bpf_backing.c').read_text();v=(root/'kernel/bpf/bpf_fuse.c').read_text();h=(root/'fs/fuse/fuse_i.h').read_text()
u=(root/'include/uapi/linux/android_fuse.h').read_text()
old=subprocess.check_output(['git','show','6f902fe36033:kernel/bpf/bpf_fuse.c'],cwd=root,text=True)
functions=[extract(v,'fuse_prog_is_valid_access'),extract(old,'fuse_prog_is_valid_access').replace('fuse_prog_is_valid_access','old_access')]
functions += [extract(b,n)for n in ['fuse_bpf_run','fuse_bpf_prepare_inputs','fuse_bpf_cleanup_args']]
macro=h[h.index('#define fuse_bpf_backing('):h.index('\n})',h.index('#define fuse_bpf_backing('))+3]
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
typedef uint32_t u32; typedef uint64_t u64;
#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t*)0)->m))
#define GFP_KERNEL 0
#define FUSE_BPF_MAX_BUFFER_SIZE 65536U
#define FUSE_READDIR 28
#define ERR_PTR(v) ((void *)(intptr_t)(v))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095L)
#define PTR_ERR(p) ((long)(intptr_t)(p))
static int allocation_call,fail_call,live_allocs,free_pages,migrating,runs;
static void *alloc(size_t n,bool clear) {
 if (++allocation_call==fail_call)return NULL;
 void *p=clear?calloc(1,n):malloc(n);assert(p);live_allocs++;return p;
}
static void *kvcalloc(size_t n,size_t size,int flags){(void)flags;return alloc(n*size,true);}
static void *kvzalloc(size_t n,int flags){(void)flags;return alloc(n,true);}
static void kvfree(void *p){if(p){live_allocs--;free(p);}}
static void free_page(unsigned long p){assert(p);free_pages++;kvfree((void *)p);}
static void migrate_disable(void){assert(!migrating);migrating=1;}
static void migrate_enable(void){assert(migrating);migrating=0;}
enum bpf_access_type {BPF_READ,BPF_WRITE};
#define PTR_TO_BUF 123
#define MEM_RDONLY 256
struct bpf_insn_access_aux {int reg_type,ctx_field_size;};
struct bpf_prog_aux {u32 max_rdonly_access,max_rdwr_access;};
struct bpf_prog {struct bpf_prog_aux *aux;int mode;};
static int bpf_prog_run(struct bpf_prog *,struct fuse_bpf_args *);
'''
# Include UAPI directly; system include resolution is not involved in extraction.
shim=shim.replace('static int bpf_prog_run(struct bpf_prog *,struct fuse_bpf_args *);','struct fuse_bpf_args;\nstatic int bpf_prog_run(struct bpf_prog *,struct fuse_bpf_args *);')
program=shim+'\n'+u+'\n'+''.join(functions)
program+=r'''
static int bpf_prog_run(struct bpf_prog *p,struct fuse_bpf_args *a) {
 runs++;assert(migrating);
 if(p->mode==1){
  /* Every pointer is valid even for unused arguments, with zero padding. */
  for(int i=0;i<FUSE_MAX_IN_ARGS;i++){assert(a->in_args[i].value);assert(!a->in_args[i].end_offset);}
  for(int i=0;i<FUSE_MAX_OUT_ARGS;i++){assert(a->out_args[i].value);assert(!a->out_args[i].end_offset);}
  unsigned char *o=a->out_args[0].value;
  assert(o[8]==0 && o[255]==0 && o[511]==0);
  memset(o,0x5a,512); /* Verified maximum, outside the real eight-byte object. */
  assert(((const unsigned char *)a->in_args[0].value)[0]==0x5a); /* Alias. */
  memset(a->out_args[2].value,0x88,512); /* Inactive output cannot affect caller. */
  return 7;
 }
 if(p->mode==2)return -EPERM;
 if(p->mode==3)return 0; /* Native daemon fallback. */
 if(a->opcode & FUSE_PREFILTER){
  assert(a->in_args[0].value==a->out_args[0].value);
  ((char*)a->out_args[0].value)[0]='X';
  return FUSE_BPF_BACKING|FUSE_BPF_POST_FILTER;
 }
 return 0;
}
struct fuse_err_ret {void *result;bool ret;};
struct inode {int ignored;}; struct fuse_mount {int ignored;};
struct fuse_inode {void *backing_inode;struct bpf_prog *bpf;};
static struct fuse_inode fi;static struct fuse_mount fm;
static struct fuse_inode *get_fuse_inode(struct inode *n){(void)n;return &fi;}
static struct fuse_mount *get_fuse_mount(struct inode *n){(void)n;return &fm;}
static bool fuse_lock_inode(struct inode *n){(void)n;return false;}
static void fuse_unlock_inode(struct inode *n,bool l){(void)n;(void)l;}
static ssize_t fuse_bpf_simple_request(struct fuse_mount *m,struct fuse_bpf_args *a){(void)m;(void)a;assert(0);return 0;}
struct sample_io {int result;};
static const char original_name[]="original";
static int finalized,backing_called,backing_error;
static int sample_init(struct fuse_bpf_args *a,struct sample_io *io,struct inode *n) {
 (void)n;void *page=alloc(4096,false);if(!page)return -ENOMEM;
 *a=(struct fuse_bpf_args){.opcode=FUSE_READDIR,.in_numargs=1,.out_numargs=2,
 .in_args[0]={.size=sizeof(original_name),.value=original_name},
 .out_args[0]={.size=sizeof(io->result),.value=&io->result},
 .out_args[1]={.size=4096,.value=page}};
 return 0;
}
static int sample_backing(struct fuse_bpf_args *a,struct inode *n) {
 (void)n;backing_called++;
 assert(((char*)a->in_args[0].value)[0]==(fi.bpf?'X':'o'));
 assert(original_name[0]=='o');
 unsigned char *data=a->out_args[1].value;
 for(int i=0;i<4096;i++)assert(data[i]==0);
 *(int*)a->out_args[0].value=33;a->out_args[1].size=17;
 return backing_error;
}
static void *sample_final(struct fuse_bpf_args *a,struct inode *n){(void)n;finalized++;assert(*(int*)a->out_args[0].value==33);return ERR_PTR(33);}
'''+macro+r'''
static void run_dispatch(struct bpf_prog *p,int fail,int error) {
 struct inode node;struct fuse_err_ret r;
 assert(!live_allocs);allocation_call=0;fail_call=fail;free_pages=0;
 finalized=0;backing_called=0;backing_error=error;
 fi=(struct fuse_inode){.backing_inode=&node,.bpf=p};
 r=fuse_bpf_backing(&node,struct sample_io,sample_init,sample_backing,sample_final,&node);
 assert(!live_allocs && !migrating && original_name[0]=='o');
 if(fail==1){assert(r.ret && PTR_ERR(r.result)==-ENOMEM && !finalized && !free_pages);return;}
 assert(free_pages==1);
 if(fail==4){assert(r.ret && PTR_ERR(r.result)==-ENOMEM && finalized==1 && backing_called==1);return;}
 if(fail || (p && p->mode==2)){assert(r.ret && IS_ERR(r.result) && !finalized && !backing_called);return;}
 if(p && p->mode==3){assert(!r.ret && !finalized && !backing_called);return;}
 assert(r.ret && finalized==1 && backing_called==1);
 assert(PTR_ERR(r.result)==(error?error:33));
}
int main(void) {
 struct bpf_prog_aux aux={.max_rdonly_access=512,.max_rdwr_access=512};
 struct bpf_prog p={.aux=&aux,.mode=1};struct bpf_insn_access_aux info;
 int count=0;
 for(int off=-8;off<=(int)sizeof(struct fuse_bpf_args)+8;off++)for(int size=1;size<=8;size*=2)for(int t=0;t<2;t++){
  info=(struct bpf_insn_access_aux){0};
  bool ok=fuse_prog_is_valid_access(off,size,t,&p,&info);count++;
  if(ok){assert(t==BPF_READ && off>=0 && off+size<=sizeof(struct fuse_bpf_args) && !(off%size));}
 }
 for(int i=0;i<FUSE_MAX_IN_ARGS;i++) {
  int pos=offsetof(struct fuse_bpf_args,in_args[i].value);
  info=(struct bpf_insn_access_aux){0};
  assert(fuse_prog_is_valid_access(pos,8,BPF_READ,&p,&info));assert(info.reg_type==(PTR_TO_BUF|MEM_RDONLY));
  assert(!fuse_prog_is_valid_access(pos,4,BPF_READ,&p,&info));
  assert(!fuse_prog_is_valid_access(pos+4,4,BPF_READ,&p,&info));
 }
 info=(struct bpf_insn_access_aux){0};
 assert(old_access(sizeof(struct fuse_bpf_args),8,BPF_READ,&p,&info));
 assert(!fuse_prog_is_valid_access(sizeof(struct fuse_bpf_args),8,BPF_READ,&p,&info));
 assert(old_access(offsetof(struct fuse_bpf_args,in_args[0].value)+4,4,BPF_READ,&p,&info));
 struct {unsigned char left[16],data[8],right[16];} guarded;
 memset(&guarded,0xcc,sizeof(guarded));
 struct fuse_bpf_args a={.in_numargs=1,.out_numargs=1,
 .in_args[0]={.size=8,.value=guarded.data},.out_args[0]={.size=8,.value=guarded.data}};
 assert(fuse_bpf_run(&p,&a)==7 && !live_allocs);
 for(int i=0;i<16;i++)assert(guarded.left[i]==0xcc && guarded.right[i]==0xcc);
 for(int i=0;i<8;i++)assert(guarded.data[i]==0x5a);
 aux.max_rdwr_access=65537;int before=runs;assert(fuse_bpf_run(&p,&a)==-E2BIG && runs==before);
 aux.max_rdwr_access=512;a.in_numargs=6;assert(fuse_bpf_run(&p,&a)==-E2BIG);a.in_numargs=1;
 fail_call=allocation_call+1;assert(fuse_bpf_run(&p,&a)==-ENOMEM && !live_allocs);fail_call=0;
 p.mode=0;run_dispatch(&p,0,0);run_dispatch(&p,0,-EIO);
 run_dispatch(NULL,0,0); /* No-BPF path still clears output and frees readdir page. */
 for(int i=1;i<=4;i++)run_dispatch(&p,i,0);
 p.mode=2;run_dispatch(&p,0,0);p.mode=3;run_dispatch(&p,0,0);
 printf("%d context cases, pointer/buffer/alias/dispatch/error/fallback checks passed; old context failures reproduced\n",count);
}
'''
with tempfile.TemporaryDirectory(prefix='fuse-bpf-bounds-')as td:
 src=Path(td)/'check.c';exe=Path(td)/'check';src.write_text(program)
 flags=['-std=gnu11','-Wall','-Wextra','-Wno-sign-compare','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-omit-frame-pointer']
 subprocess.run(['cc',*flags,str(src),'-o',str(exe)],check=True)
 result=subprocess.check_output([str(exe)],text=True)
a.output.write_text(json.dumps(dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),working_source_sha256={str(p):hashlib.sha256((root/p).read_bytes()).hexdigest()for p in ['fs/fuse/fuse_bpf_backing.c','fs/fuse/fuse_i.h','kernel/bpf/bpf_fuse.c']},extracted_program_sha256=hashlib.sha256(program.encode()).hexdigest(),compiler_flags=flags,result=result.strip(),scope=__doc__),indent=2)+'\n')
print(result,end='')
