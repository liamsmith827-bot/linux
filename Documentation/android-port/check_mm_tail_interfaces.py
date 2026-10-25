#!/usr/bin/env python3
"""Execute task-stat page conversion and FUSE context-write rejection with stubs."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
R=Path(__file__).resolve().parents[2]
stat=function((R/'fs/proc/task_mmu.c').read_text(),'task_statm')
old=function(subprocess.check_output(['git','show','b43dbce8f063:fs/proc/task_mmu.c'],cwd=R,text=True),'task_statm').replace('task_statm(', 'old_statm(')
convert=function((R/'include/linux/page_size_compat_defs.h').read_text(),'__page_size_count')
access=function((R/'kernel/bpf/bpf_fuse.c').read_text(),'fuse_prog_is_valid_access')
old_access=function(subprocess.check_output(['git','show','5c7556339e29^:kernel/bpf/bpf_fuse.c'],cwd=R,text=True),'fuse_prog_is_valid_access').replace('fuse_prog_is_valid_access(', 'old_access(')
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
'''+f'#include "{R}/include/uapi/linux/android_fuse.h"\n'+r'''
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE-1))
#define PAGE_ALIGN(x) (((x)+PAGE_SIZE-1)&PAGE_MASK)
static unsigned shift;
#define __PAGE_SHIFT shift
#define __PAGE_SIZE (1UL<<shift)
#define __PAGE_MASK (~(__PAGE_SIZE-1))
#define __PAGE_ALIGN(x) (((x)+__PAGE_SIZE-1)&__PAGE_MASK)
#define DIV_ROUND_UP(x,d) (((x)+(d)-1)/(d))
enum {MM_FILEPAGES,MM_SHMEMPAGES,MM_ANONPAGES};
struct mm_struct {unsigned long counter[3],end_code,start_code,data_vm,stack_vm,total_vm;};
static unsigned long get_mm_counter_sum(struct mm_struct *m,int i){return m->counter[i];}
enum bpf_access_type {BPF_READ,BPF_WRITE};
struct bpf_prog {int unused;};
struct bpf_insn_access_aux {int reg_type,ctx_field_size;};
#define PTR_TO_BUF 3
#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t *)0)->m))
'''
main=r'''
int main(void){
 unsigned cases=0,writes=0,reads=0,old_bad=0;
 for(shift=12;shift<=14;shift++)
 for(unsigned file=0;file<32;file++)for(unsigned shmem=0;shmem<32;shmem++)
 for(unsigned anon=0;anon<32;anon++){
  struct mm_struct m={.counter={file,shmem,anon},.data_vm=anon,.stack_vm=3,
      .total_vm=file+shmem+anon+3,.start_code=4096,.end_code=20481};
  unsigned long s,t,d,r,os,ot,od,orr,n=1UL<<(shift-12);
  unsigned long total=task_statm(&m,&s,&t,&d,&r);
  old_statm(&m,&os,&ot,&od,&orr);
  assert(s==(file+shmem+n-1)/n && d==(anon+3+n-1)/n);
  assert(total==(m.total_vm+n-1)/n);
  unsigned long exact_total=(file+shmem+anon+n-1)/n;
  assert(r>=exact_total && r<=exact_total+1);
  assert(r==s+(anon+n-1)/n);
  if(shift==12)assert(r==file+shmem+anon);
  if(orr<exact_total)old_bad++;
  cases++;
 }
 assert(old_bad);
 for(int off=-8;off<=(int)sizeof(struct fuse_bpf_args)+8;off++)
 for(int size=1;size<=8;size*=2){
  struct bpf_insn_access_aux info={0};
  assert(!fuse_prog_is_valid_access(off,size,BPF_WRITE,NULL,&info));writes++;
 }
 for(unsigned i=0;i<FUSE_MAX_OUT_ARGS;i++){
  struct bpf_insn_access_aux info={0};
  unsigned off=offsetof(struct fuse_bpf_args,out_args)+i*sizeof(struct fuse_bpf_arg)+offsetof(struct fuse_bpf_arg,value);
  assert(old_access(off,8,BPF_WRITE,NULL,&info));
  assert(!fuse_prog_is_valid_access(off,8,BPF_WRITE,NULL,&info));
  assert(fuse_prog_is_valid_access(off,8,BPF_READ,NULL,&info));
  assert(info.reg_type==PTR_TO_BUF);reads++;
 }
 printf("{\"statm_cases\":%u,\"old_underreported_cases\":%u,\"write_rejections\":%u,\"output_pointer_reads\":%u}\n",cases,old_bad,writes,reads);
}
'''
with tempfile.TemporaryDirectory(prefix='mm-tail-') as tmp:
 p=Path(tmp);(p/'check.c').write_text(prefix+convert+stat+old+access+old_access+main)
 subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined',str(p/'check.c'),'-o',str(p/'check')],check=True)
 result=json.loads(subprocess.check_output([str(p/'check')],text=True))
report=dict(results=result,sha256={k:hashlib.sha256(v.encode()).hexdigest() for k,v in [('task_statm',stat),('page_count',convert),('fuse_access',access)]},scope='Actual extracted code, synthetic MM counters and native FUSE UAPI layout under host ASan/UBSan. Checks statm units and context pointer write rejection, not proc concurrency or complete BPF verifier/JIT behavior.')
(R/'Documentation/android-port/evidence/mm-tail-interface-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
