#!/usr/bin/env python3
"""Host checks of actual task vendor layout/init helpers and regression controls.

This does not execute kernel slab allocation, fork, FPU switching or boot.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
def function(text,marker):
 start=text.index(marker);op=text.index('{',start);end=op+1;depth=1
 while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[start:end]
sources={p:(ROOT/p).read_text() for p in ['kernel/fork.c','include/linux/sched/task.h','init/init_task.c']}
setup=function(sources['kernel/fork.c'],'static void __init android_task_vendor_data_setup(')
helper=function(sources['include/linux/sched/task.h'],'static inline void *android_task_vendor_data(')
clear=function(sources['include/linux/sched/task.h'],'static inline void android_init_dynamic_vendor_data(')
decl=sources['init/init_task.c'];start=decl.index('u64 vendor_data_pad[');decl=decl[start:decl.index(';',start)+1]
# Ordering must exclude vendor bytes from the native usercopy whitelist and
# initialize storage before passing a new task to vendor callbacks.
fork_init=function(sources['kernel/fork.c'],'void __init fork_init(')
assert fork_init.index('task_struct_whitelist(')<fork_init.index('android_task_vendor_data_setup(')<fork_init.index('kmem_cache_create_usercopy(')
assert sources['kernel/fork.c'].index('android_init_dynamic_vendor_data(tsk);')<sources['kernel/fork.c'].index('trace_android_vh_dup_task_struct(tsk, orig);')
prefix=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#define __init
#define ALIGN(v,a) (((v)+(a)-1)&~((a)-1))
#define DIV_ROUND_UP(v,a) (((v)+(a)-1)/(a))
#define pr_warn(...) ((void)0)
typedef uint64_t u64;
struct task_struct { unsigned char bytes[256]; };
static struct task_struct init_task;
static unsigned int android_task_vendor_size,android_task_vendor_offset;
static int arch_task_struct_size;
static unsigned char storage[32768];
static unsigned cases,failures,checks;
static int bad;
static void check(int ok) {checks++;if(!ok)bad=1;}
static void *write_ptr;static size_t write_len;
static void *observe_memset(void *ptr,int v,size_t n) {
 write_ptr=ptr;write_len=n;
 uintptr_t s=(uintptr_t)storage,p=(uintptr_t)ptr;
 if(p>=s && p<=s+sizeof(storage) && n<=s+sizeof(storage)-p)
  return memset(ptr,v,n);
 return ptr;
}
#define memset observe_memset
'''
main=r'''
#undef memset
static void run(unsigned native,unsigned requested) {
 bad=0;cases++;arch_task_struct_size=native;
 android_task_vendor_size=requested;android_task_vendor_offset=0;
 android_task_vendor_data_setup();
 unsigned expected_offset=requested?ALIGN(native,8):native;
 check(android_task_vendor_size==requested);
 check(android_task_vendor_offset==expected_offset);
 check((unsigned)arch_task_struct_size==expected_offset+requested);
 memset(storage,0xa7,sizeof(storage));
 struct task_struct *task=(void *)storage;
 check((unsigned char *)android_task_vendor_data(task)==storage+expected_offset);
 write_ptr=NULL;write_len=0;android_init_dynamic_vendor_data(task);
 check(write_len==requested);
 if(requested)check(write_ptr==storage+expected_offset);
 /* No native task/FPU byte or allocation-end canary may change. */
 for(unsigned i=0;i<sizeof(storage);i++)
  check(storage[i]==((i>=expected_offset && i<expected_offset+requested)?0:0xa7));
 check(android_task_vendor_data(&init_task)==(void *)vendor_data_pad);
 write_ptr=NULL;write_len=0;android_init_dynamic_vendor_data(&init_task);
 check(write_len==requested);
 check(write_len<=sizeof(vendor_data_pad));
 if(requested)check(write_ptr==(void *)vendor_data_pad);
 failures+=bad;
}
int main(void) {
 unsigned extra[]={0,1,7,8,64,512,1024,4096,12288};
 for(unsigned j=0;j<sizeof(extra)/sizeof(extra[0]);j++)
  for(unsigned size=0;size<=CONFIG_GKI_TASK_STRUCT_VENDOR_SIZE_MAX;size++)
   run(sizeof(struct task_struct)+extra[j],size);
 unsigned near[]={INT_MAX,INT_MAX-1,INT_MAX-7,INT_MAX-8,INT_MAX-511};
 for(unsigned j=0;j<sizeof(near)/sizeof(near[0]);j++)
  for(unsigned size=0;size<=CONFIG_GKI_TASK_STRUCT_VENDOR_SIZE_MAX;size++) {
   bad=0;cases++;unsigned native=near[j];
   arch_task_struct_size=native;android_task_vendor_size=size;
   android_task_vendor_data_setup();
   uint64_t aligned=((uint64_t)native+7)&~UINT64_C(7);
   if(size && aligned+size>INT_MAX) {
    check(android_task_vendor_size==0);
    check((unsigned)arch_task_struct_size==native);
    check(android_task_vendor_offset==native);
   } else {
    check(android_task_vendor_size==size);
    check((unsigned)arch_task_struct_size==(size?aligned+size:native));
    check(android_task_vendor_offset==(size?aligned:native));
   }
   failures+=bad;
  }
 printf("%u cases, %u failures, %u assertions\n",cases,failures,checks);
 return failures?1:0;
}
'''
variants={'current':(setup,helper,clear),
 'old_pointer_control':(setup,helper.replace('return (void *)p + android_task_vendor_offset;','return p + 1;'),clear),
 'old_clear_length_control':(setup,helper,clear.replace('if (android_task_vendor_size)','if (arch_task_struct_size > sizeof(struct task_struct))').replace('android_task_vendor_size);','arch_task_struct_size - sizeof(struct task_struct));')),
 'overwritten_native_layout_control':(setup.replace('size_t offset = ALIGN((size_t)arch_task_struct_size, sizeof(u64));','size_t offset = sizeof(struct task_struct);'),helper,clear)}
results={}
with tempfile.TemporaryDirectory(prefix='task-vendor-check-') as tmp:
 tmp=Path(tmp)
 for maximum in [512,513]:
  for name,parts in variants.items():
   body='\n'.join(parts);source=prefix+'\n'+decl+'\n'+body+'\n'+main
   p=tmp/(name+str(maximum)+'.c');exe=p.with_suffix('');p.write_text(source)
   c=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-sign-compare',f'-DCONFIG_GKI_TASK_STRUCT_VENDOR_SIZE_MAX={maximum}',str(p),'-o',str(exe)],capture_output=True,text=True)
   assert c.returncode==0,c.stderr
   r=subprocess.run([str(exe)],capture_output=True,text=True)
   assert (r.returncode==0)==(name=='current'),(name,r.stdout,r.stderr)
   results[name+'_'+str(maximum)]=dict(returncode=r.returncode,stdout=r.stdout.strip(),body_sha256=hashlib.sha256(body.encode()).hexdigest())
report=dict(scope=__doc__,results=results,source_sha256={p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},native_sizes='sizeof(task_struct) plus 0,1,7,8,64,512,1024,4096,12288 and five values near INT_MAX',vendor_sizes='Every byte count from zero through each configured maximum 512 and 513',checks='Actual extracted layout/pointer/zeroing helpers; native-region/end canaries, initial-task pad size, zero-size no-op, alignment, overflow rejection, and usercopy/callback source ordering.',limitations='The fake task and memory instrumentation do not execute native FPU or slab code. Initial-task writes are observed without executing potentially out-of-bounds negative controls. No kernel boot or live fork test.',remote_sources_used=[])
(D/'evidence/task-vendor-storage-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(results,indent=2))
