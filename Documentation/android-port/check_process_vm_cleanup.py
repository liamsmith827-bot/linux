#!/usr/bin/env python3
"""Check extracted process_vm cleanup paths using host reference/copy shims."""
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
source = (root/'mm/process_vm_access.c').read_text()
baseline = subprocess.check_output(['git','rev-parse','8e8cbee1ce28'],cwd=root,text=True).strip()
old = subprocess.check_output(['git','show',baseline+':mm/process_vm_access.c'],cwd=root,text=True)

def function(text):
    start = text.index('static ssize_t process_vm_rw_core(')
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

shim = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#define PAGE_SIZE 4096UL
#define PVM_MAX_PP_ARRAY_COUNT 16
#define PVM_MAX_KMALLOC_PAGES 2
#define GFP_KERNEL 0
#define PTRACE_MODE_ATTACH_REALCREDS 1
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095L)
#define PTR_ERR(p) ((long)(p))
#define max(a,b) ((a)>(b)?(a):(b))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
struct page { int unused; };
struct task_struct { int refs; };
struct mm_struct { int refs; };
struct iov_iter { size_t count; };
static struct task_struct task;
static struct mm_struct mm;
static int fail_alloc,missing_task,access_error,hook_error,copy_error;
static unsigned int hooks,copies,allocs,frees,accesses;
static bool copy_partial;
static size_t iov_iter_count(struct iov_iter *i) {return i->count;}
static void *kmalloc(size_t n,int gfp) {(void)gfp;allocs++;return fail_alloc?NULL:malloc(n);}
static void kfree(void *p) {assert(p);frees++;free(p);}
static struct task_struct *find_get_task_by_vpid(pid_t p) {
    (void)p;if(missing_task)return NULL;task.refs++;return &task;
}
static struct mm_struct *mm_access(struct task_struct *t,int mode) {
    assert(t==&task && task.refs==1 && mode==PTRACE_MODE_ATTACH_REALCREDS);accesses++;
    if(access_error)return (struct mm_struct *)(intptr_t)access_error;
    mm.refs++;return &mm;
}
static void mmput(struct mm_struct *m) {assert(m==&mm && mm.refs==1);mm.refs--;}
static void put_task_struct(struct task_struct *t) {assert(t==&task && task.refs==1);task.refs--;}
static void trace_android_rvh_process_vm_rw_core(struct task_struct *t,int write,ssize_t *rc) {
    (void)write;assert(t==&task && mm.refs==1 && accesses==1 && !copies);hooks++;*rc=hook_error;
}
static int process_vm_rw_single_vec(unsigned long base,size_t len,struct iov_iter *i,
    struct page **pages,struct mm_struct *m,struct task_struct *t,int write) {
    (void)base;(void)pages;(void)write;assert(m==&mm && t==&task && mm.refs==1 && hooks==1);copies++;
    size_t n=copy_error?(copy_partial?len/2:0):len;if(n>i->count)n=i->count;
    i->count-=n;return copy_error;
}
'''
tests = r'''
static void setup(void) {
    task.refs=mm.refs=0;hooks=copies=allocs=frees=accesses=0;
    fail_alloc=missing_task=access_error=hook_error=copy_error=0;copy_partial=false;
}
int main(void) {
    unsigned int cases=0;
    for(int large=0;large<2;large++) for(int write=0;write<2;write++)
    for(int mode=0;mode<9;mode++) {
        setup();size_t len=large?PAGE_SIZE*32:32;
        struct iovec v={.iov_base=(void *)PAGE_SIZE,.iov_len=len};
        struct iov_iter iter={.count=len};ssize_t expected=len;
        switch(mode) {
        case 1:missing_task=1;expected=-ESRCH;break;
        case 2:access_error=-EACCES;expected=-EPERM;break;
        case 3:access_error=-ESRCH;expected=-ESRCH;break;
        case 4:hook_error=-EPERM;expected=-EPERM;break;
        case 5:hook_error=-EACCES;expected=-EACCES;break;
        case 6:copy_error=-EFAULT;expected=-EFAULT;break;
        case 7:copy_error=-EFAULT;copy_partial=true;expected=len/2;break;
        case 8:fail_alloc=large;expected=large?-ENOMEM:(ssize_t)len;break;
        }
        ssize_t got=process_vm_rw_core(1,&iter,&v,1,0,write);
        assert(got==expected && !task.refs && !mm.refs);
        assert(allocs==(unsigned int)large && frees==(unsigned int)(large && !fail_alloc));
        assert(hooks==(unsigned int)(!missing_task && !access_error && !fail_alloc));
        if(hook_error)assert(!copies && iter.count==len);
        cases++;
    }
    setup();struct iovec v={.iov_base=(void *)PAGE_SIZE,.iov_len=0};
    struct iov_iter iter={.count=0};assert(!process_vm_rw_core(1,&iter,&v,1,0,0));
    assert(!accesses && !allocs && !hooks);cases++;
    /* Old denial path drops task but leaks the successfully acquired mm. */
    setup();hook_error=-EPERM;v.iov_len=iter.count=32;
    assert(old_process_vm_rw_core(1,&iter,&v,1,0,0)==-EPERM);
    assert(!task.refs && mm.refs==1 && !copies);mmput(&mm);cases++;
    printf("%u allocation, authorization, callback and partial-copy cleanup cases passed\n",cases);
}
'''
body = shim + function(source) + function(old).replace('process_vm_rw_core(', 'old_process_vm_rw_core(',1) + tests
with tempfile.TemporaryDirectory(prefix='ack-process-vm-') as d:
    c, binary = Path(d)/'check.c', Path(d)/'check'
    c.write_text(body)
    subprocess.run(['cc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=undefined',str(c),'-o',str(binary)],check=True)
    r = subprocess.run([str(binary)],text=True,capture_output=True,check=True)
report = {'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
          'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'baseline':baseline,'result':r.stdout.strip(),
          'limits':'Actual process_vm_rw_core with host task/mm reference, permission, allocation and copy shims under UBSan. Does not exercise real ptrace/LSM authorization, page pins, process memory access or kernel concurrency.'}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(report['result'])
