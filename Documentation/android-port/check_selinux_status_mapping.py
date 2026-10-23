#!/usr/bin/env python3
"""Check extracted SELinux status mmap bounds and permissions with a PFN-map shim.

No real page tables, cache-mode tracking, policy authorization or faults execute.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;ROOT=D.parents[1];ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
p='security/selinux/selinuxfs.c';s=(ROOT/p).read_text();old=subprocess.check_output(['git','show',ACK+':'+p],cwd=ROOT,text=True)
def extract(s):
 start=s.index('static int sel_mmap_handle_status(');end=s.index('\n}',start)+2;return s[start:end]
prefix=r'''
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#define PAGE_SIZE 4096UL
#define __PAGE_SIZE reported_size
#define VM_WRITE 1UL
#define VM_MAYWRITE 2UL
#define VM_SHARED 4UL
#define VM_EXEC 8UL
#define VM_READ 16UL
#define BUG_ON(v) assert(!(v))
struct page { unsigned long pfn; };
struct file { void *private_data; };
struct vm_area_struct { unsigned long vm_start,vm_end,vm_pgoff,vm_flags,vm_page_prot; };
static unsigned long reported_size,mapped_size,mapped_pfn,mapped_addr,mapped_prot;
static unsigned calls,cases,failures;static int map_result;
static unsigned long page_to_pfn(struct page *p) {return p->pfn;}
static void vm_flags_clear(struct vm_area_struct *v,unsigned long flags) {v->vm_flags&=~flags;}
static int remap_pfn_range(struct vm_area_struct *v,unsigned long a,unsigned long p,unsigned long n,unsigned long prot) {
 (void)v;calls++;mapped_addr=a;mapped_pfn=p;mapped_size=n;mapped_prot=prot;return map_result;
}
'''
main=r'''
int main(void) {
 unsigned long reported[]={4096,8192,16384},sizes[]={0,4095,4096,8192,16384,32768},offsets[]={0,1,2,ULONG_MAX};
 int errors[]={0,-ENOMEM,-EINVAL};struct page page={0x1234};struct file file={&page};
 for(unsigned r=0;r<3;r++)for(unsigned n=0;n<6;n++)for(unsigned o=0;o<4;o++)
 for(unsigned flags=0;flags<32;flags++)for(unsigned e=0;e<3;e++) {
  reported_size=reported[r];map_result=errors[e];calls=0;
  mapped_size=mapped_pfn=mapped_addr=mapped_prot=0;
  struct vm_area_struct v={.vm_start=0x10000,.vm_end=0x10000+sizes[n],.vm_pgoff=offsets[o],.vm_flags=flags,.vm_page_prot=0x5678};
  int expected=(offsets[o]||sizes[n]!=reported_size)?-EIO:(flags&VM_WRITE)?-EPERM:map_result;
  int valid=!offsets[o]&&sizes[n]==reported_size&&!(flags&VM_WRITE);
  int got=sel_mmap_handle_status(&file,&v),bad=got!=expected||calls!=(unsigned)valid;
  if(valid)bad|=mapped_addr!=v.vm_start||mapped_pfn!=page.pfn||mapped_size!=PAGE_SIZE||mapped_prot!=v.vm_page_prot||v.vm_flags!=(flags&~VM_MAYWRITE);
  else bad|=v.vm_flags!=flags;
  cases++;failures+=!!bad;
 }
 printf("%u cases, %u failures\n",cases,failures);return failures?1:0;
}
'''
results={}
with tempfile.TemporaryDirectory(prefix='selinux-status-check-') as tmp:
 tmp=Path(tmp)
 for name,source in [('current',s),('original_ACK',old)]:
  body=extract(source);p=tmp/(name+'.c');exe=tmp/name;p.write_text(prefix+body+main)
  c=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(p),'-o',str(exe)],capture_output=True,text=True);assert c.returncode==0,c.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True);assert (r.returncode==0)==(name=='current'),(name,r.stdout,r.stderr)
  results[name]=dict(returncode=r.returncode,stdout=r.stdout.strip(),function_sha256=hashlib.sha256(body.encode()).hexdigest())
report=dict(scope=__doc__,results=results,negative_control_source=ACK,source_sha256=hashlib.sha256(s.encode()).hexdigest(),coverage='4/8/16 KiB reported pages, zero/mismatched/valid lengths, four offsets, write/maywrite/shared/read/exec flags and remap success/errors. Exactly one owned native page is passed to the mapper on every accepted call; existing controls and errors remain.',limitations='Host shim observes mapping arguments and flag changes only. It does not prove live fault/SIGBUS behavior, status-policy access or leak exploitability.',remote_sources_used=[])
(D/'evidence/selinux-status-mapping-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(results,indent=2))
