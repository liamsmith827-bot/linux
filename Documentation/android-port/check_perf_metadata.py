#!/usr/bin/env python3
"""Check extracted perf metadata address/bounds/accounting code on the host.

No perf syscalls, VM mappings, PMU access or running-kernel tests are performed.
"""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
OLD = '600ffdb508823a56f22e533a87a1bc77b1b7e541'
PRE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
typedef int64_t __s64;
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096UL
#define __PAGE_SIZE reported_size
#define EINVAL 22
#define VM_FAULT_SIGBUS 2
typedef unsigned int vm_fault_t;
static unsigned long reported_size;
struct page;
struct user_struct { long locked_vm; } user;
struct mm_struct { long pinned_vm; } mm;
struct vm_area_struct { struct mm_struct *vm_mm; } vma;
struct vm_fault { unsigned long pgoff; } fault;
struct perf_event;
'''
HELPERS = r'''
struct perf_buffer {
 struct perf_event_mmap_page *user_page;
 unsigned long nr_pages;
 void *data_pages[1024];
 struct user_struct *mmap_user;
 long mmap_locked;
};
static unsigned long data_page_nr(struct perf_buffer *rb) { return rb->nr_pages; }
static unsigned long perf_data_size(struct perf_buffer *rb) { return rb->nr_pages*PAGE_SIZE; }
static struct page *virt_to_page(void *p) { return (struct page *)p; }
static struct page *vmalloc_to_page(void *p) { return (struct page *)p; }
static void atomic_long_sub(long n,long *p) { *p-=n; }
static void atomic64_sub(long n,long *p) { *p-=n; }
static int is_power_of_2(unsigned long n) { return n && !(n&(n-1)); }
'''
MAIN = r'''
int main(void) {
 struct perf_buffer rb={0};
 /* Large backing keeps even old structure-scaled arithmetic within reserved
    host storage; logical metadata ownership is only reported_size bytes. */
 void *storage=calloc(1, 64UL*1024*1024);
 void *data=calloc(1024,PAGE_SIZE);
 unsigned long sizes[]={4096,8192,16384}, counts[]={0,1,2,4,8,16,128,1024};
 unsigned long checks=0,bad_address=0,bad_write=0,bad_account=0,bad_aux=0,bad_size=0;
 if (!storage || !data) return 2;
 rb.user_page=storage; rb.mmap_user=&user; vma.vm_mm=&mm;
 for (unsigned i=0;i<1024;i++) rb.data_pages[i]=(char *)data+i*PAGE_SIZE;
 for (unsigned s=0;s<3;s++) {
  reported_size=sizes[s]; unsigned long meta=reported_size/PAGE_SIZE;
  for (unsigned c=0;c<8;c++) {
   rb.nr_pages=counts[c];
   for (unsigned long off=0;off<rb.nr_pages+meta+2;off++) {
    uintptr_t expected=off>=rb.nr_pages+meta ? 0 : off<meta ? (uintptr_t)storage+off*PAGE_SIZE : (uintptr_t)rb.data_pages[off-meta];
    checks++; bad_address+=(uintptr_t)map_regular(&rb,off)!=expected;
    expected=off>=rb.nr_pages+meta ? 0 : (uintptr_t)storage+off*PAGE_SIZE;
    checks++; bad_address+=(uintptr_t)map_vmalloc(&rb,off)!=expected;
    fault.pgoff=off; checks++; bad_write+=perf_mmap_pfn_mkwrite(&fault)!=(off<meta ? 0 : VM_FAULT_SIGBUS);
   }
   for (unsigned long extra=0;extra<=rb.nr_pages+meta;extra++) {
    rb.mmap_locked=extra; user.locked_vm=rb.nr_pages+meta-extra; mm.pinned_vm=extra;
    perf_mmap_unaccount(&vma,&rb); checks++; bad_account+=user.locked_vm!=0 || mm.pinned_vm!=0;
   }
   unsigned long end=(rb.nr_pages+meta)*PAGE_SIZE;
   for (long delta=-((long)meta);delta<=1;delta++) {
    unsigned long off=end+delta*PAGE_SIZE;
    checks++; bad_aux+=aux_prefix(&rb,off)!=(off<end ? -EINVAL : 0);
   }
  }
  for (unsigned long total=0;total<128;total++) {
   long expected=total<meta ? -EINVAL : (long)(total-meta);
   if (expected>=0 && expected!=0 && !is_power_of_2(expected)) expected=-EINVAL;
   checks++; bad_size+=size_prefix(&vma,NULL,total)!=expected;
  }
 }
 printf("{\"cases\":%lu,\"bad_addresses\":%lu,\"bad_write_permissions\":%lu,\"unbalanced_unaccounts\":%lu,\"bad_aux_bounds\":%lu,\"bad_sizes\":%lu,\"metadata_struct_size\":%zu}\n",checks,bad_address,bad_write,bad_account,bad_aux,bad_size,sizeof(struct perf_event_mmap_page));
 free(storage); free(data); return 0;
}
'''

def extract(ref):
    read = lambda p: subprocess.check_output(['git', 'show', ref + ':' + p], cwd=ROOT, text=True)
    ring = read('kernel/events/ring_buffer.c')
    core = read('kernel/events/core.c')
    uapi = read('include/uapi/linux/perf_event.h')
    start = uapi.index('struct perf_event_mmap_page {')
    metadata = uapi[start:uapi.index('\n};', start)+3]
    normal = function(ring, '__perf_mmap_to_page')
    start = ring.index(normal)+len(normal)
    vmalloc = function(ring[start:], '__perf_mmap_to_page')
    write = function(core, 'perf_mmap_pfn_mkwrite')
    unaccount = function(core, 'perf_mmap_unaccount')
    size = function(core, 'perf_mmap_rb')
    size = size[:size.index('\tWARN_ON_ONCE')]+ '\treturn nr_pages;\n}\n'
    aux = function(core, 'perf_mmap_aux')
    match = re.search(r'\tif \(aux_offset < .*?\n\t\treturn -EINVAL;', aux)
    assert match
    aux = 'static int aux_prefix(struct perf_buffer *rb, unsigned long aux_offset) {\n'+match.group()+'\n return 0;\n}\n'
    code = PRE+metadata+HELPERS+'static struct page *\n'+normal.replace('__perf_mmap_to_page','map_regular')+'static struct page *\n'+vmalloc.replace('__perf_mmap_to_page','map_vmalloc')+write+unaccount+size.replace('perf_mmap_rb','size_prefix')+aux+MAIN
    hashes = {n:hashlib.sha256(v.encode()).hexdigest() for n,v in dict(regular_map=normal,vmalloc_map=vmalloc,write=write,unaccount=unaccount,size_prefix=size,aux_prefix=aux,metadata_type=metadata).items()}
    return code,hashes

head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
results={}
with tempfile.TemporaryDirectory(prefix='perf-metadata-') as tmp:
    tmp=Path(tmp)
    for name,ref in [('port',head),('old_control',OLD)]:
        code,hashes=extract(ref);src=tmp/(name+'.c');exe=tmp/name;src.write_text(code)
        subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-unused-parameter','-Wno-sign-compare',str(src),'-o',str(exe)],check=True)
        results[name]=dict(json.loads(subprocess.check_output([str(exe)],text=True)),ref=ref,extracted_sha256=hashes)
fields=['bad_addresses','bad_write_permissions','unbalanced_unaccounts','bad_aux_bounds','bad_sizes']
assert all(results['port'][f]==0 for f in fields),results
assert all(results['old_control'][f]>0 for f in fields[:-1]),results
record=dict(source_head=head,results=results,scope='Actual extracted mapping functions, write-fault function, unaccount function and initial size/AUX-bound validation blocks. Host memory and atomics are modeled. Native 4 KiB and emulated 8/16 KiB, regular/vmalloc address calculations, metadata/data/invalid offsets, full locked/pinned split and boundary checks. The metadata structure is extracted from the port UAPI. No perf syscall, actual page allocation, PFN mapping, concurrent teardown or PMU operation was executed. Old control shows wrong logical addresses without dereferencing them; this is not an exploit demonstration.',remote_sources_used=[])
(Path(__file__).resolve().parent/'evidence/perf-metadata-check.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
