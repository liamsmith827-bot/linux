#!/usr/bin/env python3
"""Host execution of actual BPF mapping and syscall-size dispatch with stubs."""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ring_source = (ROOT/'kernel/bpf/ringbuf.c').read_text()
ring = '\n'.join(function(ring_source, name) for name in
                 ['ringbuf_map_mmap', 'ringbuf_map_mmap_kern', 'ringbuf_map_mmap_user'])
old_ring = function(subprocess.check_output(['git', 'show', '23a6d60f6e99:kernel/bpf/ringbuf.c'], cwd=ROOT, text=True), 'ringbuf_map_mmap_kern').replace('ringbuf_map_mmap_kern(', 'old_ring(')
syscall = function((ROOT/'kernel/bpf/syscall.c').read_text(), '__sys_bpf')
fields = {
    'BPF_PROG_QUERY': 'query.prog_cnt', 'BPF_PROG_TEST_RUN': 'test.duration',
    'BPF_PROG_GET_NEXT_ID': 'next_id', 'BPF_MAP_GET_NEXT_ID': 'next_id',
    'BPF_BTF_GET_NEXT_ID': 'next_id', 'BPF_OBJ_GET_INFO_BY_FD': 'info.info_len',
    'BPF_TASK_FD_QUERY': 'task_fd_query.probe_addr',
    'BPF_MAP_LOOKUP_BATCH': 'batch.flags', 'BPF_MAP_LOOKUP_AND_DELETE_BATCH': 'batch.flags',
    'BPF_MAP_UPDATE_BATCH': 'batch.flags', 'BPF_MAP_DELETE_BATCH': 'batch.flags',
    'BPF_LINK_GET_NEXT_ID': 'next_id',
}
arms = []
helpers = set()
for cmd in fields:
    arm = re.search(r'\tcase '+cmd+r':\n.*?\t\tbreak;', syscall, re.S).group()
    arms.append(arm)
    helpers.update(re.findall(r'err = (\w+)\(', arm))
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
'''+f'#include "{ROOT}/include/uapi/linux/bpf.h"\n'+r'''
typedef uint64_t u64;
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096UL
#define RINGBUF_POS_PAGES 2
#define RINGBUF_PGOFF 1
#define RINGBUF_NR_META_PAGES 3
#define VM_WRITE 1
#define EPERM 1
static unsigned long emulated_size;
#define __PAGE_SIZE emulated_size
#define __PAGE_ALIGN(x) (((x)+__PAGE_SIZE-1)&~(__PAGE_SIZE-1))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t *)0)->m))
struct bpf_map { unsigned int max_entries; };
struct bpf_ringbuf_map { struct bpf_map map; void *rb; };
struct vm_area_struct { unsigned long vm_start,vm_end,vm_flags,vm_pgoff; };
static unsigned long mapped, mapped_offset, allocation_size, slots[256];
static int remap_calls, fail_call;
static int remap_vmalloc_range_partial(struct vm_area_struct *vma, unsigned long addr,
                                      void *base, unsigned long pgoff, unsigned long size) {
    assert(addr>=vma->vm_start && size && !(size&(PAGE_SIZE-1)));
    if(++remap_calls==fail_call) return -ENOMEM;
    if(pgoff>allocation_size/PAGE_SIZE || size>allocation_size-pgoff*PAGE_SIZE) return -EINVAL;
    assert(size<=vma->vm_end-addr);
    unsigned start=(addr-vma->vm_start)/PAGE_SIZE;
    for(unsigned i=0;i<size/PAGE_SIZE;i++) slots[start+i]=pgoff+i+1;
    if(!mapped) mapped_offset=pgoff*PAGE_SIZE;
    mapped+=size;return 0;
}
static int remap_vmalloc_range(struct vm_area_struct *vma,void *base,unsigned long pgoff) {
    return remap_vmalloc_range_partial(vma,vma->vm_start,base,pgoff,vma->vm_end-vma->vm_start);
}
static unsigned calls;
static int helper(void) { calls++;return 77; }
'''
prefix += '\n'.join('#define '+h+'(...) helper()' for h in sorted(helpers))+'\n'
dispatch = 'static int dispatch(enum bpf_cmd cmd,unsigned size) { int err=-99; switch(cmd) {\n'+'\n'.join(arms)+'\ndefault: break; } return err;}\n'
table = ',\n'.join('{'+c+',offsetofend(union bpf_attr,'+f+')}' for c, f in fields.items())
main = r'''
int main(void) {
    unsigned query_cases=0,ring_cases=0;
    struct { enum bpf_cmd cmd; unsigned minimum; } commands[] = {
'''+table+r'''
    };
    for(unsigned c=0;c<sizeof(commands)/sizeof(commands[0]);c++)
    for(unsigned size=0;size<=sizeof(union bpf_attr)+1;size++) {
        calls=0;int r=dispatch(commands[c].cmd,size);
        if(size<commands[c].minimum) assert(r==-EINVAL && !calls);
        else assert(r==77 && calls==1);
        query_cases++;
    }
    for(emulated_size=4096;emulated_size<=16384;emulated_size*=2)
    for(unsigned entries=4096;entries<=32768;entries*=2)
    for(unsigned user=0;user<2;user++)
    for(unsigned write=0;write<2;write++)
    for(unsigned p=0;p<20;p++)
    for(unsigned pages=1;pages<=24;pages++) {
        struct bpf_ringbuf_map m={.map={.max_entries=entries}};
        unsigned long pgoff=p==19?ULONG_MAX:p;
        struct vm_area_struct v={.vm_start=0x100000,.vm_end=0x100000+pages*emulated_size,
                                  .vm_flags=write?VM_WRITE:0,.vm_pgoff=pgoff};
        unsigned long available=2*PAGE_SIZE+2*entries;
        allocation_size=RINGBUF_PGOFF*PAGE_SIZE+available;
        /* do_mmap rejects overflow before invoking the BPF map callback. */
        if(pgoff+(pages*emulated_size/PAGE_SIZE)<pgoff) continue;
        mapped=remap_calls=0;
        for(unsigned i=0;i<256;i++) slots[i]=0;
        int r=user?ringbuf_map_mmap_user(&m.map,&v):ringbuf_map_mmap_kern(&m.map,&v);
        if(write && !user) {
            if(pgoff || pages!=1) assert(r==-EPERM && !mapped);
            else assert(!r && mapped==PAGE_SIZE && mapped_offset==RINGBUF_PGOFF*PAGE_SIZE);
        } else if(write && user && !pgoff) assert(r==-EPERM && !mapped);
        else if(emulated_size!=PAGE_SIZE && pgoff==emulated_size/PAGE_SIZE &&
                pages*emulated_size==__PAGE_ALIGN(emulated_size+2*entries)) {
            assert(!r && mapped==PAGE_SIZE+2*entries && remap_calls==2);
            assert(slots[0]==RINGBUF_PGOFF+2);
            for(unsigned i=1;i<emulated_size/PAGE_SIZE;i++) assert(!slots[i]);
            for(unsigned i=0;i<2*entries/PAGE_SIZE;i++)
                assert(slots[emulated_size/PAGE_SIZE+i]==RINGBUF_NR_META_PAGES+i+1);
            for(unsigned i=(emulated_size+2*entries)/PAGE_SIZE;i<pages*emulated_size/PAGE_SIZE;i++)
                assert(!slots[i]);
        } else if(pgoff>=available/PAGE_SIZE) assert(r==-EINVAL && !mapped);
        else {
            unsigned long remaining=available-pgoff*PAGE_SIZE;
            if(pages*emulated_size>__PAGE_ALIGN(remaining)) assert(r==-EINVAL && !mapped);
            else {
                assert(!r && mapped==(pages*emulated_size<remaining?pages*emulated_size:remaining)
                        && mapped_offset==(pgoff+RINGBUF_PGOFF)*PAGE_SIZE);
                for(unsigned i=0;i<mapped/PAGE_SIZE;i++) assert(slots[i]==pgoff+RINGBUF_PGOFF+i+1);
                for(unsigned i=mapped/PAGE_SIZE;i<pages*emulated_size/PAGE_SIZE;i++) assert(!slots[i]);
            }
        }
        ring_cases++;
    }
    emulated_size=16384;
    struct bpf_ringbuf_map m={.map={.max_entries=32768}};
    struct vm_area_struct v={.vm_start=0x100000,.vm_end=0x104000,.vm_flags=VM_WRITE};
    allocation_size=3*PAGE_SIZE+2*m.map.max_entries;
    mapped=0;
    assert(!old_ring(&m.map,&v) && mapped==4*PAGE_SIZE);
    mapped=0;
    assert(!ringbuf_map_mmap_kern(&m.map,&v) && mapped==PAGE_SIZE);
    m.map.max_entries=4096;allocation_size=3*PAGE_SIZE+2*m.map.max_entries;
    v.vm_flags=0;v.vm_pgoff=1;
    assert(old_ring(&m.map,&v)==-EINVAL);
    mapped=0;
    assert(!ringbuf_map_mmap_kern(&m.map,&v) && mapped==3*PAGE_SIZE);
    v.vm_pgoff=emulated_size/PAGE_SIZE;v.vm_end=v.vm_start+__PAGE_ALIGN(emulated_size+2*m.map.max_entries);
    for(fail_call=1;fail_call<=2;fail_call++) {
        mapped=remap_calls=0;
        assert(ringbuf_map_mmap_kern(&m.map,&v)==-ENOMEM && remap_calls==fail_call);
    }
    printf("{\"dispatch_cases\":%u,\"mapping_cases\":%u,\"negative_controls\":2,\"remap_failure_cases\":2}\n",query_cases,ring_cases);
}
'''
with tempfile.TemporaryDirectory(prefix='bpf-mmap-') as tmp:
    src=Path(tmp)/'check.c';exe=Path(tmp)/'check'
    src.write_text(prefix+dispatch+ring+'\n'+old_ring+'\n'+main)
    subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined',str(src),'-o',str(exe)],check=True)
    results=json.loads(subprocess.check_output([str(exe)],text=True))
report=dict(results=results,source_sha256={'mapping':hashlib.sha256(ring.encode()).hexdigest(),'dispatch_arms':hashlib.sha256('\n'.join(arms).encode()).hexdigest()},
            scope='Actual shared and kernel/user-produced mapping functions and twelve dispatch arms, native UAPI layout, mocked remapping/helper calls under host ASan/UBSan. Covers hardware-offset separate mappings and userspace-page-size combined producer/data mappings, padding holes, page identity and remap failures. Proves bounds/selection in this model, not kernel page-table behavior or runtime emulator compatibility.')
out=ROOT/'Documentation/android-port/evidence/bpf-mmap-bounds-test.json'
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
