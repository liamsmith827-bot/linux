#!/usr/bin/env python3
"""Host checks of extracted smaps PMD accounting and VMA range selection.

Exercise every split of a PMD, per-page sharing, migration and special entries,
shmem fast/partial/COW paths, padding bounds, RCU release/reacquisition and mmap
fallback. An old-source control demonstrates double counting. Kernel page tables,
real locks, concurrent modification and Android runtime are not executed.
"""
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
path = 'fs/proc/task_mmu.c'
baseline = '15bccdfefe6dab136de759c0048289ab89784f19'
text = (root / path).read_text()
old = subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)

def function(source, signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

stats = text[text.index('struct mem_size_stats {'):text.index('static void smaps_page_accumulate(')]
accounting = ''.join(function(text, sig) for sig in [
    'static void smaps_page_accumulate(', 'static void smaps_account(',
    'static void smaps_pmd_entry('])
accounting += function(old, 'static void smaps_pmd_entry(').replace('smaps_pmd_entry(', 'old_smaps_pmd_entry(', 1)
range_code = ''.join(function(text, sig) for sig in [
    'static inline void drop_rcu(', 'static inline void reacquire_rcu(',
    'static void smap_gather_stats_range('])

shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL<<PAGE_SHIFT)
#define HPAGE_PMD_NR 512
#define HPAGE_PMD_SIZE (PAGE_SIZE*HPAGE_PMD_NR)
#define HPAGE_PMD_MASK (~(HPAGE_PMD_SIZE-1))
#define PSS_SHIFT 12
#define VM_LOCKED 1
#define VM_MAYWRITE 2
#define VM_SHARED 4
#define unlikely(x) (x)
#define IS_ERR_OR_NULL(x) (!(x))
#define CONFIG_NO_PAGE_MAPCOUNT 0
#define CONFIG_PAGE_MAPCOUNT 1
#define IS_ENABLED(x) (x)
#define do_div(n,d) ((n)/=(d))
typedef uint64_t u64;
typedef unsigned int pmd_t;
typedef unsigned int swp_entry_t;
struct folio { bool anon,swapbacked,device,dirty,young,referenced,ksm; unsigned int refs; };
struct page { struct folio *folio; unsigned int mapcount; };
struct mapping { bool shmem; };
struct file { struct mapping *f_mapping; };
struct vm_area_struct { unsigned long vm_flags,vm_start,vm_end,pad,swapped; struct file *vm_file; };
struct mem_size_stats;
struct mm_walk { struct vm_area_struct *vma; struct mem_size_stats *private; };
static struct folio backing;
static struct page pages[HPAGE_PMD_NR];
static bool valid_page=true,migration=true;
static struct folio *page_folio(struct page *p) {return p->folio;}
static bool folio_test_anon(struct folio *f) {return f->anon;}
static bool folio_test_swapbacked(struct folio *f) {return f->swapbacked;}
static bool folio_is_zone_device(struct folio *f) {return f->device;}
static bool folio_test_dirty(struct folio *f) {return f->dirty;}
static bool folio_test_young(struct folio *f) {return f->young;}
static bool folio_test_referenced(struct folio *f) {return f->referenced;}
static bool folio_test_ksm(struct folio *f) {return f->ksm;}
static unsigned int folio_ref_count(struct folio *f) {return f->refs;}
static int compound_nr(struct page *p) {(void)p;return HPAGE_PMD_NR;}
static int folio_precise_page_mapcount(struct folio *f,struct page *p) {assert(p->folio==f);return p->mapcount;}
static int folio_average_page_mapcount(struct folio *f) {(void)f;return 2;}
static bool folio_maybe_mapped_shared(struct folio *f) {(void)f;return true;}
static bool pmd_none(pmd_t p) {return p==0;}
static bool pmd_present(pmd_t p) {return p&1;}
static bool pmd_young(pmd_t p) {return p&2;}
static bool pmd_dirty(pmd_t p) {return p&4;}
static struct page *vm_normal_page_pmd(struct vm_area_struct *v,unsigned long addr,pmd_t p) {(void)v;(void)addr;(void)p;return valid_page?pages:NULL;}
static bool thp_migration_supported(void) {return migration;}
static swp_entry_t pmd_to_swp_entry(pmd_t p) {return p;}
static bool is_pfn_swap_entry(swp_entry_t s) {return s&8;}
static struct page *pfn_swap_entry_to_page(swp_entry_t s) {(void)s;return pages;}
'''
range_shim = r'''
struct proc_maps_locking_ctx { bool mmap_locked; struct vm_area_struct *locked_vma; void *mm; };
struct proc_maps_private { struct proc_maps_locking_ctx lock_ctx; unsigned long iter; };
struct mm_walk_ops { bool shmem, vma_lock; };
static struct mm_walk_ops normal_ops,shmem_ops;
static struct vm_area_struct gate;
static int rcu_depth,walks;
static unsigned long walked_start,walked_end;
static bool walked_shmem,walked_vma_lock;
static struct proc_maps_private *active;
#define VMA_PAD_START(v) ((v)->vm_end-(v)->pad)
static void rcu_read_lock(void) {assert(rcu_depth==0);rcu_depth++;}
static void rcu_read_unlock(void) {assert(rcu_depth==1);rcu_depth--;}
static void vma_iter_set(unsigned long *iter,unsigned long end) {*iter=end;}
static const struct mm_walk_ops *get_smaps_walk_ops(struct proc_maps_private *p) {normal_ops.vma_lock=!p->lock_ctx.mmap_locked;return &normal_ops;}
static const struct mm_walk_ops *get_smaps_shmem_walk_ops(struct proc_maps_private *p) {shmem_ops=(struct mm_walk_ops){true,!p->lock_ctx.mmap_locked};return &shmem_ops;}
static struct vm_area_struct *get_gate_vma(void *mm) {(void)mm;return &gate;}
static bool shmem_mapping(struct mapping *m) {return m->shmem;}
static unsigned long shmem_swap_usage(struct vm_area_struct *v) {assert(!rcu_depth);return v->swapped;}
static int walk_page_range_vma(struct vm_area_struct *v,unsigned long start,unsigned long end,const struct mm_walk_ops *ops,struct mem_size_stats *mss) {
    (void)mss;assert(!rcu_depth);assert(start>=v->vm_start && end<=v->vm_end && start<end);
    assert(active->lock_ctx.mmap_locked || active->lock_ctx.locked_vma);
    walks++;walked_start=start;walked_end=end;walked_shmem=ops->shmem;walked_vma_lock=ops->vma_lock;return 0;
}
'''
tests = r'''
int main(void) {
    struct vm_area_struct v={.vm_flags=VM_LOCKED};
    struct mem_size_stats full={0},parts={0},before={0};
    struct mm_walk w={&v,&full};pmd_t pmd=7;
    backing.refs=2;
    for(unsigned int i=0;i<HPAGE_PMD_NR;i++)pages[i]=(struct page){&backing,i%3==0?2:1};
    for(int kind=0;kind<4;kind++)for(int migrating=0;migrating<2;migrating++) {
        backing.anon=kind==0;backing.swapbacked=kind==1;backing.device=kind==3;
        pmd=migrating?8:7;memset(&full,0,sizeof(full));w.private=&full;
        smaps_pmd_entry(&pmd,HPAGE_PMD_SIZE,2*HPAGE_PMD_SIZE,&w);
        assert(full.resident==HPAGE_PMD_SIZE);
        for(unsigned int split=1;split<HPAGE_PMD_NR;split++) {
            memset(&parts,0,sizeof(parts));w.private=&parts;
            smaps_pmd_entry(&pmd,HPAGE_PMD_SIZE,HPAGE_PMD_SIZE+split*PAGE_SIZE,&w);
            assert(parts.resident==split*PAGE_SIZE);
            smaps_pmd_entry(&pmd,HPAGE_PMD_SIZE+split*PAGE_SIZE,2*HPAGE_PMD_SIZE,&w);
            assert(!memcmp(&parts,&full,sizeof(full)));
        }
    }
    w.private=&before;pmd=7;
    old_smaps_pmd_entry(&pmd,HPAGE_PMD_SIZE,&w);
    old_smaps_pmd_entry(&pmd,HPAGE_PMD_SIZE+PAGE_SIZE,&w);
    assert(before.resident==2*HPAGE_PMD_SIZE);
    memset(&parts,0,sizeof(parts));w.private=&parts;pmd=0;
    smaps_pmd_entry(&pmd,0,PAGE_SIZE,&w);assert(!parts.resident);
    pmd=1;valid_page=false;smaps_pmd_entry(&pmd,0,PAGE_SIZE,&w);assert(!parts.resident);valid_page=true;
    pmd=8;migration=false;smaps_pmd_entry(&pmd,0,PAGE_SIZE,&w);assert(!parts.resident);
    struct mapping mapping={true};struct file file={&mapping};
    for(int mmap=0;mmap<2;mmap++)for(int cow=0;cow<2;cow++)for(int partial=0;partial<2;partial++)for(int padded=0;padded<2;padded++) {
        v=(struct vm_area_struct){.vm_start=4096,.vm_end=32768,.vm_flags=cow?VM_MAYWRITE:VM_SHARED,.pad=padded?4096:0,.swapped=8192,.vm_file=&file};
        struct proc_maps_private priv={.lock_ctx={mmap,mmap?NULL:&v,NULL}};
        active=&priv;rcu_depth=!mmap;walks=0;memset(&parts,0,sizeof(parts));
        smap_gather_stats_range(&priv,&v,&parts,partial?8192:4096);
        assert(walks==1 && walked_start==(partial?8192:4096) && walked_end==32768-v.pad);
        assert(walked_shmem==(bool)(cow||partial||padded));
        assert(parts.swap==((cow||partial||padded)?0:8192));
        assert(walked_vma_lock==!mmap && rcu_depth==!mmap);
        if(!mmap)assert(priv.iter==v.vm_end);
        walks=0;smap_gather_stats_range(&priv,&v,&parts,0);assert(!walks);
        smap_gather_stats_range(&priv,&v,&parts,v.vm_end-v.pad);assert(!walks);
        v.pad=v.vm_end-v.vm_start;smap_gather_stats_range(&priv,&v,&parts,v.vm_start);assert(!walks);
        gate=v;gate.pad=0;smap_gather_stats_range(&priv,&gate,&parts,gate.vm_start);assert(!walks);
    }
    puts("PASS: 4088 PMD partitions, old double-count control, shmem/COW/padding ranges and RCU/mmap paths");
}
'''
source = shim + stats + accounting + range_shim + range_code + tests
with tempfile.TemporaryDirectory(prefix='smaps-ranges-') as temp:
    c = Path(temp) / 'check.c'
    binary = Path(temp) / 'check'
    c.write_text(source)
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(c), '-o', str(binary)], check=True)
    result = subprocess.check_output([str(binary)], text=True).strip()
report = {'status': 'passed', 'scope': __doc__, 'baseline': baseline,
          'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
          'source_blob': subprocess.check_output(['git', 'hash-object', path], cwd=root, text=True).strip(),
          'harness_sha256': hashlib.sha256(source.encode()).hexdigest(),
          'result': result, 'remote_resources_used': []}
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(result)
