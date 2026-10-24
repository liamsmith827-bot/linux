#!/usr/bin/env python3
"""Host tests of extracted Intel IOMMU walkers with mocked pages and invalidation.

These checks do not exercise DMA hardware, real allocation, locking or concurrency.
The compare/exchange-loss case injects an interleaving, rather than running threads.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
OLD='aad8b72c5b0f'
p='drivers/iommu/intel/iommu.c'
src=(ROOT/p).read_text();old=subprocess.check_output(['git','show',OLD+':'+p],cwd=ROOT,text=True)
names=['pfn_to_dma_pte','dma_pte_clear_level','switch_to_super_page']
bodies={n:function(src,n) for n in names}
previous={n:function(old,n) for n in names}
pre=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned gfp_t;
typedef uint64_t u64;
#define SZ_4K 4096
#define VTD_PAGE_SIZE 4096
#define VTD_PAGE_SHIFT 12
#define DMA_PTE_READ 1
#define DMA_PTE_WRITE 2
#define DMA_FL_PTE_US 4
#define DMA_FL_PTE_ACCESS 32
#define GFP_ATOMIC 0
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define max(a,b) ((a)>(b)?(a):(b))
#define IS_ALIGNED(x,a) (!((x)&((a)-1)))
static unsigned warnings;
#define WARN_ON_ONCE(x) ((x)?(warnings++,1):0)
#define WARN_ON(x) WARN_ON_ONCE(x)
struct dma_pte { uint64_t val; };
struct dmar_domain { int agaw,nid; bool use_first_level; struct dma_pte *pgd; };
struct iommu_pages_list { unsigned count; void *pages[64]; };
static _Alignas(4096) struct dma_pte pool[32][512];
static unsigned used,freed,fail_alloc,inject_leaf,bad_descent,flushes;
static unsigned upgrade_frees,upgrade_flushes;
static unsigned long free_start[512],flush_start[512],flush_end[512];
static int agaw_to_level(int a) {return a+2;}
static unsigned long level_size(int l) {assert(l>=1 && l<=4);return 1UL<<(9*(l-1));}
static unsigned long level_mask(int l) {return ~(level_size(l)-1);}
static unsigned long lvl_to_nr_pages(int l) {return level_size(l);}
static int pfn_level_offset(unsigned long pfn,int l) {return (pfn>>(9*(l-1)))&511;}
static bool domain_pfn_supported(struct dmar_domain *d,unsigned long pfn) {return pfn < (1UL<<(9*agaw_to_level(d->agaw)));}
static bool dma_pte_present(struct dma_pte *p) {return p->val&3;}
static bool dma_pte_superpage(struct dma_pte *p) {return p->val&128;}
static uintptr_t dma_pte_addr(struct dma_pte *p) {return p->val&~4095UL;}
static uintptr_t virt_to_phys(void *p) {return (uintptr_t)p;}
static void *phys_to_virt(uintptr_t p) {
 assert(p>=(uintptr_t)pool && p<(uintptr_t)(pool+32));
 if(p>=(uintptr_t)pool[31]) bad_descent++;
 return (void *)p;
}
static void dma_clear_pte(struct dma_pte *p) {p->val=0;}
static bool first_pte_in_page(struct dma_pte *p) {return !((uintptr_t)p&4095);}
static void *iommu_alloc_pages_node_sz(int nid,gfp_t g,size_t sz) {
 assert(sz==4096);if(fail_alloc)return NULL;assert(used<30);return pool[used++];
}
static void iommu_free_pages(void *p) {assert(p>=(void *)pool && p<(void *)(pool+30));freed++;}
static void domain_flush_cache(struct dmar_domain *d,void *p,size_t n) {flushes++;}
static bool try_cmpxchg64(uint64_t *p,uint64_t *expected,uint64_t desired) {
 if(inject_leaf) {*p=(uintptr_t)pool[31]|131;inject_leaf=0;}
 if(*p!=*expected) {*expected=*p;return false;}*p=desired;return true;
}
static void iommu_pages_list_add(struct iommu_pages_list *f,void *p) {assert(f->count<64);f->pages[f->count++]=p;}
static void dma_pte_free_pagetable(struct dmar_domain *d,unsigned long s,unsigned long e,int retain) {
 assert(upgrade_frees<512);assert(e-s+1==level_size(retain-1));free_start[upgrade_frees++]=s;
}
static void cache_tag_flush_range(struct dmar_domain *d,unsigned long s,unsigned long e,int hint) {
 assert(!hint && upgrade_flushes<512);flush_start[upgrade_flushes]=s;flush_end[upgrade_flushes++]=e;
}
static struct dmar_domain reset(void) {
 memset(pool,0,sizeof(pool));used=1;freed=fail_alloc=inject_leaf=bad_descent=flushes=warnings=0;
 upgrade_frees=upgrade_flushes=0;return (struct dmar_domain){.agaw=1,.pgd=pool[0]};
}
static struct dma_pte *seed(struct dmar_domain *d,unsigned long pfn,int leaf) {
 struct dma_pte *table=d->pgd;
 for(int l=3;l>leaf;l--) {struct dma_pte *p=&table[pfn_level_offset(pfn,l)];p->val=(uintptr_t)pool[used]|3;table=pool[used++];}
 struct dma_pte *p=&table[pfn_level_offset(pfn,leaf)];p->val=(uintptr_t)pool[31]|(leaf>1?131:3);return p;
}
'''
main=r'''
int main(void) {
 unsigned walk_cases=0,old_bad=0,unmap_cases=0,upgrade_cases=0;
 for(int leaf=1;leaf<=3;leaf++) for(unsigned k=0;k<5;k++) {
  unsigned long pfn=3*level_size(leaf)+k;
  for(int target=0;target<=leaf;target++) for(int version=0;version<2;version++) {
   struct dmar_domain d=reset();struct dma_pte *expected=seed(&d,pfn,leaf);int l=target;
   struct dma_pte *got=version?new_walk(&d,pfn,&l,0):old_walk(&d,pfn,&l,0);
   if(target && target<leaf) {
    if(version) {assert(IS_ERR(got)&&PTR_ERR(got)==-EEXIST&&!bad_descent);}
    else {assert(bad_descent);old_bad++;}
   } else {assert(got==expected&&l==(target?target:leaf)&&!bad_descent);}
   walk_cases++;
  }
 }
 for(int version=0;version<2;version++) for(int mode=0;mode<5;mode++) {
  struct dmar_domain d=reset();int l=1;unsigned long pfn=1;
  if(mode==1) fail_alloc=1;
  if(mode==2) pfn=1UL<<27;
  if(mode==3) inject_leaf=1;
  if(mode==4) d.use_first_level=true;
  struct dma_pte *p=version?new_walk(&d,pfn,&l,0):old_walk(&d,pfn,&l,0);
  if(mode==1||mode==2) {if(version)assert(IS_ERR(p)&&PTR_ERR(p)==(mode==1?-ENOMEM:-EINVAL));else assert(!p);}
  else if(mode==3) {if(version)assert(IS_ERR(p)&&PTR_ERR(p)==-EEXIST&&!bad_descent&&freed==1);else {assert(bad_descent&&freed==1);old_bad++;}}
  else {assert(p==&pool[2][1]&&!bad_descent&&used==3);assert(!mode || (pool[0][0].val&DMA_FL_PTE_US));}
  walk_cases++;
 }
 for(int leaf=1;leaf<=3;leaf++) for(int mode=0;mode<4;mode++) {
  if(leaf==1 && mode) continue;
  unsigned long n=level_size(leaf),start=3*n,end=4*n-1;
  if(mode&1)start++;
  if(mode&2)end--;
  unsigned old_cleared=0,old_list=0,old_flush=0;
  for(int version=0;version<2;version++) {
   struct dmar_domain d=reset();struct dma_pte *p=seed(&d,3*n,leaf);struct iommu_pages_list f={0};
   if(version)new_clear(&d,3,d.pgd,0,start,end,&f);else old_clear(&d,3,d.pgd,0,start,end,&f);
   if(!mode) {
    assert(!dma_pte_present(p)&&!bad_descent);
    if(!version){old_cleared=!p->val;old_list=f.count;old_flush=flushes;}
    else assert(old_cleared==!p->val&&old_list==f.count&&old_flush==flushes);
   } else if(version) {assert(dma_pte_present(p)&&!bad_descent&&warnings);}
   else {assert(bad_descent);old_bad++;}
   unmap_cases++;
  }
 }
 /* Caller bounds the range to this PTE page and a whole number of large pages. */
 for(int level=2;level<=3;level++) for(unsigned offset=0;offset<512;offset+=17)
 for(unsigned requested=1;requested<=513;requested+=32) {
  unsigned count=requested<512-offset?requested:512-offset;
  unsigned old_frees=0,old_flushes=0;unsigned long expected_start[512],expected_end[512];
  for(int version=0;version<2;version++) {
   struct dmar_domain d=reset();struct dma_pte *table=d.pgd;
   if(level==2){d.pgd[0].val=(uintptr_t)pool[used]|3;table=pool[used++];}
   for(unsigned j=offset;j<offset+count;j++) if(j%3)table[j].val=(uintptr_t)pool[31]|131;
   unsigned long start=offset*level_size(level),end=(offset+count)*level_size(level)-1;
   if(version)new_upgrade(&d,start,end,level,&table[offset]);else old_upgrade(&d,start,end,level);
   assert(!bad_descent && !warnings && upgrade_frees==upgrade_flushes);
   if(!version){old_frees=upgrade_frees;old_flushes=upgrade_flushes;memcpy(expected_start,flush_start,sizeof(expected_start));memcpy(expected_end,flush_end,sizeof(expected_end));}
   else {assert(upgrade_frees==old_frees&&upgrade_flushes==old_flushes);assert(!memcmp(expected_start,flush_start,old_flushes*sizeof(unsigned long)));assert(!memcmp(expected_end,flush_end,old_flushes*sizeof(unsigned long)));}
   upgrade_cases++;
  }
 }
 assert(old_bad);
 printf("{\"walker_cases\":%u,\"unmap_cases\":%u,\"upgrade_cases\":%u,\"pre_fix_leaf_descents\":%u}\n",walk_cases,unmap_cases,upgrade_cases,old_bad);
}
'''
code=pre+function(src,'dma_pte_list_pagetables')
for n,before,after in [('pfn_to_dma_pte','old_walk','new_walk'),('dma_pte_clear_level','old_clear','new_clear'),('switch_to_super_page','old_upgrade','new_upgrade')]:
    code+=previous[n].replace(n,before).replace('pfn_to_dma_pte','old_walk')
    code+=bodies[n].replace(n,after)
code+=main
with tempfile.TemporaryDirectory(prefix='intel-iommu-walk-') as tmp:
    c=Path(tmp)/'test.c';exe=Path(tmp)/'test';c.write_text(code)
    subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',str(c),'-o',str(exe)],check=True)
    result=json.loads(subprocess.check_output([str(exe)],text=True))
# Each PASID change is error representation/propagation only, preserving native
# cache publication, teardown ordering, and replacement APIs byte for byte.
pp='drivers/iommu/intel/pasid.c';ps=(ROOT/pp).read_text();po=subprocess.check_output(['git','show',OLD+':'+pp],cwd=ROOT,text=True)
normalized=ps.replace('ERR_PTR(-ENODEV)','NULL').replace('ERR_PTR(-ENOMEM)','NULL').replace('IS_ERR(pe)','!pe').replace('IS_ERR(pte)','!pte').replace('PTR_ERR(pte)','-ENODEV')
assert normalized==po
# A dirty-lookup error must be handled before level_size(0) can be evaluated.
dirty=function(src,'intel_iommu_read_and_clear_dirty');assert dirty.index('if (IS_ERR(pte))')<dirty.index('pgsize = level_size(lvl)')
report=dict(pre_fix_commit=subprocess.check_output(['git','rev-parse',OLD],cwd=ROOT,text=True).strip(),source_sha256={p:hashlib.sha256(src.encode()).hexdigest(),pp:hashlib.sha256(ps.encode()).hexdigest()},results=result,pasid_whole_file_normalization_matches=True,sanitizers='AddressSanitizer and UndefinedBehaviorSanitizer',limits=__doc__,remote_sources_used=[])
(ROOT/'Documentation/android-port/evidence/intel-iommu-walk-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(result))
