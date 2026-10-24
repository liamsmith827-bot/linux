#!/usr/bin/env python3
"""Extracted IOMMU allocation/shift host checks; no DMA hardware or RB-tree execution."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
OLD='4209d699e800'
def old(path): return subprocess.check_output(['git','show',OLD+':'+path],cwd=ROOT,text=True)
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
p='drivers/iommu/dma-iommu.c';source=(ROOT/p).read_text();body=function(source,'__iommu_dma_alloc_pages');before=function(old(p),'__iommu_dma_alloc_pages');free=function(source,'__iommu_dma_free_pages')
added='\t\t\t/* Pages are split and freed individually; keep requested zeroing. */\n\t\t\talloc_flags &= ~__GFP_COMP;\n\t\t\talloc_flags |= gfp & __GFP_ZERO;\n'
assert body.replace(added,'')==before
pre=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
typedef unsigned gfp_t;
#define MAX_PAGE_ORDER 4
#define GFP_KERNEL 0
#define __GFP_ZERO 1U
#define __GFP_COMP 2U
#define __GFP_NORETRY 4U
#define __GFP_NOWARN 8U
#define __GFP_HIGHMEM 16U
#define GENMASK(h,l) ((~0UL << (l)) & (~0UL >> (sizeof(long)*8-1-(h))))
static unsigned __fls(unsigned long v) { assert(v); return sizeof(long)*8-1-__builtin_clzl(v); }
struct device { int node; };
struct page { unsigned flags; int alive; };
static struct page pool[128];
static unsigned used, attempts, freed, fail_orders, fail_nth, drop, add;
static unsigned required_zero, bad_zero, bad_comp, array_fail, arrays;
static int dev_to_node(struct device *d) { return d->node; }
static void *kvcalloc(unsigned n, size_t s, int g) { if(array_fail) return NULL; arrays++; return calloc(n,s); }
static void kvfree(void *p) { assert(arrays); arrays--; free(p); }
static void trace_android_vh_adjust_alloc_flags(unsigned order,gfp_t *flags) { *flags=(*flags&~drop)|add; }
static struct page *alloc_pages_node(unsigned nid,gfp_t flags,unsigned order) {
 attempts++;
 if((fail_orders&(1U<<order)) || attempts==fail_nth) return NULL;
 unsigned n=1U<<order; assert(used+n<=128);
 struct page *p=&pool[used]; used+=n;
 for(unsigned i=0;i<n;i++) {p[i].flags=flags; p[i].alive=1;}
 if(required_zero && !(flags&__GFP_ZERO)) bad_zero++;
 return p;
}
static void split_page(struct page *p,unsigned order) { if(p->flags&__GFP_COMP) bad_comp++; }
static void __free_page(struct page *p) { assert(p->alive); p->alive=0; freed++; }
'''
main=r'''
static unsigned run(int version,unsigned n,unsigned mask,unsigned gfp) {
 struct device dev={0}; used=attempts=freed=bad_zero=bad_comp=arrays=0;
 memset(pool,0,sizeof(pool)); required_zero=gfp&__GFP_ZERO;
 struct page **pages= version ? new_alloc(&dev,n,mask,gfp) : old_alloc(&dev,n,mask,gfp);
 if(pages) {
  assert(used==n);
  for(unsigned i=0;i<n;i++) { assert(pages[i]->alive); if(i) assert(pages[i]==pages[i-1]+1); }
  __iommu_dma_free_pages(pages,n);
 }
 assert(freed==used && !arrays);
 for(unsigned i=0;i<used;i++) assert(!pool[i].alive);
 if(version) assert(!bad_zero && !bad_comp);
 return !!pages;
}
int main(void) {
 unsigned long cases=0,old_failures=0,controls=0;
 unsigned counts[]={1,2,3,4,7,8,15,16,17,31,32,33,63};
 unsigned masks[]={0,1,2,3,5,7,15,16,17,31,63};
 unsigned flags[]={0,__GFP_ZERO,__GFP_NORETRY,__GFP_ZERO|__GFP_NORETRY};
 for(unsigned c=0;c<sizeof(counts)/sizeof(counts[0]);c++)
 for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++)
 for(unsigned f=0;f<sizeof(flags)/sizeof(flags[0]);f++)
 for(unsigned policy=0;policy<8;policy++)
 for(unsigned failures=0;failures<5;failures++) {
  drop=(policy&1)?__GFP_ZERO:0; add=(policy&2)?__GFP_COMP:0;
  if(policy&4) {drop|=__GFP_NORETRY; add|=32;}
  array_fail=failures==4; fail_nth=failures==3?2:0;
  fail_orders=failures==1?16:(failures==2?31:0);
  unsigned got=run(1,counts[c],masks[m],flags[f]);
  unsigned want=run(0,counts[c],masks[m],flags[f]); assert(got==want);
  old_failures+=!!(bad_zero||bad_comp); if(!policy) controls++;
  cases++;
 }
 assert(old_failures);
 printf("{\"allocation_cases\":%lu,\"no_callback_controls\":%lu,\"old_contract_failures\":%lu}\n",cases,controls,old_failures);
}
'''
def prefix(src):
 b=function(src,'__alloc_and_insert_iova_range')
 return b[b.index('\tif (size_aligned)'):b.index('\n\t/* Walk the tree backwards */')]
path='drivers/iommu/iova.c';shift=prefix((ROOT/path).read_text());oldshift=prefix(old(path));guard='\t\t/* A callback must not turn the alignment mask into an invalid shift. */\n\t\tif (shift >= BITS_PER_LONG)\n\t\t\treturn -EINVAL;\n';assert shift.replace(guard,'')==oldshift
shiftpre=r'''
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#define BITS_PER_LONG (sizeof(unsigned long)*8)
static unsigned long override;
static bool enabled;
static unsigned long fls_long(unsigned long n) {return n ? BITS_PER_LONG-__builtin_clzl(n):0;}
static void trace_android_rvh_iommu_limit_align_shift(void *d,unsigned long size,unsigned long *s) { if(enabled) *s=override; }
'''
def shiftfn(name,s):return 'static int '+name+'(unsigned long size,bool size_aligned,unsigned long *result) {\nvoid *iovad=0;unsigned long align_mask=~0UL;\n'+s+'\n*result=align_mask;return 0;\n}\n'
shiftmain=r'''
int main(int argc,char **argv) {
 unsigned long result=0;
 if(argc>1) {enabled=true; override=BITS_PER_LONG; return old_mask(2,true,&result);}
 unsigned long cases=0,rejected=0;
 unsigned long sizes[]={0,1,2,3,4,63,64,65,4096,4097,1UL<<31,1UL<<63,ULONG_MAX};
 unsigned long values[]={0,1,2,7,12,31,32,62,63,64,65,ULONG_MAX};
 for(unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++)
 for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++)
 for(unsigned e=0;e<2;e++)
 for(unsigned aligned=0;aligned<2;aligned++) {
  enabled=e;override=values[j];
  unsigned long expected_shift=e?override:fls_long(sizes[i]-1);
  int ret=new_mask(sizes[i],aligned,&result);
  if(aligned && expected_shift>=BITS_PER_LONG) {assert(ret==-EINVAL);rejected++;}
  else {assert(!ret);assert(result==(aligned?(~0UL<<expected_shift):~0UL)); unsigned long before; assert(!old_mask(sizes[i],aligned,&before)&&before==result);}
  cases++;
 }
 assert(rejected);printf("{\"alignment_cases\":%lu,\"invalid_shifts_rejected\":%lu}\n",cases,rejected);
}
'''
freebody=function(source,'iommu_dma_free_iova');oldfree=function(old(p),'iommu_dma_free_iova')
freepre=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint64_t dma_addr_t;
struct iova_domain { unsigned shift; };
struct iommu_dma_cookie { struct iova_domain iovad; };
struct iommu_dma_msi_cookie { dma_addr_t msi_iova; };
struct iommu_domain { int cookie_type; union { struct iommu_dma_cookie *iova_cookie; struct iommu_dma_msi_cookie *msi_cookie; }; };
struct iommu_iotlb_gather { bool queued; int freelist; };
#define IOMMU_COOKIE_DMA_MSI 1
static unsigned queued,freed,callbacks,bad;
static struct iova_domain *expected;
static unsigned iova_shift(struct iova_domain *d) {assert(d==expected);return d->shift;}
static unsigned long iova_pfn(struct iova_domain *d,dma_addr_t a) {return a>>iova_shift(d);}
static void queue_iova(struct iommu_dma_cookie *c,unsigned long p,unsigned long n,int *f) {assert(&c->iovad==expected);queued++;}
static void free_iova_fast(struct iova_domain *d,unsigned long p,unsigned long n) {assert(d==expected);freed++;}
static void trace_android_vh_iommu_iovad_free_iova(struct iova_domain *d,dma_addr_t a,size_t n) {callbacks++; if(!expected || d!=expected) bad++;}
'''
freemain=r'''
int main(void) {
 unsigned cases=0,old_failures=0;
 for(unsigned msi=0;msi<2;msi++) for(unsigned gather=0;gather<3;gather++)
 for(unsigned shift=0;shift<4;shift++) for(unsigned ver=0;ver<2;ver++) {
  struct iommu_dma_cookie c={{shift}};struct iommu_dma_msi_cookie m={8192};
  struct iommu_domain d={.cookie_type=msi};if(msi)d.msi_cookie=&m;else d.iova_cookie=&c;
  struct iommu_iotlb_gather g={.queued=gather==2};
  queued=freed=callbacks=bad=0;expected=msi?NULL:&c.iovad;
  if(ver)new_free(&d,4096,4096,gather?&g:NULL);else old_free(&d,4096,4096,gather?&g:NULL);
  if(msi)assert(m.msi_iova==4096&&!queued&&!freed);else assert(queued==(gather==2)&&freed==(gather!=2));
  if(ver) {assert(!bad&&callbacks==!msi);cases++;}else old_failures+=!!bad;
 }
 assert(old_failures);printf("{\"free_cookie_cases\":%u,\"old_msi_cookie_type_failures\":%u}\n",cases,old_failures);
}
'''
with tempfile.TemporaryDirectory(prefix='iommu-hooks-') as tmp:
 tmp=Path(tmp);stats={}
 programs={'pages':pre+free+before.replace('__iommu_dma_alloc_pages(','old_alloc(',1)+body.replace('__iommu_dma_alloc_pages(','new_alloc(',1)+main,'alignment':shiftpre+shiftfn('new_mask',shift)+shiftfn('old_mask',oldshift)+shiftmain}
 programs['free-cookie']=freepre+freebody.replace('iommu_dma_free_iova(','new_free(',1)+oldfree.replace('iommu_dma_free_iova(','old_free(',1)+freemain
 for name,code in programs.items():
  src=tmp/(name+'.c');exe=tmp/name;src.write_text(code)
  subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True)
  p=subprocess.run([str(exe)],text=True,capture_output=True);assert p.returncode==0,p.stderr;stats.update(json.loads(p.stdout))
 p=subprocess.run([str(tmp/'alignment'),'old-invalid-shift'],text=True,capture_output=True);assert p.returncode!=0 and 'shift exponent 64 is too large' in p.stderr,p.stderr
 stats['old_invalid_shift_control_rejected_by_ubsan']=True
report=dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),pre_fix_commit=OLD,extracted_alloc_sha256=sha(body),extracted_shift_prefix_sha256=sha(shift),extracted_free_sha256=sha(freebody),results=stats,scope=__doc__,limitations='Mocks allocator/free operations and selected failure outcomes; no actual page allocator, RB tree, IOMMU/DMA, driver callback, concurrency or runtime execution.',remote_sources_used=[])
(ROOT/'Documentation/android-port/evidence/iommu-hook-bounds-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(stats))
