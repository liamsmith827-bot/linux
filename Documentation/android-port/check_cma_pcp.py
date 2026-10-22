#!/usr/bin/env python3
"""Check extracted CMA PCP selection and pageblock setup with host shims.

Exercises type/order separation, empty-CMA fallback, restricted/unrestricted
selection and pageblock initialization. This is not a running buddy allocator.
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
baseline = subprocess.check_output(['git', 'rev-parse', '769c2a3ea3f5'], cwd=root, text=True).strip()
paths = ['mm/page_alloc.c', 'include/linux/mmzone.h']
current = {s: (root / s).read_text() for s in paths}
old = {s: subprocess.check_output(['git', 'show', baseline + ':' + s], cwd=root, text=True) for s in paths}

def function(text, signature):
    start = text.index(signature)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#define __meminit
#define unlikely(x) (x)
#define VM_BUG_ON(x) assert(!(x))
#define VM_WARN_ONCE(x,...) assert(!(x))
#define PAGE_ALLOC_COSTLY_ORDER 3
#define HPAGE_PMD_ORDER 9
#define ALLOC_CMA 1
#define MIGRATETYPE_AND_ISO_MASK 7
#define BIT(x) (1UL<<(x))
static bool restricted=true;
static bool page_group_by_mobility_disabled;
static bool cma_has_pcplist(void) {return restricted;}
static bool cma_redirect_restricted(void) {return restricted;}
static unsigned int pcp_thp_order=HPAGE_PMD_ORDER;
struct page {unsigned long flags; int id;};
struct list_head {struct page *page;};
struct zone {int unused;};
static unsigned long page_to_pfn(struct page *p) {(void)p; return 0;}
static void __set_pfnblock_flags_mask(struct page *p, unsigned long pfn,
                                    unsigned long flags,unsigned long mask) {
    (void)pfn; p->flags=(p->flags & ~mask) | (flags & mask);
}
'''

stub = r'''
struct per_cpu_pages {struct list_head lists[NR_PCP_LISTS];};
static struct page normal_page={.id=1},cma_page={.id=2};
static unsigned int calls,wrong_list;
static struct page *___rmqueue_pcplist(struct zone *zone,unsigned int order,
    int mt,unsigned int flags,struct per_cpu_pages *pcp,struct list_head *list) {
    (void)zone;(void)flags;calls++;
    if(list != &pcp->lists[order_to_pindex(mt,order)]) wrong_list++;
    struct page *p=list->page; list->page=NULL; return p;
}
'''

tests = r'''
int main(void) {
    unsigned int cases=0,alias_fail=0,fallback_fail=0,init_fail=0;
    struct zone z={0};
    for(unsigned int thp=4;thp<=HPAGE_PMD_ORDER;thp++) {
        pcp_thp_order=thp;
        for(unsigned int order=0;order<=HPAGE_PMD_ORDER;order++) {
            if(!pcp_allowed_order(order))continue;
            for(int mt=0;mt<MIGRATE_PCPTYPES;mt++) {
                unsigned int index=order_to_pindex(mt,order);
                assert(index<NR_PCP_LISTS);
                assert(pindex_to_order(index)==(int)order);
                cases++;
            }
#ifdef CONFIG_CMA
            unsigned int ci=order_to_pindex(MIGRATE_CMA,order);
            unsigned int mi=order_to_pindex(MIGRATE_MOVABLE,order);
            if(ci==mi)alias_fail++;
            assert(ci!=order_to_pindex(MIGRATE_UNMOVABLE,order));
            /* CMA empty, movable cached: fallback must consume the original list. */
            struct per_cpu_pages pcp={0};
            pcp.lists[mi].page=&normal_page;
            calls=wrong_list=0;
            struct page *got=__rmqueue_pcplist(&z,order,MIGRATE_MOVABLE,ALLOC_CMA,
                                              &pcp,&pcp.lists[mi]);
            if(got!=&normal_page || wrong_list)fallback_fail++;
            /* Restricted, non-CMA request cannot consume cached CMA pages. */
            pcp=(struct per_cpu_pages){0};pcp.lists[ci].page=&cma_page;
            got=__rmqueue_pcplist(&z,order,MIGRATE_MOVABLE,0,&pcp,&pcp.lists[mi]);
            if(got==&cma_page)alias_fail++;
            /* Explicitly eligible requests prefer CMA. */
            pcp=(struct per_cpu_pages){0};pcp.lists[ci].page=&cma_page;
            got=__rmqueue_pcplist(&z,order,MIGRATE_MOVABLE,ALLOC_CMA,&pcp,&pcp.lists[mi]);
            assert(got==&cma_page);
#endif
            /* Unrestricted mode does not redirect the PCP lookup. */
            restricted=false;
            for(int mt=0;mt<MIGRATE_FALLBACKS;mt++) {
                struct per_cpu_pages pcp={0};
                unsigned int index=order_to_pindex(mt,order);
                pcp.lists[index].page=&normal_page;
                calls=wrong_list=0;
                assert(__rmqueue_pcplist(&z,order,mt,0,&pcp,&pcp.lists[index])==&normal_page);
                assert(calls==1 && !wrong_list);cases++;
            }
            restricted=true;
        }
    }
    for(int disabled=0;disabled<2;disabled++) {
        page_group_by_mobility_disabled=disabled;
        for(int mt=0;mt<=MIGRATE_HIGHATOMIC;mt++) {
            struct page page={0};
            init_pageblock_migratetype(&page,mt,false);
            int expected=disabled && mt<MIGRATE_FALLBACKS?MIGRATE_UNMOVABLE:mt;
            if(page.flags!=(unsigned long)expected)init_fail++;
            cases++;
        }
    }
#ifdef OLD_CONTROL
#ifdef CONFIG_CMA
    assert(fallback_fail>0 && init_fail>0);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
    assert(alias_fail>0);
#endif
#else
    assert(!alias_fail && !fallback_fail && !init_fail);
#endif
#else
    assert(!alias_fail && !fallback_fail && !init_fail);
#endif
    printf("cases=%u alias_fail=%u fallback_fail=%u init_fail=%u\n",cases,alias_fail,fallback_fail,init_fail);
}
'''

results=[]
with tempfile.TemporaryDirectory(prefix='ack-cma-pcp-') as t:
    for label,source in [('port',current),('old-control',old)]:
        h=source[paths[1]];c=source[paths[0]]
        enum=h[h.index('enum migratetype {'):h.index('\n};',h.index('enum migratetype {'))+3]
        start=h.index('#ifdef CONFIG_TRANSPARENT_HUGEPAGE\n#define NR_PCP_THP') if label=='old-control' else h.index('#ifdef CONFIG_TRANSPARENT_HUGEPAGE\n#ifdef CONFIG_CMA\n#define NR_PCP_THP')
        defs=h[start:h.index('\n',h.index('#define NR_PCP_LISTS',start))]
        helpers=''.join(function(c,s) for s in ['static inline unsigned int order_to_pindex(', 'static inline int pindex_to_order(', 'static inline bool pcp_allowed_order(', 'void __meminit init_pageblock_migratetype('])
        gettype='\n#ifdef CONFIG_CMA\n#define get_cma_migrate_type() MIGRATE_CMA\n#else\n#define get_cma_migrate_type() MIGRATE_MOVABLE\n#endif\n'
        body=shim+enum+'\n'+defs+gettype+helpers+stub+function(c,'struct page *__rmqueue_pcplist(')+tests
        for cma in (False,True):
            for thp in (False,True):
                f=Path(t)/'check.c';b=Path(t)/'check';f.write_text(body)
                flags=(['-DCONFIG_CMA'] if cma else [])+(['-DCONFIG_TRANSPARENT_HUGEPAGE'] if thp else [])+(['-DOLD_CONTROL'] if label=='old-control' else [])
                subprocess.run(['cc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-Wno-sign-compare','-Werror','-fsanitize=undefined',*flags,str(f),'-o',str(b)],check=True)
                result=subprocess.run([str(b)],capture_output=True,text=True,check=True)
                results.append({'source':label,'cma':cma,'thp':thp,'result':result.stdout.strip()})
report={'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'baseline':baseline,'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in current.items()},'checks':results,'limits':'Extracted selection/setup functions, host list/refill shims and UBSan. No real buddy allocator, CMA reservation, concurrency or kernel runtime tested.'}
a.output.write_text(json.dumps(report,indent=2)+'\n')
for r in results: print(r)
