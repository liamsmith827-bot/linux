#!/usr/bin/env python3
"""Exercise extracted MGLRU scan/rotation controls with host policy shims."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[2]
source=(root/'mm/vmscan.c').read_text()
baseline=subprocess.check_output(['git','rev-parse','769c2a3ea3f5'],cwd=root,text=True).strip()
old=subprocess.check_output(['git','show',baseline+':mm/vmscan.c'],cwd=root,text=True)
def function(text,signature):
    start=text.index(signature);end=text.index('{',start)+1;depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]+'\n'
shim=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#define DEF_PRIORITY 12
#define SWAP_CLUSTER_MAX 32UL
#define MEMCG_LRU_YOUNG 2
#define MEMCG_LRU_TAIL 1
#define MEMCG_LOW 0
#define WB_REASON_VMSCAN 0
#define READ_ONCE(x) (x)
#define min(a,b) ((a)<(b)?(a):(b))
#define DEFINE_MAX_SEQ(x) unsigned long max_seq=0
struct mem_cgroup {bool online;};
struct pglist_data {int node_id;};
struct lruvec {struct mem_cgroup *memcg;struct pglist_data *pgdat;struct {int seg;} lrugen;};
struct scan_control {
    struct mem_cgroup *target_mem_cgroup;
    int priority,gfp_mask;bool proactive;
    unsigned long nr_scanned,nr_reclaimed;
    struct {unsigned long unqueued_dirty,file_taken;} nr;
};
static unsigned long size,protection;
static bool aging,bmin,blow,aged,sizable;
static unsigned int scans,evictions,reschedules,flushes,slabs;
static int hook_mode,abort_after;
static struct mem_cgroup *lruvec_memcg(struct lruvec *l) {return l->memcg;}
static struct pglist_data *lruvec_pgdat(struct lruvec *l) {return l->pgdat;}
static bool mem_cgroup_below_min(struct mem_cgroup *a,struct mem_cgroup *b) {(void)a;(void)b;return bmin;}
static bool mem_cgroup_below_low(struct mem_cgroup *a,struct mem_cgroup *b) {(void)a;(void)b;return blow;}
static bool mem_cgroup_online(struct mem_cgroup *m) {return m->online;}
static bool should_run_aging(struct lruvec *l,unsigned long seq,int swap,unsigned long *n) {
    (void)l;(void)seq;(void)swap;scans++;*n=size;return aging;
}
static unsigned long apply_proportional_protection(struct mem_cgroup *m,struct scan_control *sc,unsigned long n) {
    (void)m;(void)sc;return n>protection?n-protection:0;
}
static void trace_android_vh_mglru_aging_bypass(struct lruvec *l,unsigned long seq,int swap,bool *b,bool *y) {
    (void)l;(void)seq;(void)swap;(void)b;(void)y;
}
static bool try_to_inc_max_seq(struct lruvec *l,unsigned long seq,int swap,bool force) {
    (void)l;(void)seq;(void)swap;(void)force;return aged;
}
static int get_swappiness(struct lruvec *l,struct scan_control *sc) {(void)l;(void)sc;return 60;}
static void trace_android_rvh_mglru_shrink_spec_lru(struct lruvec *l,struct scan_control *sc,int swap,
    int *delta,unsigned long n,unsigned long *scanned,bool *bypass) {
    (void)l;(void)sc;(void)swap;(void)n;(void)scanned;
    if(hook_mode==1) {*delta=0;*bypass=true;}
    if(hook_mode==2) {*delta=2;*bypass=true;}
}
static int evict_folios(unsigned long n,struct lruvec *l,struct scan_control *sc,int swap) {
    (void)n;(void)l;(void)sc;(void)swap;evictions++;return 2;
}
static bool should_abort_scan(struct lruvec *l,struct scan_control *sc) {
    (void)l;(void)sc;return abort_after && scans>=(unsigned int)abort_after;
}
static void cond_resched(void) {reschedules++;assert(reschedules<10);}
static void wakeup_flusher_threads(int reason) {(void)reason;flushes++;}
static bool lruvec_is_sizable(struct lruvec *l,struct scan_control *sc) {(void)l;(void)sc;return sizable;}
static void memcg_memory_event(struct mem_cgroup *m,int ev) {(void)m;(void)ev;}
static void shrink_slab(int gfp,int nid,struct mem_cgroup *m,int priority) {(void)gfp;(void)nid;(void)m;(void)priority;slabs++;}
static void vmpressure(int gfp,struct mem_cgroup *m,bool tree,unsigned long scanned,unsigned long reclaimed) {
    (void)gfp;(void)m;(void)tree;(void)scanned;(void)reclaimed;
}
static void flush_reclaim_state(struct scan_control *sc) {(void)sc;}
'''
tests=r'''
static void setup(void) {
    size=16384;protection=0;aging=false;bmin=blow=aged=false;sizable=true;
    scans=evictions=reschedules=flushes=slabs=0;hook_mode=abort_after=0;
}
int main(void) {
    struct mem_cgroup m={.online=true};struct pglist_data pg={0};
    struct lruvec l={.memcg=&m,.pgdat=&pg};struct scan_control sc={.priority=DEF_PRIORITY};
    unsigned int cases=0;
    for(int online=0;online<2;online++) for(int priority=0;priority<=DEF_PRIORITY;priority++) {
        const unsigned long sizes[]={0,1,31,32,4095,4096,16384,65536};
        for(unsigned int i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
            setup();m.online=online;sc.priority=priority;size=sizes[i];
            unsigned long n=size>>priority;
            if(!online && !n)n=min(size,SWAP_CLUSTER_MAX);
            assert(get_nr_to_scan(&l,&sc,60)==(long)n);cases++;
            protection=size;assert(get_nr_to_scan(&l,&sc,60)==0);cases++;
        }
    }
    setup();sc.priority=DEF_PRIORITY;m.online=true;
    assert(!try_to_shrink_lruvec(&l,&sc));assert(evictions==2 && reschedules==1);cases++;
    setup();hook_mode=1;abort_after=3;
    assert(!try_to_shrink_lruvec(&l,&sc));assert(scans==1 && !evictions && !reschedules);cases++;
    setup();hook_mode=1;abort_after=3;
    assert(!old_try_to_shrink_lruvec(&l,&sc));assert(scans==3 && reschedules==2);cases++;
    setup();hook_mode=2;
    assert(!try_to_shrink_lruvec(&l,&sc));assert(scans==2 && !evictions && reschedules==1);cases++;
    setup();hook_mode=1;sc.nr.unqueued_dirty=sc.nr.file_taken=4;
    try_to_shrink_lruvec(&l,&sc);assert(flushes==1);sc.nr.unqueued_dirty=sc.nr.file_taken=0;cases++;
    for(int online=0;online<2;online++) for(int seg=0;seg<=2;seg++) {
        setup();hook_mode=1;m.online=online;l.lrugen.seg=seg;
        int result=shrink_one(&l,&sc);
        assert(result==(online?0:(seg==MEMCG_LRU_TAIL?MEMCG_LRU_YOUNG:MEMCG_LRU_TAIL)));
        assert(slabs==1);cases++;
    }
    setup();bmin=true;assert(shrink_one(&l,&sc)==MEMCG_LRU_YOUNG && !slabs);cases++;
    setup();aging=aged=true;sc.priority=0;
    assert(get_nr_to_scan(&l,&sc,60)==-1);cases++;
    printf("%u scan/rotation/progress cases passed, including the old zero-progress repeat control\n",cases);
}
'''
body=shim+function(source,'static long get_nr_to_scan(')+function(source,'static bool try_to_shrink_lruvec(')+function(source,'static int shrink_one(')+function(old,'static bool try_to_shrink_lruvec(').replace('try_to_shrink_lruvec','old_try_to_shrink_lruvec',1)+tests
with tempfile.TemporaryDirectory(prefix='ack-mglru-policy-') as t:
    f=Path(t)/'check.c';b=Path(t)/'check';f.write_text(body)
    subprocess.run(['cc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Wno-sign-compare','-Werror','-fsanitize=undefined',str(f),'-o',str(b)],check=True)
    r=subprocess.run([str(b)],text=True,capture_output=True,check=True)
report={'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'baseline':baseline,'result':r.stdout.strip(),'limits':'Extracted scan/rotation functions with host aging/reclaim/cgroup shims and UBSan. No actual LRU lists, reclaim, pressure, races or running Android policy tested.'}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(report['result'])
