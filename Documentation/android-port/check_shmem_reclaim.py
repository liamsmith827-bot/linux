#!/usr/bin/env python3
"""Check extracted shmem reclaim helper with host reference/LRU/batch shims.

Exercises empty/non-shmem mappings, holes/value entries, off-LRU folios, bounded
batches, lookup-reference release before reclaim and return saturation. An old
source control records isolation without an owned lookup reference. No real
XArray, folio concurrency, swap I/O or reclamation is executed.
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
baseline = '745944398038'
def function(t, name):
    start = t.index(name); end = t.index('{', start) + 1; depth = 1
    while depth:
        depth += (t[end] == '{') - (t[end] == '}'); end += 1
    return t[start:end] + '\n'
name = 'int reclaim_shmem_address_space('
current = function((root/'mm/shmem.c').read_text(), name)
old = function(subprocess.check_output(['git','show',baseline+':mm/shmem.c'],cwd=root,text=True),name).replace('reclaim_shmem_address_space(', 'old_reclaim_shmem_address_space(',1)
shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define CAP 5
#define MAX 37
#define min_t(type,a,b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
typedef unsigned long pgoff_t;
struct list_head { struct list_head *next; };
#define LIST_HEAD(n) struct list_head n = { NULL }
struct folio { struct list_head lru; int refs, lookup; bool on_lru; unsigned long pages; };
#define page folio
#define page_folio(p) (p)
struct address_space { bool shmem; struct folio *i_pages[MAX]; unsigned int count; };
struct folio_batch { struct folio *folios[CAP]; unsigned int nr; };
static unsigned int violations, max_isolated, isolated, reclaimed_batches, yielded;
static unsigned long override_reclaim;
static bool shmem_mapping(struct address_space *m) { return m->shmem; }
static void lru_add_drain(void) {}
static void folio_batch_init(struct folio_batch *b) { b->nr=0; }
static unsigned int folio_batch_count(struct folio_batch *b) { return b->nr; }
static bool xa_is_value(struct folio *f) { return f == (void *)1; }
static unsigned int filemap_get_folios(struct address_space *m, pgoff_t *start,
        pgoff_t end, struct folio_batch *b) {
    assert(!b->nr);
    while (*start < m->count && *start <= end && b->nr < CAP) {
        struct folio *f = m->i_pages[(*start)++];
        if (!f || xa_is_value(f) || !f->refs) continue;
        f->refs++; f->lookup++; b->folios[b->nr++] = f;
    }
    return b->nr;
}
static void folio_batch_release(struct folio_batch *b) {
    for (unsigned int i=0;i<b->nr;i++) {
        assert(b->folios[i]->lookup==1 && b->folios[i]->refs>1);
        b->folios[i]->lookup--; b->folios[i]->refs--;
    }
    b->nr=0;
}
static bool folio_isolate_lru(struct folio *f) {
    if (!f->lookup) violations++;
    assert(f->refs>0);
    if (!f->on_lru) return false;
    f->on_lru=false; f->refs++; isolated++;
    if (max_isolated<isolated) max_isolated=isolated;
    return true;
}
static void list_add(struct list_head *e, struct list_head *head) { e->next=head->next; head->next=e; }
static unsigned long reclaim_pages(struct list_head *head) {
    unsigned long pages=0;
    while (head->next) {
        struct list_head *e=head->next; head->next=e->next;
        struct folio *f=(struct folio *)e;
        assert(!f->lookup && f->refs==2 && isolated);
        f->refs--; isolated--; pages+=f->pages;
    }
    reclaimed_batches++;
    return override_reclaim ? override_reclaim : pages;
}
static void cond_resched(void) { yielded++; }
struct xa_state { unsigned int index; struct address_space *m; };
#define XA_STATE(n,p,s) struct xa_state n = { (s), (struct address_space *)((char *)(p)-offsetof(struct address_space,i_pages)) }
#define xas_for_each(x,p,last) for (;(x)->index < (x)->m->count && (x)->index <= (last);(x)->index++) if (((p)=(x)->m->i_pages[(x)->index]))
#define xas_retry(x,p) false
static void rcu_read_lock(void) {}
static void rcu_read_unlock(void) {}
static bool need_resched(void) { return true; }
static void xas_pause(struct xa_state *x) { (void)x; }
static void cond_resched_rcu(void) { yielded++; }
static struct folio folios[MAX];
static void reset(struct address_space *m, unsigned int count, int pattern) {
    *m=(struct address_space){.shmem=true,.count=count};
    violations=max_isolated=isolated=reclaimed_batches=yielded=0; override_reclaim=0;
    for (unsigned int i=0;i<count;i++) {
        folios[i]=(struct folio){.refs=1,.on_lru=pattern!=2 || i%3,.pages=1UL<<(i%4)};
        m->i_pages[i]=pattern==1 && i%4==0 ? NULL : pattern==1 && i%4==1 ? (void *)1 : &folios[i];
    }
}
'''
checks = r'''
int main(void) {
    struct address_space m;
    unsigned int tests=0;
    for (unsigned int count=0;count<=MAX;count++)
    for (int pattern=0;pattern<3;pattern++) {
        reset(&m,count,pattern); unsigned long expected=0;
        for(unsigned int i=0;i<count;i++)
            if(m.i_pages[i] && !xa_is_value(m.i_pages[i]) && m.i_pages[i]->on_lru) expected+=m.i_pages[i]->pages;
        assert(reclaim_shmem_address_space(&m)==(int)expected);
        assert(!violations && !isolated && max_isolated<=CAP && yielded==reclaimed_batches);
        for(unsigned int i=0;i<count;i++) assert(folios[i].refs==1 && !folios[i].lookup);
        tests++;
    }
    reset(&m,MAX,0); m.shmem=false;
    assert(reclaim_shmem_address_space(&m)==-EINVAL && !reclaimed_batches);
    reset(&m,MAX,0);
    assert(old_reclaim_shmem_address_space(&m)>0 && violations==MAX && max_isolated==MAX);
    reset(&m,CAP+1,0); override_reclaim=INT_MAX;
    assert(reclaim_shmem_address_space(&m)==INT_MAX && !violations && !isolated);
    printf("Shmem reclaim ownership/batch checks passed (%u cases); old missing-reference control reproduced\n",tests);
}
'''
program=shim+current+old+checks
with tempfile.TemporaryDirectory(prefix='shmem-reclaim-check-') as tmp:
    src=Path(tmp)/'check.c';binary=Path(tmp)/'check';src.write_text(program)
    flags=['-std=gnu11','-Wall','-Wextra','-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run(['cc',*flags,str(src),'-o',str(binary)],check=True)
    r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
    if r.returncode: raise SystemExit(r.stderr or r.stdout)
record={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'negative_control_commit':subprocess.check_output(['git','rev-parse',baseline],cwd=root,text=True).strip(),
        'excerpts_sha256':hashlib.sha256((current+old).encode()).hexdigest(),'compiler_flags':flags,'result':r.stdout.strip(),'scope':__doc__.strip()}
a.output.write_text(json.dumps(record,indent=2)+'\n');print(record['result'])
