#!/usr/bin/env python3
"""Host extraction check of saved IRQ-name ownership and disabled-cache capture.

No kernel IRQ registration, allocation, locking, suspend or sysfs operation runs.
"""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = 'kernel/power/wakeup_reason.c'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'


def function(source, name):
    lines = source.splitlines(True)
    for i, line in enumerate(lines):
        if re.search(r'\b' + name + r'\(', line) and not line[0].isspace():
            for j in range(i + 1, len(lines)):
                if lines[j].startswith('}'):
                    return ''.join(lines[i:j + 1])
    raise ValueError(name)


PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#define GFP_ATOMIC 1
#define unlikely(x) (x)
#define pr_warn(...) ((void)0)
#define spin_lock_irqsave(lock, flags) ((void)((flags) = 0))
#define spin_unlock_irqrestore(lock, flags) ((void)(flags))
struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(p) ((p)->next = (p), (p)->prev = (p))
#define list_empty(p) ((p)->next == (p))
#define list_first_entry(p, type, member) ((type *)((char *)(p)->next - offsetof(type, member)))
static void list_del(struct list_head *p) { p->prev->next=p->next; p->next->prev=p->prev; }
static void list_add_tail(struct list_head *p, struct list_head *h) {
 p->next=h; p->prev=h->prev; h->prev->next=p; h->prev=p;
}
struct irqaction { const char *name; };
struct irq_desc { struct irqaction *action; };
static struct irqaction action;
static struct irq_desc desc;
static bool has_desc, fail_name, fail_node;
static int live_names, live_nodes, failures, cases;
static void *owned[64];
static const char *default_irq_name="(unnamed)";
static struct list_head leaf_irqs, parent_irqs;
static void *wakeup_irq_nodes_cache;
static int wakeup_reason;
static bool capture_reasons;
#define RESUME_NONE 0
static struct irq_desc *irq_to_desc(int irq) { (void)irq; return has_desc ? &desc : NULL; }
static __attribute__((unused)) const char *kstrdup_const(const char *s, int gfp) {
 (void)gfp;
 if(s==default_irq_name) return s;
 if(fail_name) return NULL;
 char *p=strdup(s); if(!p) abort();
 for(size_t i=0;i<64;i++) if(!owned[i]) { owned[i]=p; live_names++; return p; }
 abort();
}
static __attribute__((unused)) void kfree_const(const void *p) {
 if(p==default_irq_name) return;
 for(size_t i=0;i<64;i++) if(owned[i]==p) { owned[i]=NULL; live_names--; free((void *)p); return; }
 failures++;
}
'''

SUPPORT = r'''
static void *kmem_cache_alloc(void *cache, int gfp) {
 (void)gfp;
 if(!cache) { failures++; return NULL; }
 if(fail_node) return NULL;
 void *p=calloc(1,sizeof(struct wakeup_irq_node)); if(!p) abort(); live_nodes++; return p;
}
static void kmem_cache_free(void *cache, void *p) { (void)cache; live_nodes--; free(p); }
'''

MAIN = r'''
#define CHECK(x) do { if(!(x)) failures++; } while(0)
int main(void) {
 INIT_LIST_HEAD(&leaf_irqs); INIT_LIST_HEAD(&parent_irqs);
 for(int available=0;available<2;available++) {
  wakeup_irq_nodes_cache=available ? &desc : NULL;
  capture_reasons=true; wakeup_reason=3;
  clear_wakeup_reasons(); CHECK(capture_reasons==available); CHECK(wakeup_reason==RESUME_NONE); cases++;
 }
 size_t lengths[]={0,1,7,63,64,65,127,256,4096};
 for(size_t k=0;k<sizeof(lengths)/sizeof(lengths[0]);k++)
 for(int missing=0;missing<4;missing++)
 for(int failure=0;failure<2;failure++) {
  size_t len=lengths[k]; char *input=malloc(len+1), *expected=malloc(len+1);
  if(!input || !expected) abort();
  memset(input,'A'+k,len); input[len]=0; memcpy(expected,input,len+1);
  has_desc=missing!=1; desc.action=missing==2 ? NULL : &action;
  action.name=missing==3 ? NULL : input; fail_name=failure;
  fail_node=false; struct wakeup_irq_node *p=create_node(21);
  CHECK(p && p->irq==21); if(!p) abort();
  if(!missing && !failure) { CHECK(p->irq_name!=input); memset(input,'Z',len); CHECK(!strcmp(p->irq_name,expected)); }
  else CHECK(!strcmp(p->irq_name,default_irq_name));
  list_add_tail(&p->siblings,(cases&1) ? &leaf_irqs : &parent_irqs);
  clear_wakeup_reasons(); CHECK(list_empty(&leaf_irqs) && list_empty(&parent_irqs));
  CHECK(live_nodes==0 && live_names==0); free(input); free(expected); cases++;
 }
 fail_node=true; CHECK(create_node(21)==NULL); CHECK(!live_names && !live_nodes); cases++;
 /* Both lists can hold separately owned snapshots of the same source name. */
 fail_node=false; fail_name=false; has_desc=true; desc.action=&action;
 char shared[]="shared-name"; action.name=shared;
 for(int i=0;i<20;i++) {
  struct wakeup_irq_node *p=create_node(i); CHECK(p!=NULL); if(!p) abort();
  list_add_tail(&p->siblings,(i&1) ? &leaf_irqs : &parent_irqs);
 }
 clear_wakeup_reasons(); CHECK(!live_nodes && !live_names); cases++;
 printf("{\"cases\":%d,\"failures\":%d}\n",cases,failures);
 return failures ? 1 : 0;
}
'''


def run(source, destination):
    structure = re.search(r'struct wakeup_irq_node \{.*?\n};', source, re.S).group()
    names = ['init_node', 'create_node', 'delete_list', 'clear_wakeup_reasons']
    extracted = '\n'.join(function(source, n) for n in names)
    c = destination.with_suffix('.c')
    c.write_text(PREAMBLE + structure + '\n' + SUPPORT + extracted + MAIN)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-O2', str(c), '-o', str(destination)], check=True)
    completed = subprocess.run([str(destination)], text=True, capture_output=True)
    return completed.returncode, json.loads(completed.stdout), hashlib.sha256(extracted.encode()).hexdigest()


if __name__ == '__main__':
    current = (ROOT / PATH).read_text()
    original = subprocess.check_output(['git', 'show', ACK + ':' + PATH], cwd=ROOT, text=True)
    with tempfile.TemporaryDirectory(prefix='wakeup-name-review-') as temp:
        code, result, digest = run(current, Path(temp) / 'current')
        old_code, old_result, _ = run(original, Path(temp) / 'original')
    assert code == 0 and result['failures'] == 0, result
    assert old_code == 1 and old_result['failures'] > 0, old_result
    report = dict(path=PATH, extracted_sha256=digest, current=result,
                  original_ack_control=old_result,
                  scope='Actual init/create/delete/clear functions with host list, allocator, IRQ descriptor and lock shims. Mutable source-name retirement, full-length snapshots, fallback on allocation failure, missing descriptor/action/name, node failure, both-list cleanup and unavailable-cache capture.',
                  limits='No kernel slab allocator, real read-only-section detection, IRQ registration/teardown, locking/concurrency, suspend or sysfs access. Mutating the source checks ownership without dereferencing freed host memory. The old control is an ownership/fallback/capture failure, not an exploit demonstration.',
                  remote_sources_used=[])
    out = ROOT / 'Documentation/android-port/evidence/wakeup-reason-name-check.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
