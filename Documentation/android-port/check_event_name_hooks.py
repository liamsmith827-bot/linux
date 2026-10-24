#!/usr/bin/env python3
"""Exercise extracted epoll/timerfd naming code with modeled callback writers.

This is a host string/control-flow check, not kernel wakeup or timer validation.
"""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
OLD = 'e6bc4ab2483f740e7eea0ad93e401265758636cc'

PRE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ENOMEM 12
#define rcu_assign_pointer(a, b) ((a) = (b))
struct wakeup_source { int unused; } sources[3];
struct file { struct { void *dentry; } f_path; } file;
struct eventpoll { struct wakeup_source *ws; } ep;
struct epitem { struct eventpoll *ep; struct { struct file *file; } ffd; struct wakeup_source *ws; } item;
struct name_snapshot { struct { const char *name; } name; };
static char input_name[1024];
static int enabled, mode, calls, failure, checks, failures, padded_failures, unterminated, truncated;
static size_t strscpy(char *dst, const char *src, size_t size) {
 size_t n = strlen(src); if (n >= size) n = size - 1;
 memcpy(dst, src, n); dst[n] = 0; return n;
}
static size_t strscpy_pad(char *dst, const char *src, size_t size) {
 size_t n = strscpy(dst, src, size); memset(dst+n, 0, size-n); return n;
}
static void take_dentry_name_snapshot(struct name_snapshot *n, void *d) { (void)d; n->name.name=input_name; }
static void release_dentry_name_snapshot(struct name_snapshot *n) { (void)n; }
static int trace_android_vh_ep_create_wakeup_source_enabled(void) { return enabled; }
static void callback(char *name, int len) {
 if (!enabled) return;
 size_t n = strnlen(name, len);
 for (size_t i=n; i<(size_t)len; ++i) if (name[i]) { padded_failures++; failure=1; break; }
 if (mode==1) strscpy(name, "custom", len);
 if (mode==2) memset(name, 'x', len);
 if (mode==3) name[0]=0;
 if (mode==4) name[0]='z';
}
static void trace_android_vh_ep_create_wakeup_source(char *n, int len) { callback(n,len); }
static void trace_android_vh_timerfd_create(char *n, int len) { callback(n,len); }
static struct wakeup_source *wakeup_source_register(void *dev, const char *name) {
 (void)dev;
 size_t limit=name==input_name ? sizeof(input_name) : 64;
 size_t n=strnlen(name,limit);
 if (n==limit) { failure=1; unterminated++; }
 if (!enabled && calls==1 && n!=strlen(input_name)) { failure=1; truncated++; }
 if (enabled && mode==1 && strcmp(name,"custom")) failure=1;
 if (enabled && mode==3 && n) failure=1;
 return &sources[calls++];
}
'''
POST = r'''
int main(void) {
 item.ep=&ep; item.ffd.file=&file;
 for (int length=0; length<=512; ++length)
 for (enabled=0; enabled<=1; ++enabled)
 for (mode=0; mode<5; ++mode)
 for (int existing=0; existing<2; ++existing) {
  memset(input_name,'a',length); input_name[length]=0;
  ep.ws=existing ? &sources[0] : NULL; calls=existing; failure=0;
  if (ep_create_wakeup_source(&item) || calls!=2 || item.ws!=&sources[1]) failure=1;
  checks++; failures+=!!failure;
 }
 for (enabled=0; enabled<=1; ++enabled)
 for (mode=0; mode<5; ++mode) {
  failure=0; timer_name(); checks++; failures+=!!failure;
 }
 printf("{\"cases\":%d,\"failed_cases\":%d,\"nonzero_tail_observations\":%d,\"unterminated_observations\":%d,\"inactive_name_truncations\":%d}\n",checks,failures,padded_failures,unterminated,truncated);
 return 0;
}
'''

def extract(ref):
    def read(p):
        return subprocess.check_output(['git', 'show', ref + ':' + p], cwd=ROOT, text=True)
    epoll = function(read('fs/eventpoll.c'), 'ep_create_wakeup_source')
    timer = read('fs/timerfd.c')
    start = timer.index('\tstrscpy', timer.index('SYSCALL_DEFINE2(timerfd_create'))
    end = timer.index('\tfile = anon_inode_getfile_fmode', start)
    block = timer[start:end]
    timer = '''static void timer_name(void) {
 char file_name_buf[32];
''' + block + '''
 size_t n=strnlen(file_name_buf,sizeof(file_name_buf));
 if (n==sizeof(file_name_buf)) { failure=1; unterminated++; }
 if (!enabled && strcmp(file_name_buf,"[timerfd]")) failure=1;
 if (enabled && mode==1 && strcmp(file_name_buf,"custom")) failure=1;
 if (enabled && mode==3 && n) failure=1;
}
'''
    return epoll, block, timer

head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
results = {}
with tempfile.TemporaryDirectory(prefix='event-name-hooks-') as tmp:
    tmp = Path(tmp)
    for label, ref in [('port', head), ('old_control', OLD)]:
        epoll, block, timer = extract(ref)
        src = tmp / (label + '.c')
        exe = tmp / label
        src.write_text(PRE + epoll + timer + POST)
        subprocess.run(['cc', '-O1', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-ftrivial-auto-var-init=pattern', str(src), '-o', str(exe)], check=True)
        result = json.loads(subprocess.check_output([str(exe)], text=True))
        result.update(ref=ref, epoll_function_sha256=hashlib.sha256(epoll.encode()).hexdigest(), timer_block_sha256=hashlib.sha256(block.encode()).hexdigest())
        results[label] = result
assert results['port']['failed_cases'] == 0, results
assert results['old_control']['unterminated_observations'] > 0, results
assert results['old_control']['inactive_name_truncations'] > 0, results
record = dict(source_head=head, results=results, scope='Extracted whole ep_create_wakeup_source and timerfd name preparation block. Host stubs model string copies, registrations and callbacks only. Lengths 0..512, absent/present hook, existing/new epoll source, no-op/custom/full-buffer non-NUL/empty/partial writers. Pattern stack initialization intentionally exposes unwritten tails in the old control; SDK zero initialization is not claimed to have leaked data. No actual wakeup, alarm, timer, concurrent hook registration or userspace behavior was executed.', remote_sources_used=[])
(Path(__file__).resolve().parent / 'evidence/event-name-hook-check.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
