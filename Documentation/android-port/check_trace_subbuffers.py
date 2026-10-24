#!/usr/bin/env python3
"""Host checks of extracted trace-buffer sizing; no tracing or mmap execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
OLD = 'af1e8554749e'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True)

def source(ref, path):
    return (ROOT/path).read_text() if ref == 'worktree' else git('show', ref+':'+path)

def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()

prelude = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#define __user
static int physical_shift, reported_shift, parse_error;
static unsigned long input;
#define PAGE_SIZE (1UL << physical_shift)
#define __PAGE_SIZE (1UL << reported_shift)
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
struct trace_array { int unused; };
struct file { struct trace_array *private_data; };
struct lock_class_key { int unused; };
struct trace_buffer { int order; unsigned long size; unsigned flags; };
static struct trace_buffer allocated;
static int fls(unsigned int v) { return v ? 32 - __builtin_clz(v) : 0; }
static int get_order(unsigned long bytes) {
 return fls((bytes-1) >> physical_shift);
}
static int kstrtoul_from_user(const char *s, size_t n, int base, unsigned long *v) {
 *v=input; return parse_error;
}
static struct trace_buffer *alloc_buffer(unsigned long size, unsigned flags,
 int order, unsigned long start, unsigned long end, unsigned long scratch,
 struct lock_class_key *key) {
 assert(!start && !end && !scratch && key);
 allocated=(struct trace_buffer){order,size,flags}; return &allocated;
}
'''

parts = [prelude]
fingerprints = {}
for ref, tag in [('worktree', 'new'), (OLD, 'old'), (LTS, 'lts'), (ACK, 'ack')]:
    whole = function(source(ref, 'kernel/trace/trace.c'), 'buffer_subbuf_size_write')
    before, after = whole.split('\t/* Do not allow tracing while changing the order', 1)
    if ref == 'worktree':
        native = function(source(LTS, 'kernel/trace/trace.c'), 'buffer_subbuf_size_write')
        assert after == native.split('\t/* Do not allow tracing while changing the order', 1)[1]
    prefix = 'static ssize_t\n' + before.replace('buffer_subbuf_size_write', 'size_'+tag)
    parts.append(prefix+'\treturn order;\n}\n')
    fingerprints[tag] = {'function_sha256': sha(whole), 'prefix_sha256': sha(before)}

for ref, tag in [('worktree', 'new'), (OLD, 'old')]:
    whole = function(source(ref, 'kernel/trace/ring_buffer.c'), '__ring_buffer_alloc')
    parts.append(whole.replace('__ring_buffer_alloc', 'alloc_'+tag))
    fingerprints[tag]['allocation_function_sha256'] = sha(whole)

assert function(source('worktree', 'kernel/trace/trace.c'), 'allocate_trace_buffer').replace(
    'ring_buffer_alloc_range(size, rb_flags, get_order(__PAGE_SIZE),',
    'ring_buffer_alloc_range(size, rb_flags, 0,') == function(
        source(LTS, 'kernel/trace/trace.c'), 'allocate_trace_buffer')
assert source('worktree', 'kernel/trace/ring_buffer.c').replace(
    '#include <linux/page_size_compat_defs.h>\n', '').replace(
    '/* Match the page size presented to Android tracing readers. */',
    '/* Default buffer page size - one system page */').replace(
    'alloc_buffer(size, flags, get_order(__PAGE_SIZE), 0, 0, 0, key)',
    'alloc_buffer(size, flags, 0, 0, 0, 0, key)') == source(LTS, 'kernel/trace/ring_buffer.c')

parts.append(r'''
static unsigned long tests, native_equal, ack_equal, old_small, old_wrap, allocs;
static void test(unsigned long kb) {
 struct trace_array tr={0}; struct file f={&tr}; loff_t pos=0;
 input=kb;
 int got=size_new(&f, "", 1, &pos);
 unsigned long limit=(PAGE_SIZE << 7)/1024;
 int expected=-EINVAL;
 if (kb && kb<=limit) {
  unsigned long bytes=__PAGE_SIZE;
  while (bytes<kb*1024) bytes*=2;
  expected=get_order(bytes);
 }
 assert(got==expected); tests++;
 if (kb<=limit) {
  assert(size_ack(&f, "", 1, &pos)==expected); ack_equal++;
  if (physical_shift==reported_shift) {
   assert(size_lts(&f, "", 1, &pos)==expected); native_equal++;
  } else if (kb && size_old(&f, "", 1, &pos)<expected) old_small++;
 }
 if (kb>limit && size_old(&f, "", 1, &pos)>=0) old_wrap++;
}
int main(void) {
 assert(sizeof(unsigned long)==8);
 for (physical_shift=12; physical_shift<=16; physical_shift+=2) {
  for (reported_shift=physical_shift; reported_shift<=16; reported_shift+=2) {
   if (reported_shift!=physical_shift && !(physical_shift==12 && reported_shift==14)) continue;
   unsigned long limit=(PAGE_SIZE << 7)/1024;
   for (unsigned long v=0; v<=limit+2; v++) test(v);
   for (int bit=0; bit<64; bit++) {
    unsigned long v=1UL<<bit;
    test(v-1); test(v); if(v<ULONG_MAX) test(v+1);
   }
   test(ULONG_MAX);
   struct trace_array tr={0}; struct file f={&tr}; loff_t pos=0;
   parse_error=-EFAULT; input=16;
   assert(size_new(&f,"",1,&pos)==-EFAULT); parse_error=0;
   struct lock_class_key key={0};
   for (unsigned long size=0; size<=65536; size+=4096) {
    struct trace_buffer *b=alloc_new(size, 3, &key);
    assert((PAGE_SIZE << b->order)==__PAGE_SIZE && b->size==size && b->flags==3);
    b=alloc_old(size,3,&key); assert(b->order==0); allocs++;
   }
  }
 }
 assert(old_small && old_wrap);
 printf("{\"size_cases\":%lu,\"native_valid_equal\":%lu,\"ack_valid_equal\":%lu,"
        "\"old_too_small\":%lu,\"old_overflow_accepted\":%lu,\"allocation_cases\":%lu}\n",
        tests,native_equal,ack_equal,old_small,old_wrap,allocs);
}
''')

with tempfile.TemporaryDirectory(prefix='trace-subbuf-check-') as td:
    td = Path(td)
    cfile, exe = td/'test.c', td/'test'
    cfile.write_text('\n'.join(parts))
    subprocess.run(['cc', '-O1', '-g', '-fno-strict-overflow', '-Wall', '-Wextra', '-Wno-unused-parameter',
                    '-Wno-unused-variable', '-Werror', '-fsanitize=undefined,address',
                    '-fno-sanitize-recover=all', str(cfile), '-o', str(exe)], check=True)
    counts = json.loads(subprocess.check_output([str(exe)], text=True))

report = {'source_head_before_changes': git('rev-parse', 'HEAD').strip(),
          'old': git('rev-parse', OLD).strip(), 'lts': LTS, 'ack': ACK,
          'counts': counts, 'function_fingerprints': fingerprints,
          'preservation': 'Whole ring_buffer.c differs from LTS only by emulated default allocation order and header/comment; trace allocation differs only by range order; size-write locking/snapshot/rollback suffix exactly equals LTS.',
          'scope': 'ASan/UBSan extracted size-parsing prefix and allocation-wrapper tests, with mocked parsing/allocation and kernel Makefile -fno-strict-overflow semantics. An initial run without that kernel flag diagnosed signed page-count overflow in the old control; the bounded new path avoids the narrowing. Valid size choices match ACK; native mode valid choices match LTS. No kernel tracing, mmap, boot, Perfetto or concurrent test.',
          'remote_sources_used': []}
(ROOT/'Documentation/android-port/evidence/trace-subbuffers-check.json').write_text(
    json.dumps(report, indent=2)+'\n')
print(json.dumps(counts))
