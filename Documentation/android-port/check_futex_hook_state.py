#!/usr/bin/env python3
"""Exercise extracted futex_wake with mocked buckets and optional vendor hooks."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
OLD = '0fe6c3c8db36'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'

def at(ref):
    return subprocess.check_output(['git', 'show', ref+':kernel/futex/waitwake.c'], cwd=ROOT, text=True)

new = function((ROOT/'kernel/futex/waitwake.c').read_text(), 'futex_wake')
old = function(at(OLD), 'futex_wake')
native = function(at(LTS), 'futex_wake')
assert old.replace('int target_nr;', 'int target_nr = nr_wake;') == new

shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define __user
typedef uint32_t u32;
union futex_key { int id; };
#define FUTEX_KEY_INIT {0}
#define FUTEX_READ 0
#define FLAGS_STRICT 1
#define unlikely(v) (v)
struct wake_q_head { int unused; };
#define DEFINE_WAKE_Q(v) struct wake_q_head v={0}
struct task_struct { int id; };
struct futex_q { union futex_key key; int pi_state,rt_waiter; u32 bitset;
 struct task_struct *task; void (*wake)(struct wake_q_head *,struct futex_q *); };
static struct task_struct tasks[4];
static struct futex_q entries[4];
struct plist_head { int unused; };
struct futex_hash_bucket { int lock; struct plist_head chain; };
static struct futex_hash_bucket bucket;
struct fake_hash { struct futex_hash_bucket *hb; };
static struct fake_hash get_hash(union futex_key *k) { return (struct fake_hash){&bucket}; }
#define CLASS(type,var) struct fake_hash var = get_hash
#define plist_for_each_entry_safe(this,next,chain,list) \
 for(int i=0; i<4 && ((this)=&entries[i],(next)=NULL,true); i++)
static int error,pending,mask,override_target,locked,wake_mask,callbacks,bad_targets,expected_target;
static int get_futex_key(u32 *addr,unsigned flags,union futex_key *k,int type) { k->id=1; return error; }
static bool futex_hb_waiters_pending(struct futex_hash_bucket *hb) { return pending; }
static bool futex_match(union futex_key *a, union futex_key *b) { return a->id==b->id; }
static void spin_lock(int *p) { assert(!locked); locked=1; }
static void spin_unlock(int *p) { assert(locked); locked=0; }
static void wake_up_q(struct wake_q_head *q) { assert(!locked); }
static void wake(struct wake_q_head *w,struct futex_q *q) { assert(locked); wake_mask |= 1<<q->task->id; }
static void trace_android_vh_futex_wake_traverse_plist(struct plist_head *c,int *n,union futex_key k,u32 b) {
 assert(locked); if(mask&1) *n=override_target;
}
static void trace_android_vh_futex_wake_this(int ret,int n,int target,struct task_struct *p) {
 assert(locked); if(mask&2) { callbacks++; if(target!=expected_target) bad_targets++; }
}
static void trace_android_vh_futex_wake_up_q_finish(int n,int target) {
 assert(!locked); if(mask&4) { callbacks++; if(target!=expected_target) bad_targets++; }
}
'''

def adapt(body, name):
    return body.replace('futex_wake(', name+'(', 1).replace('auto hb = hbr.hb;', 'struct futex_hash_bucket *hb = hbr.hb;')

# Defined poison models an unset callback output without evaluating undefined C.
poisoned = old.replace('int target_nr;', 'int target_nr = INT_MIN;')
main = r'''
int main(void) {
 unsigned long cases=0,old_failures=0,observations=0;
 u32 addr=0;
 for(error=0; error>=-1; error--)
 for(pending=0; pending<2; pending++)
 for(unsigned flags=0;flags<2;flags++)
 for(int nr=-1;nr<=5;nr++)
 for(u32 bits=0;bits<4;bits++)
 for(int layout=0;layout<8;layout++)
 for(mask=0;mask<8;mask++)
 for(override_target=-1;override_target<=1;override_target++) {
  for(int i=0;i<4;i++) {
   tasks[i].id=i;
   entries[i]=(struct futex_q){.key={i==0 && (layout&1)?2:1},
    .pi_state=(layout&2) && i==2,.rt_waiter=(layout&4) && i==1,
    .bitset=(i&1)?2:1,.task=&tasks[i],.wake=wake};
  }
  expected_target=(mask&1)?override_target:nr;
  wake_mask=callbacks=bad_targets=0;
  int got=new_wake(&addr,flags,nr,bits),got_mask=wake_mask;
  assert(!locked && !bad_targets); observations+=callbacks;
  wake_mask=0;
  int want=native_wake(&addr,flags,nr,bits);
  assert(got==want && got_mask==wake_mask && !locked);
  wake_mask=callbacks=bad_targets=0;
  assert(old_wake(&addr,flags,nr,bits)==want && wake_mask==got_mask && !locked);
  if(bad_targets) old_failures++;
  cases++;
 }
 assert(old_failures && observations);
 printf("{\"cases\":%lu,\"callback_observations\":%lu,\"old_unset_output_failures\":%lu}\n",cases,observations,old_failures);
}
'''

with tempfile.TemporaryDirectory(prefix='futex-hook-state-') as td:
    td = Path(td)
    c, exe = td/'test.c', td/'test'
    c.write_text(shim+adapt(new, 'new_wake')+adapt(poisoned, 'old_wake')+adapt(native, 'native_wake')+main)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-parameter', '-Wno-unused-but-set-variable',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(c), '-o', str(exe)], check=True)
    counts = json.loads(subprocess.check_output([str(exe)], text=True))
report = {'old': OLD, 'native': LTS, 'counts': counts,
          'new_function_sha256': hashlib.sha256(new.encode()).hexdigest(),
          'scope': 'ASan/UBSan whole extracted futex_wake with mocked buckets, locks, wake functions and independently registered hooks; exact native return and wake-mask comparisons. Old control substitutes INT_MIN for otherwise undefined uninitialized target_nr. auto declaration is spelled explicitly for the host compiler. No kernel futex, scheduler or concurrency execution.',
          'remote_sources_used': []}
(ROOT/'Documentation/android-port/evidence/futex-hook-state-check.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(counts))
