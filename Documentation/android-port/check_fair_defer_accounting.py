#!/usr/bin/env python3
"""Exercise extracted update_deadline/avg_vruntime during vendor deferral.

The host model has a current entity and optionally one fixed queued entity.
Compare zero_vruntime to the independent weighted-average oracle at expiration,
while checking that deferral leaves the deadline unchanged and returns false.
No actual scheduler, rb-tree, locking, PELT or runtime-latency verification.
"""
import ctypes
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path

from check_scx_donor_retry import function
from check_fair_eligibility import git, MASK

ROOT = Path(__file__).resolve().parents[2]
CONTROL = '4f317b026e1797258b44067faba2d0e97aa71361'
PRE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef int64_t s64;
typedef uint64_t u64;
struct load_weight { unsigned long weight; };
struct sched_entity { bool on_rq, custom_slice; u64 vruntime, deadline, slice; struct load_weight load; };
struct cfs_rq { struct sched_entity *curr; s64 sum_w_vruntime; long sum_weight; u64 zero_vruntime; };
#define SCHED_FIXEDPOINT_SHIFT 10
#define max(a,b) ((a) > (b) ? (a) : (b))
#define div_s64(a,b) ((s64)(a) / (int32_t)(b))
static bool defer;
static unsigned long sysctl_sched_base_slice = 1000;
static u64 calc_delta_fair(u64 slice, struct sched_entity *se) { return slice; }
static void trace_android_rvh_update_deadline(struct cfs_rq *rq, struct sched_entity *se, bool *skip) { *skip = defer; }
'''
WRAP = r'''
void probe(u64 base, int offset, int other, int custom, int step, int mode, u64 *out) {
 struct sched_entity se = { .on_rq=true, .custom_slice=custom, .vruntime=base+offset,
  .deadline=base+100, .slice=100, .load.weight=1024UL << 10 };
 struct cfs_rq rq = { .curr=&se, .sum_w_vruntime=37L * other,
  .sum_weight=other, .zero_vruntime=base };
 for (int i=0; i<12; i++) {
  defer = mode==1 || (mode==2 && i<6);
  out[i*4] = update_deadline(&rq, &se);
  out[i*4+1] = rq.zero_vruntime;
  out[i*4+2] = se.deadline;
  out[i*4+3] = se.slice;
  se.vruntime += step;
 }
}
'''

def main():
    head = git('rev-parse', 'HEAD').strip()
    current = (ROOT / 'kernel/sched/fair.c').read_text()
    old = git('show', CONTROL + ':kernel/sched/fair.c')
    header = (ROOT / 'kernel/sched/sched.h').read_text()
    start = header.index('# define scale_load_down(w)')
    scale = header[start:header.index('#else', start)]
    cases = list(itertools.product([0, MASK - 700], [-50, 0, 99, 100, 150],
                 [0, 2048], [0, 1], [1, 50, 500], [0, 1, 2]))
    expected = []
    for base, offset, other, custom, step, mode in cases:
        zero, deadline, value, size = base, base+100, base+offset, 100
        result = []
        for i in range(12):
            defer = mode == 1 or (mode == 2 and i < 6)
            expired = value >= deadline
            if expired:
                zero = ((base+37) * other + value * 1024) // (other+1024)
                if not defer:
                    if not custom:
                        size = 1000
                    deadline = value + size
            result.extend([int(expired and not defer), zero & MASK, deadline & MASK, size])
            value += step
        expected.append(result)
    report = dict(source_head=head, control=CONTROL, cases=len(cases), steps_per_case=12,
                  scope=__doc__, results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='fair-defer-') as tmp:
        for label, source in [('port', current), ('pre_fix_control', old)]:
            macros = source[source.index('extern void __BUILD_BUG_vruntime_cmp'):source.index('static inline __maybe_unused u64 max_vruntime')]
            names = ['entity_key', 'update_zero_vruntime', 'avg_vruntime', 'update_deadline']
            bodies = [function(source, n) for n in names]
            code = PRE + scale + macros + '\n'.join(bodies) + WRAP
            path = Path(tmp) / (label + '.c'); path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-fwrapv', str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_uint64, *([ctypes.c_int] * 5), ctypes.POINTER(ctypes.c_uint64)]
            probe.restype = None
            failures = []
            for i, args in enumerate(cases):
                out = (ctypes.c_uint64 * 48)(); probe(*args, out)
                if list(out) != expected[i]:
                    failures.append(i)
            report['results'][label] = dict(failures=len(failures),
                first_failure_inputs=cases[failures[0]] if failures else None,
                functions={n:hashlib.sha256(f.encode()).hexdigest() for n,f in zip(names,bodies)},
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['failures'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT / 'Documentation/android-port/evidence/fair-defer-accounting-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
