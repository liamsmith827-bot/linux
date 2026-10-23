#!/usr/bin/env python3
"""Check actual fair placement and enqueue flags in a small host model.

The model fixes nice=0, virtual time=1000 and disables lag compensation. It tests
initial versus synchronous placement and relative-deadline precedence. This is
not scheduler execution, contention, performance or userspace compatibility proof.
"""
import ctypes
import hashlib
import itertools
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
CONTROL = 'faad9f616aa9f339512f7123914957a052992a7c'
PRE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef uint64_t u64;
typedef int64_t s64;
struct load_weight { unsigned long weight; };
struct sched_entity { bool custom_slice, on_rq, rel_deadline; u64 slice, vruntime, deadline; s64 vlag; struct load_weight load; };
struct cfs_rq { unsigned nr_queued; long sum_weight; struct sched_entity *curr; };
static unsigned long sysctl_sched_base_slice=100;
#define sched_feat(n) feature_##n
static bool feature_PLACE_LAG=false, feature_PLACE_REL_DEADLINE=true, feature_PLACE_DEADLINE_INITIAL;
#define scale_load_down(w) (w)
#define WARN_ON_ONCE(x) (x)
#define div_s64(x,y) ((x)/(y))
static u64 avg_vruntime(struct cfs_rq *rq) { return 1000; }
static u64 calc_delta_fair(u64 slice, struct sched_entity *se) { return slice; }
static void trace_android_rvh_place_entity(struct cfs_rq *rq, struct sched_entity *se, int flags, u64 *vruntime) {}
'''
WRAP = r'''
void probe(int initial, int sync, int feature, int custom, int relative, u64 *out) {
 struct cfs_rq rq = {0};
 struct sched_entity se = {.custom_slice=custom,.slice=200,.deadline=17,.rel_deadline=relative};
 int flags=ENQUEUE_NOCLOCK | (initial ? ENQUEUE_INITIAL : ENQUEUE_WAKEUP);
 if(sync) flags|=ENQUEUE_WAKEUP_SYNC;
 feature_PLACE_DEADLINE_INITIAL=feature;
 place_entity(&rq,&se,flags);
 out[0]=se.deadline; out[1]=se.slice; out[2]=se.rel_deadline;
 out[3]=!!(flags & ENQUEUE_WAKEUP_SYNC);
 out[4]=!!(flags & ENQUEUE_INITIAL);
}
'''


def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    cases = list(itertools.product(range(2), repeat=5))
    expected = []
    for initial, sync, feature, custom, relative in cases:
        size = 200 if custom else 100
        delta = 17 if relative else size // (2 if initial and feature else 1)
        expected.append([1000 + delta, size, 0, sync, initial])
    source = (ROOT / 'kernel/sched/fair.c').read_text()
    body = function(source, 'place_entity')
    assert 'static void\n' + body in source
    body = 'static void\n' + body
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=CONTROL,
                  cases=len(cases), scope=__doc__, results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='sync-enqueue-') as tmp:
        for label, header in [('port', (ROOT / 'kernel/sched/sched.h').read_text()),
                              ('pre_fix_control', git('show', CONTROL + ':kernel/sched/sched.h'))]:
            defines = re.findall(r'^#define ENQUEUE_\w+\s+0x[0-9a-fA-F]+', header, re.M)
            flags = {line.split()[1]: int(line.split()[2], 16) for line in defines}
            if label == 'port':
                assert all(not (value & flags['ENQUEUE_WAKEUP_SYNC'])
                           for name,value in flags.items() if name != 'ENQUEUE_WAKEUP_SYNC')
            code = PRE + '\n'.join(defines) + '\n' + body + WRAP
            path = Path(tmp) / (label + '.c'); path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror', str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_int] * 5 + [ctypes.POINTER(ctypes.c_uint64)]
            probe.restype = None
            failures, placement = [], []
            for i,c in enumerate(cases):
                out = (ctypes.c_uint64 * 5)(); probe(*c, out)
                if list(out) != expected[i]: failures.append(i)
                if out[0] != expected[i][0]: placement.append(i)
            report['results'][label] = dict(failures=len(failures),
                deadline_mismatches=len(placement), flags=flags,
                function_sha256=hashlib.sha256(body.encode()).hexdigest(),
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['deadline_mismatches'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT / 'Documentation/android-port/evidence/sync-enqueue-flag-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
