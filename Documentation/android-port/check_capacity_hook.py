#!/usr/bin/env python3
"""Exercise the extracted capacity update with callback-produced zero values.

Models leaf capacity storage and a guarded load division; does not execute the
kernel scheduler or claim a reproduced runtime divide fault.
"""
import ctypes
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
PRE = r'''
struct sched_group_capacity { unsigned long capacity, min_capacity, max_capacity; };
struct sched_group { struct sched_group_capacity *sgc; };
struct sched_domain { struct sched_group *groups; };
struct rq { unsigned long cpu_capacity; };
static struct rq runq;
static unsigned long native, replacement, observed, traced;
static int enabled, calls;
static unsigned long scale_rt_capacity(int cpu) { return native; }
static struct rq *cpu_rq(int cpu) { return &runq; }
static void trace_android_rvh_update_cpu_capacity(int cpu, unsigned long *v) {
 observed = *v; calls++; if (enabled) *v = replacement;
}
static void trace_sched_cpu_capacity_tp(struct rq *rq) { traced = rq->cpu_capacity; }
'''
POST = r'''
void probe(unsigned long value, int active, unsigned long result, unsigned long *out) {
 struct sched_group_capacity gc = {0};
 struct sched_group group = {&gc};
 struct sched_domain sd = {&group};
 native=value; enabled=active; replacement=result; calls=0;
 update_cpu_capacity(&sd, 0);
 out[0]=runq.cpu_capacity; out[1]=gc.capacity; out[2]=gc.min_capacity;
 out[3]=gc.max_capacity; out[4]=traced; out[5]=observed; out[6]=calls;
 out[7]=gc.capacity ? 1048576UL/gc.capacity : ~0UL;
}
'''

def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    control = git('rev-parse', '43b0da438cfd').strip()
    path = 'kernel/sched/fair.c'
    values = [0, 1, 2, 511, 1023, 1024, 1025, 4096, (1 << 64) - 1]
    cases = list(itertools.product(values, range(2), values))
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=control,
                  scope=__doc__, cases=len(cases), results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='capacity-hook-') as tmp:
        for label, source in [('port', (ROOT/path).read_text()),
                              ('pre_fix_control', git('show', control+':'+path))]:
            body = function(source, 'update_cpu_capacity')
            code = PRE + body + POST
            c = Path(tmp)/(label+'.c'); c.write_text(code)
            lib = c.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror', str(c), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            probe.restype = None
            failures = zero_divisors = 0
            for value, active, result in cases:
                out = (ctypes.c_ulong*8)(); probe(value, active, result, out)
                expected = max(result if active else value, 1)
                failures += list(out) != [expected]*5 + [max(value, 1), 1, 1048576//expected]
                zero_divisors += out[1] == 0
            report['results'][label] = dict(failures=failures, zero_divisors=zero_divisors,
                function_sha256=hashlib.sha256(body.encode()).hexdigest(),
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['zero_divisors'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT/'Documentation/android-port/evidence/capacity-hook-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
