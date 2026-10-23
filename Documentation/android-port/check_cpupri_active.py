#!/usr/bin/env python3
"""Check the extracted CPU-priority mask helper against a four-CPU set oracle.

Exhaust all static priority-vector, affinity and active masks, with/without an
execution task and output mask. Barriers and atomic counts are modeled, not
concurrent; this does not reproduce hotplug, prove chain lifetime or boot a kernel.
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
CONTROL = '00025a40da57'
PRE = r'''
#include <stddef.h>
struct cpumask { unsigned bits; };
struct task_struct { struct cpumask cpus_mask; };
struct cpupri_vec { int count; struct cpumask *mask; };
struct cpupri { struct cpupri_vec pri_to_cpu[1]; };
static struct cpumask active;
#define cpu_active_mask (&active)
#define nr_cpu_ids 4
#define atomic_read(p) (*(p))
#define smp_rmb() ((void)0)
static unsigned cpumask_any(const struct cpumask *m) { return m->bits ? __builtin_ctz(m->bits) : 4; }
static unsigned cpumask_any_and(const struct cpumask *a, const struct cpumask *b) {
 struct cpumask m = { a->bits & b->bits }; return cpumask_any(&m);
}
static void cpumask_and(struct cpumask *d, const struct cpumask *a, const struct cpumask *b) { d->bits=a->bits & b->bits; }
static void cpumask_copy(struct cpumask *d, const struct cpumask *s) { *d=*s; }
static int cpumask_empty(const struct cpumask *m) { return !m->bits; }
'''
WRAP = r'''
unsigned probe(unsigned vector, unsigned allowed, unsigned online, int count, int has_task, int output) {
 struct cpumask v = { vector }, result = { 0xff };
 struct task_struct task = { .cpus_mask = { allowed } };
 struct cpupri cp = { .pri_to_cpu = { { count, &v } } };
 active.bits=online;
 int ok = __cpupri_find(&cp, has_task ? &task : NULL, output ? &result : NULL, 0);
 return ok ? 0x100 | (output ? result.bits : 0) : 0;
}
'''


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True)


def main():
    old = git('rev-parse', CONTROL).strip()
    cases = list(itertools.product(range(16), range(16), range(16), range(2), range(2), range(2)))
    expected = []
    for vector, allowed, active, count, task, output in cases:
        selected = vector & (allowed if task else 15)
        if output:
            selected &= active
        expected.append((0x100 | (selected if output else 0)) if count and selected else 0)
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=old,
                  cases=len(cases), scope=__doc__, results={}, remote_sources_used=[])
    with tempfile.TemporaryDirectory(prefix='cpupri-active-') as tmp:
        for label, source in [('port', (ROOT / 'kernel/sched/cpupri.c').read_text()),
                              ('pre_fix_control', git('show', old + ':kernel/sched/cpupri.c'))]:
            body = function(source, '__cpupri_find')
            code = PRE + body + WRAP
            path = Path(tmp) / (label + '.c')
            path.write_text(code)
            lib = path.with_suffix('.so')
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror', str(path), '-o', str(lib)], check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_uint] * 6
            probe.restype = ctypes.c_uint
            failures = [i for i, case in enumerate(cases) if probe(*case) != expected[i]]
            report['results'][label] = dict(failures=len(failures),
                first_failure_inputs=cases[failures[0]] if failures else None,
                function_sha256=hashlib.sha256(body.encode()).hexdigest(),
                harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    assert report['results']['port']['failures'] == 0
    assert report['results']['pre_fix_control']['failures'] > 0
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    (ROOT / 'Documentation/android-port/evidence/cpupri-active-check.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
