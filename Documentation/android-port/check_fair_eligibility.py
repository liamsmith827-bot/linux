#!/usr/bin/env python3
"""Compare extracted 64-bit eligibility code with a Python integer oracle.

Checks arithmetic only: no rb-tree, scheduler execution, locking or fairness test.
The accumulator/current contribution is constrained to fit s64; the comparison
product deliberately spans that boundary. Both 64-bit implementations are tested.
"""
import ctypes
import hashlib
import itertools
import json
import random
import subprocess
import tempfile
from pathlib import Path

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
MASK = (1 << 64) - 1
MIN, MAX = -(1 << 63), (1 << 63) - 1
PRE = r'''
#include <stdbool.h>
#include <stdint.h>
typedef int64_t s64;
typedef uint64_t u64;
struct load_weight { unsigned long weight; };
struct sched_entity { bool on_rq; u64 vruntime; struct load_weight load; };
struct cfs_rq { struct sched_entity *curr; s64 sum_w_vruntime; long sum_weight; u64 zero_vruntime; };
#define SCHED_FIXEDPOINT_SHIFT 10
#define max(a,b) ((a) > (b) ? (a) : (b))
#define check_mul_overflow(a,b,r) __builtin_mul_overflow(a,b,r)
'''
WRAP = r'''
int probe(s64 avg, long load, u64 zero, u64 value, int current, int onrq,
          u64 cv, unsigned long cw) {
 struct sched_entity se = { .on_rq=onrq, .vruntime=cv, .load.weight=cw << 10 };
 struct cfs_rq rq = { .curr=current ? &se : 0, .sum_w_vruntime=avg,
                      .sum_weight=load, .zero_vruntime=zero };
 return vruntime_eligible(&rq, value);
}
'''

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True)

def signed(value):
    value &= MASK
    return value if value <= MAX else value - (1 << 64)

def main():
    head = git('rev-parse', 'HEAD').strip()
    source = (ROOT / 'kernel/sched/fair.c').read_text()
    old = git('show', LTS + ':kernel/sched/fair.c')
    header = (ROOT / 'kernel/sched/sched.h').read_text()
    start = header.index('# define scale_load_down(w)')
    scale = header[start:header.index('#else', start)]
    cases = []
    # Comparison-product boundaries, negative lag, wraparound and equality.
    keys = [MIN, MIN + 1, -(1 << 44), -(1 << 32), -1, 0, 1,
            (1 << 32), (1 << 44), MAX - 1, MAX]
    for key, load, zero, avg in itertools.product(
            keys, [0, 1, 2, 1024, 102402, 104857602, 1 << 30], [0, MASK - 13],
            [MIN, -1, 0, 1, MAX]):
        cases.append((avg, load, zero, (zero + key) & MASK, 0, 0, zero, 0))
    # Include current only when on_rq, with representable accumulator and total.
    rng = random.Random(618)
    for _ in range(4000):
        zero = rng.getrandbits(64)
        key = rng.choice(keys)
        load = rng.choice([1, 2, 1024, 102402, 1 << 30])
        avg = rng.randrange(-(1 << 60), 1 << 60)
        ck = rng.randrange(-(1 << 36), 1 << 36)
        cw = rng.choice([1, 2, 1024, 88761])
        cases.append((avg, load, zero, (zero + key) & MASK,
                      1, rng.randrange(2), (zero + ck) & MASK, cw))
    # The reported cgroup extreme: one tiny entity and a heavy zero-key entity.
    for sign in [-1, 1]:
        key = sign * (4_000_000 + 700_000) * (1 << 20)
        cases.append((2 * key, 104857602, 0, key & MASK, 0, 0, 0, 0))

    expected = []
    for avg, load, zero, value, current, onrq, cv, cw in cases:
        if current and onrq:
            cw = max(2, cw) if cw else 0
            avg += signed(cv - zero) * cw
            load += cw
        assert MIN <= avg <= MAX and 0 <= load <= MAX
        expected.append(int(avg >= signed(value - zero) * load))

    variants = [('int128', source, ['-DCONFIG_ARCH_SUPPORTS_INT128']),
                ('checked_multiply', source, []), ('lts_control', old, [])]
    report = dict(source_head=head, control=LTS, cases=len(cases), results={},
                  scope=__doc__, remote_sources_used=[],
                  scale_load_down_sha256=hashlib.sha256(scale.encode()).hexdigest())
    with tempfile.TemporaryDirectory(prefix='fair-eligibility-') as tmp:
        for label, text, flags in variants:
            macros = text[text.index('extern void __BUILD_BUG_vruntime_cmp'):text.index('static inline __maybe_unused u64 max_vruntime')]
            bodies = [function(text, n) for n in ['entity_key', 'vruntime_eligible']]
            code = PRE + scale + macros + '\n'.join(bodies) + WRAP
            path = Path(tmp) / (label + '.c')
            path.write_text(code)
            lib = path.with_suffix('.so')
            cmd = ['cc', '-shared', '-fPIC', '-O2', '-fwrapv', '-DCONFIG_64BIT', *flags,
                   str(path), '-o', str(lib)]
            subprocess.run(cmd, check=True)
            probe = ctypes.CDLL(str(lib)).probe
            probe.argtypes = [ctypes.c_int64, ctypes.c_long, ctypes.c_uint64,
                              ctypes.c_uint64, ctypes.c_int, ctypes.c_int,
                              ctypes.c_uint64, ctypes.c_ulong]
            probe.restype = ctypes.c_int
            bad = [i for i, (args, want) in enumerate(zip(cases, expected)) if probe(*args) != want]
            report['results'][label] = dict(failures=len(bad),
                first_failure=dict(inputs=cases[bad[0]], expected=expected[bad[0]]) if bad else None,
                extracted_sha256=hashlib.sha256(('\n'.join(bodies)).encode()).hexdigest(),
                compiler_flags=cmd[1:-3], harness_sha256=hashlib.sha256(code.encode()).hexdigest())
    report['compiler'] = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    assert not report['results']['int128']['failures']
    assert not report['results']['checked_multiply']['failures']
    assert report['results']['lts_control']['failures']
    (ROOT / 'Documentation/android-port/evidence/fair-eligibility-check.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
