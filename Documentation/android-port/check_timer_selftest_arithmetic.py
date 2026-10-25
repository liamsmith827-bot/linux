#!/usr/bin/env python3
"""Exercise extracted timer arithmetic with 32-bit longs represented by int32_t.

This never runs timer selftests, clocks, suspend or kernel code. The native
b-minus-a subtraction convention is preserved, including negative differences.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
baseline = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
paths = ['tools/testing/selftests/timers/' + f for f in ['alarmtimer-suspend.c', 'nsleep-lat.c', 'nanosleep.c', 'valid-adjtimex.c']]
sources = {p: (root / p).read_text() for p in paths}
parts = []
for i, path in enumerate(paths[:2]):
    for prefix, s in [('new', sources[path]), ('old', subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True))]:
        f = re.search(r'^long long timespec_sub\(.*?^\}', s, re.M | re.S)[0]
        parts.append(f.replace('timespec_sub(', f'{prefix}_{i}('))
shim = r'''
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <stdio.h>
struct timespec { int32_t tv_sec, tv_nsec; };
#define NSEC_PER_SEC ((int32_t)1000000000)
'''
# Check actual source expressions, not independently recreated constants.
for path in paths:
    s = sources[path]
    for expr in re.findall(r'(?:length <= |set_offset\()([^,\n;]+)', s):
        if 'NSEC_PER_SEC' in expr and '5LL' in expr:
            expected = -5500000000 if '-5LL' in expr and ' / 2' in expr else 5500000000 if ' / 2' in expr else -5000000000 if '-5LL' in expr else 5000000000
            parts.append(f'_Static_assert(({expr}) == {expected}LL, "32-bit offset");')
    if 'length <=' in s:
        expr = re.search(r'length <= \((NSEC_PER_SEC \* 10LL)\)', s)[1]
        parts.append(f'_Static_assert(({expr}) == 10000000000LL, "32-bit duration");')
expr = re.search(r'#define UNREASONABLE_LAT \((.*?)\)', sources[paths[0]])[1]
parts.append(f'_Static_assert(({expr}) == 5000000000LL, "32-bit latency");')
main = r'''
int main(int argc, char **argv) {
    (void)argv;
    const int32_t secs[] = {INT32_MIN, -100, -1, 0, 1, 100, INT32_MAX};
    const int32_t ns[] = {0, 123, 999999999};
    if (argc > 1) {
        struct timespec a = {0, 0}, b = {INT32_MAX, 123};
        volatile long long control = old_0(a, b) + old_1(a, b);
        (void)control;
        return 0;
    }
    unsigned cases = 0;
    for (unsigned a = 0; a < 7; a++) for (unsigned b = 0; b < 7; b++)
    for (unsigned an = 0; an < 3; an++) for (unsigned bn = 0; bn < 3; bn++) {
        struct timespec x = {secs[a], ns[an]}, y = {secs[b], ns[bn]};
        long long expected = ((long long)y.tv_sec - x.tv_sec) * 1000000000LL + y.tv_nsec - x.tv_nsec;
        assert(new_0(x, y) == expected && new_1(x, y) == expected);
        cases++;
    }
    printf("%u signed ILP32 timespec cases passed for both extracted helpers\n", cases);
}
'''
code = shim + '\n'.join(parts) + main
flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined', '-fno-sanitize-recover=all']
with tempfile.TemporaryDirectory(prefix='timer-arithmetic-') as temp:
    p = Path(temp); (p / 'check.c').write_text(code)
    subprocess.run(['cc', *flags, str(p / 'check.c'), '-o', str(p / 'check')], check=True)
    result = subprocess.check_output([str(p / 'check')], text=True).strip()
    control = subprocess.run([str(p / 'check'), 'old'], capture_output=True, text=True)
    assert control.returncode and 'signed integer overflow' in control.stderr, control.stderr
args.output.write_text(json.dumps({
    'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'source_files_sha256': {p: hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},
    'extracted_code_sha256': hashlib.sha256(code.encode()).hexdigest(),
    'compiler_flags': flags, 'result': result,
    'negative_control': 'Native unadapted helper produces signed 32-bit multiplication overflow under UBSan',
    'baseline': baseline, 'scope': __doc__,
}, indent=2) + '\n')
print(result)
