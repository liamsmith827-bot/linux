#!/usr/bin/env python3
"""Host checks of the extracted queue-run wrapper; no kernel/runtime test."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NAME = 'blk_mq_delay_run_hw_queue'


def extract(source):
    match = re.search(r'^void ' + NAME + r'\([^;{}]*\)\n\{.*?^\}',
                      source, re.M | re.S)
    assert match
    return match.group()


prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#define unlikely(x) (x)
struct blk_mq_hw_ctx { bool stopped; int run_work; };
static int selections, callbacks, queued, observed_cpu, queued_cpu;
static unsigned long observed_delay, queued_delay;
static bool hook_enabled, hook_skips;
static bool blk_mq_hctx_stopped(struct blk_mq_hw_ctx *h) { return h->stopped; }
/* Model a stateful selection; actual native selection also mutates hctx. */
static int blk_mq_hctx_next_cpu(struct blk_mq_hw_ctx *h)
{ (void)h; return ++selections; }
static unsigned long msecs_to_jiffies(unsigned long ms) { return ms * 2 + 1; }
static void trace_android_vh_blk_mq_delay_run_hw_queue(
    int cpu, struct blk_mq_hw_ctx *h, unsigned long delay, bool *skip)
{
    (void)h;
    if (!hook_enabled) return;
    callbacks++; observed_cpu = cpu; observed_delay = delay; *skip = hook_skips;
}
static void kblockd_mod_delayed_work_on(int cpu, int *work, unsigned long delay)
{ (void)work; queued++; queued_cpu = cpu; queued_delay = delay; }
'''
suffix = r'''
int main(void)
{
    unsigned int cases = 0;
    const unsigned long delays[] = {0, 1, 17, 1000};
    for (int stopped = 0; stopped < 2; stopped++)
    for (int enabled = 0; enabled < 2; enabled++)
    for (int skips = 0; skips < 2; skips++)
    for (unsigned int i = 0; i < sizeof(delays)/sizeof(delays[0]); i++) {
        struct blk_mq_hw_ctx h = {.stopped = stopped};
        selections = callbacks = queued = observed_cpu = queued_cpu = 0;
        observed_delay = queued_delay = 0;
        hook_enabled = enabled; hook_skips = skips;
        blk_mq_delay_run_hw_queue(&h, delays[i]);
        bool expect_queue = !stopped && !(enabled && skips);
        if (selections != !stopped || callbacks != (!stopped && enabled) ||
            queued != expect_queue ||
            (callbacks && (observed_cpu != 1 || observed_delay != delays[i]*2+1)) ||
            (queued && (queued_cpu != 1 || queued_delay != delays[i]*2+1)))
            return 1;
        cases++;
    }
    printf("%u cases passed\n", cases);
    return 0;
}
'''

current = extract((ROOT / 'block/blk-mq.c').read_text())
old = extract(subprocess.check_output(
    ['git', 'show', '23112ce1886e:block/blk-mq.c'], cwd=ROOT, text=True))
with tempfile.TemporaryDirectory(prefix='blk-mq-wrapper-') as directory:
    work = Path(directory)
    outcomes = []
    for label, body in [('port', current), ('ack_negative_control', old)]:
        source = work / (label + '.c')
        binary = work / label
        source.write_text(prefix + body + suffix)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        str(source), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == (0 if label == 'port' else 1), result
        outcomes.append(dict(source=label, exit_code=result.returncode,
                             stdout=result.stdout.strip(),
                             extracted_sha256=hashlib.sha256(body.encode()).hexdigest()))
report = dict(function=NAME, cases=32, results=outcomes,
              scope='Extracted production wrapper under host UBSan with modeled '
                    'stateful CPU selection, trace callback and workqueue. '
                    'Checks single selection, stopped path, disabled/enabled '
                    'callbacks, skip and consistent CPU/delay. Does not execute '
                    'native CPU masks, hotplug, actual tracepoints or workqueues; '
                    'not a kernel or emulator runtime test.')
output = ROOT / 'Documentation/android-port/evidence/blk-mq-workqueue-check.json'
output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
