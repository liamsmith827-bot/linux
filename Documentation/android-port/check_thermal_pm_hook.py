#!/usr/bin/env python3
"""Exercise per-zone hook decisions using extracted thermal PM traversal code."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT=Path(__file__).resolve().parents[2]
PATH='drivers/thermal/thermal_core.c'
ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
LTS='2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
PRE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
struct thermal_zone_device { unsigned id; };
static struct thermal_zone_device zones[3]={{0},{1},{2}};
static bool thermal_pm_suspended;
static unsigned selected, processed, seen, stale_input, prepared, completed;
#define guard(kind) (void)
static int thermal_list_lock;
#define list_for_each_entry(tz, head, node) for (unsigned idx=0; idx<3 && ((tz)=&zones[idx],1); idx++)
static void trace_android_vh_thermal_pm_notify_suspend(struct thermal_zone_device *tz, int *wakeable) {
    stale_input += *wakeable!=0;
    seen |= 1U<<tz->id;
    /* A consumer may set true for its own zone and leave other zones alone. */
    if (selected & (1U<<tz->id)) *wakeable=1;
}
static void thermal_zone_pm_prepare(struct thermal_zone_device *tz) {
    assert(thermal_pm_suspended && !(processed&(1U<<tz->id)));
    processed |= 1U<<tz->id; prepared++;
}
static void thermal_zone_pm_complete(struct thermal_zone_device *tz) {
    assert(!thermal_pm_suspended && !(processed&(1U<<tz->id)));
    processed |= 1U<<tz->id; completed++;
}
'''
MAIN=r'''
int main(void) {
    const unsigned masks[]={0,1,2,4,7};
    unsigned lost=0,total_stale=0,cases=0;
    for (unsigned m=0; m<5; m++) for (unsigned phase=0; phase<2; phase++) {
        selected=masks[m];processed=seen=stale_input=prepared=completed=0;
        thermal_pm_suspended=!!phase;
        if (!phase) thermal_pm_notify_prepare(); else thermal_pm_notify_complete();
        assert(thermal_pm_suspended==!phase);
        unsigned expected=NATIVE ? 7 : 7 & ~selected;
        lost += __builtin_popcount(expected & ~processed);
        total_stale += stale_input;
        if (PORT || NATIVE) assert(processed==expected && !stale_input);
        assert(seen==(NATIVE ? 0U : 7U));
        assert((phase ? prepared : completed)==0);
        assert((phase ? completed : prepared)==(unsigned)__builtin_popcount(processed));
        cases++;
    }
    printf("{\"cases\":%u,\"unintentionally_skipped_zones\":%u,\"stale_callback_inputs\":%u}\n",cases,lost,total_stale);
    return 0;
}
'''

def main():
    results={}
    with tempfile.TemporaryDirectory(prefix='thermal-pm-hook-') as tmp:
        for label,ref in [('port',None),('ack_control',ACK),('native_control',LTS)]:
            source=(ROOT/PATH).read_text() if ref is None else subprocess.check_output(['git','show',ref+':'+PATH],cwd=ROOT,text=True)
            body=''.join(function(source,name) for name in ['thermal_pm_notify_prepare','thermal_pm_notify_complete'])
            src=Path(tmp)/(label+'.c');exe=src.with_suffix('');src.write_text(PRE+body+MAIN)
            subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie',
                            '-DPORT='+str(int(label=='port')),'-DNATIVE='+str(int(label=='native_control')),str(src),'-o',str(exe)],check=True,capture_output=True,text=True)
            run=subprocess.run([str(exe)],check=True,capture_output=True,text=True);assert not run.stderr,run.stderr
            results[label]=dict(functions_sha256=hashlib.sha256(body.encode()).hexdigest(),**json.loads(run.stdout))
    assert results['ack_control']['unintentionally_skipped_zones']>0
    print(json.dumps(dict(results=results,limitations='Host traversal/control-flow shims under ASan/UBSan; no live thermal controller, workqueue, lock concurrency or suspend test.'),indent=2))

if __name__=='__main__':main()
