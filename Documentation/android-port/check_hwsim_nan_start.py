#!/usr/bin/env python3
"""Invoke a simulated timer immediately from the actual NAN start routine."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
PATH = 'drivers/net/wireless/virtual/mac80211_hwsim_nan.c'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
port = function((ROOT / PATH).read_text(), 'mac80211_hwsim_nan_start')
ack = function(subprocess.check_output(['git', 'show', ACK + ':' + PATH], cwd=ROOT, text=True),
               'mac80211_hwsim_nan_start')
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "include/uapi/linux/nl80211.h"
#define scoped_guard(type, arg) for(int once=1;once;once=0)
#define MAC80211_HWSIM_NAN_PHASE_SCAN 0
#define MAC80211_HWSIM_NAN_ROLE_MASTER 0
#define NSEC_PER_USEC 1000
#define HRTIMER_MODE_REL_SOFT 0
#define cpu_to_le64(x) (x)
#define ns_to_ktime(x) (x)
#define ether_addr_copy(d,s) memcpy(d,s,6)
struct ieee80211_vif { unsigned type; };
struct cfg80211_nan_conf { unsigned bands,master_pref; bool enable_dw_notification; unsigned char cluster_id[6]; };
struct mac80211_hwsim_data { struct {
    struct ieee80211_vif *device_vif;
    unsigned bands,phase,random_factor_valid_dwst,random_factor,master_pref,role;
    struct { uint64_t master_rank; } current_ami,last_ami;
    unsigned char cluster_id[6];bool notify_dw;int slot_timer;
} nan; };
struct ieee80211_hw { struct mac80211_hwsim_data *priv; };
static struct cfg80211_nan_conf *expected;
static struct mac80211_hwsim_data *data;
static unsigned timers,mismatches;
static uint64_t hwsim_nan_get_master_rank(struct mac80211_hwsim_data *d) {
    assert(d->nan.device_vif);return 0x1234;
}
static void hrtimer_start(int *timer,unsigned delay,unsigned mode) {
    timers++;assert(timer==&data->nan.slot_timer);
    assert(data->nan.device_vif && data->nan.bands==expected->bands);
    assert(data->nan.master_pref==expected->master_pref);
    if(memcmp(data->nan.cluster_id,expected->cluster_id,6) ||
       data->nan.notify_dw!=expected->enable_dw_notification) mismatches++;
}
'''
code = pre + port.replace('mac80211_hwsim_nan_start(', 'port_start(') + ack.replace('mac80211_hwsim_nan_start(', 'ack_start(')
code += r'''
int main(void) {
    unsigned cases=0,ack_races=0;
    struct ieee80211_vif vif={0},old={0};
    struct cfg80211_nan_conf conf={.bands=3,.master_pref=50,.cluster_id={0x50,0x6f,0x9a,1,2,3}};
    struct mac80211_hwsim_data d;struct ieee80211_hw hw={.priv=&d};
    expected=&conf;data=&d;
    for(unsigned t=0;t<NUM_NL80211_IFTYPES;t++)
    for(unsigned running=0;running<2;running++) for(unsigned notify=0;notify<2;notify++) {
        vif.type=t;conf.enable_dw_notification=notify;
        memset(&d,0,sizeof(d));d.nan.device_vif=running?&old:NULL;
        timers=mismatches=0;
        int result=port_start(&hw,&vif,&conf);
        int want=t!=NL80211_IFTYPE_NAN?-EINVAL:running?-EALREADY:0;
        assert(result==want && timers==!want && !mismatches);
        memset(&d,0,sizeof(d));d.nan.device_vif=running?&old:NULL;
        timers=mismatches=0;
        result=ack_start(&hw,&vif,&conf);
        assert(result==want && timers==!want);
        ack_races+=mismatches;cases++;
    }
    assert(ack_races==2);
    printf("{\"cases\":%u,\"ack_timer_observed_uninitialized_cluster\":%u}\n",cases,ack_races);
}
'''
with tempfile.TemporaryDirectory(prefix='hwsim-nan-start-') as tmp:
    c = Path(tmp) / 'test.c'; c.write_text(code); binary = Path(tmp) / 'test'
    subprocess.run(['clang','-fsanitize=address,undefined','-g','-O1','-I',str(ROOT),str(c),'-o',str(binary)],check=True)
    results = json.loads(subprocess.check_output([str(binary)],text=True))
report = dict(results=results,function_sha256=hashlib.sha256(port.encode()).hexdigest(),
              limitations='Actual start routine, host ASan/UBSan; hrtimer_start shim checks state immediately, demonstrating the publication-order bug. Lock shims do not validate kernel memory ordering, RX concurrency, timer cancellation or station lifetime.')
(ROOT/'Documentation/android-port/evidence/hwsim-nan-start-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
