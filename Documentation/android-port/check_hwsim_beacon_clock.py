#!/usr/bin/env python3
"""Check actual beacon callback deadlines across simulated suspend offsets."""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
PATH = 'drivers/net/wireless/virtual/mac80211_hwsim_main.c'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
text = (ROOT/PATH).read_text()
ack = subprocess.check_output(['git','show',ACK+':'+PATH],cwd=ROOT,text=True)
body = function(text,'mac80211_hwsim_beacon')
assert body == function(ack,'mac80211_hwsim_beacon')
pattern = r'hrtimer_setup\(&data->link_data\[i\]\.beacon_timer, mac80211_hwsim_beacon,\s*(CLOCK_\w+)'
assert re.search(pattern,text)[1]=='CLOCK_BOOTTIME'
assert re.search(pattern,ack)[1]=='CLOCK_MONOTONIC'
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
typedef uint64_t u64;typedef uint32_t u32;
enum hrtimer_restart { HRTIMER_NORESTART, HRTIMER_RESTART };
struct hrtimer { u64 expires; };
struct mac80211_hwsim_link_data { unsigned link_id; u64 beacon_int; struct hrtimer beacon_timer; };
struct ieee80211_hw { int unused; };
struct mac80211_hwsim_data { struct mac80211_hwsim_link_data link_data[1]; struct ieee80211_hw *hw; bool started; };
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define IEEE80211_IFACE_ITER_NORMAL 0
static u64 boot_now,offset;
static void mac80211_hwsim_beacon_tx(void) {}
static void ieee80211_iterate_active_interfaces_atomic(struct ieee80211_hw *hw,int flags,void (*f)(void),void *d) {}
static u64 mac80211_hwsim_get_tsf(struct ieee80211_hw *hw,void *vif) { return boot_now+offset; }
static u64 mac80211_hwsim_tsf_to_boottime(struct mac80211_hwsim_data *d,u64 tsf) { return tsf-offset; }
static void div_u64_rem(u64 n,u64 d,u32 *r) { *r=n%d; }
static void hrtimer_set_expires(struct hrtimer *t,u64 expires) { t->expires=expires; }
'''
code = pre + 'static enum hrtimer_restart\n' + body + r'''
int main(void) {
    unsigned cases=0,ack_late=0;
    const u64 sleeps[]={0,1000000,3600000000ULL};
    const u64 offsets[]={0,17,99999};
    struct ieee80211_hw hw={0};struct mac80211_hwsim_data data={.hw=&hw,.started=true};
    struct mac80211_hwsim_link_data *link=&data.link_data[0];
    for(unsigned si=0;si<3;si++) for(unsigned oi=0;oi<3;oi++)
    for(unsigned interval=1;interval<=1000;interval++) {
        u64 mono_now=123456789;
        boot_now=mono_now+sleeps[si];offset=offsets[oi];link->beacon_int=interval*1024;
        assert(mac80211_hwsim_beacon(&link->beacon_timer)==HRTIMER_RESTART);
        u64 delay=link->beacon_timer.expires-boot_now;
        assert(delay>0 && delay<=link->beacon_int);
        assert((link->beacon_timer.expires+offset)%link->beacon_int==0);
        u64 ack_delay=link->beacon_timer.expires-mono_now;
        assert(ack_delay==delay+sleeps[si]);ack_late+=ack_delay>delay;cases++;
    }
    data.started=false;assert(mac80211_hwsim_beacon(&link->beacon_timer)==HRTIMER_NORESTART);
    printf("{\"cases\":%u,\"ack_deadlines_delayed_by_suspend_duration\":%u}\n",cases,ack_late);
}
'''
with tempfile.TemporaryDirectory(prefix='hwsim-beacon-clock-') as tmp:
    c=Path(tmp)/'test.c';c.write_text(code);binary=Path(tmp)/'test'
    subprocess.run(['clang','-fsanitize=address,undefined','-g','-O1',str(c),'-o',str(binary)],check=True)
    results=json.loads(subprocess.check_output([str(binary)],text=True))
report=dict(results=results,callback_sha256=hashlib.sha256(body.encode()).hexdigest(),
            limitations='Actual callback with host clock/iteration/timer shims and verified source timer clock selection. Covers 1..1000 TU intervals, TSF offsets and simulated suspend deltas. Does not suspend a kernel or validate timer cancellation/concurrency or real radio timing.')
(ROOT/'Documentation/android-port/evidence/hwsim-beacon-clock-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
