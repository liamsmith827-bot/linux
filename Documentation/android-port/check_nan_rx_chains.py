#!/usr/bin/env python3
"""Run the actual channel SMPS calculation with mixed NAN/link users."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
name = 'ieee80211_recalc_smps_chanctx'
port = function((ROOT/'net/mac80211/chan.c').read_text(), name)
ack = function(subprocess.check_output(['git','show',ACK+':net/mac80211/chan.c'],cwd=ROOT,text=True),name)
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "include/uapi/linux/nl80211.h"
typedef uint8_t u8;
#define lockdep_assert_wiphy(x) ((void)0)
#define ieee80211_hw_check(hw,flag) true
#define wiphy_dereference(w,p) (p)
#define rcu_access_pointer(p) (p)
#define WARN_ONCE(c,...) ((void)0)
#define fallthrough __attribute__((fallthrough))
#define max(a,b) ((a)>(b)?(a):(b))
#define IEEE80211_CHANCTX_CHANGE_RX_CHAINS 1
enum { IEEE80211_SMPS_OFF, IEEE80211_SMPS_DYNAMIC, IEEE80211_SMPS_STATIC };
struct conf { unsigned rx_chains_static,rx_chains_dynamic; };
struct ieee80211_chanctx { struct conf conf; };
struct ieee80211_sub_if_data {
    struct { struct { bool associated; } mgd; } u;
    struct { struct { struct conf *chanctx_conf; } bss_conf; } vif;
};
struct link { unsigned smps_mode,needed_rx_chains; };
struct nan_channel { unsigned needed_rx_chains; };
struct ieee80211_chanctx_user_iter {
    unsigned iftype;struct ieee80211_sub_if_data *sdata;
    struct link *link;struct nan_channel *nan_channel;
};
struct ieee80211_local { struct { int wiphy; } hw; unsigned rx_chains;
    struct ieee80211_sub_if_data *monitor_sdata;
    struct ieee80211_chanctx_user_iter users[2];unsigned n;
};
#define for_each_chanctx_user_assigned(local,ctx,iter) \
    for(unsigned i=0;i<(local)->n && ((*(iter)=(local)->users[i]),true);i++)
static void drv_change_chanctx(struct ieee80211_local *l,struct ieee80211_chanctx *c,int flags) {}
'''
code = pre + port.replace(name+'(', 'port_calc(') + ack.replace(name+'(', 'ack_calc(')
code += r'''
int main(void) {
    unsigned cases=0,old_wrong=0,non_nan=0;
    struct ieee80211_sub_if_data s={0};struct link link={0};struct nan_channel nc={0};
    struct ieee80211_local l={.rx_chains=8};
    for(unsigned type=0;type<NUM_NL80211_IFTYPES;type++)
    for(unsigned mode=0;mode<3;mode++) for(unsigned chains=1;chains<=8;chains++)
    for(unsigned assoc=0;assoc<2;assoc++) {
        link.smps_mode=mode;link.needed_rx_chains=chains;s.u.mgd.associated=assoc;
        struct ieee80211_chanctx_user_iter ordinary={.iftype=type,.sdata=&s,.link=&link};
        struct ieee80211_chanctx p={0},a={0};
        l.n=1;l.users[0]=ordinary;port_calc(&l,&p);ack_calc(&l,&a);
        assert(p.conf.rx_chains_static==a.conf.rx_chains_static &&
               p.conf.rx_chains_dynamic==a.conf.rx_chains_dynamic);non_nan++;
        unsigned base_static=p.conf.rx_chains_static,base_dynamic=p.conf.rx_chains_dynamic;
        for(unsigned nan_chains=1;nan_chains<=8;nan_chains++) for(unsigned order=0;order<2;order++) {
            nc.needed_rx_chains=nan_chains;
            l.n=2;l.users[order]=ordinary;
            l.users[1-order]=(struct ieee80211_chanctx_user_iter){.iftype=NL80211_IFTYPE_NAN,.sdata=&s,.nan_channel=&nc};
            p=(struct ieee80211_chanctx){0};a=p;port_calc(&l,&p);ack_calc(&l,&a);
            assert(p.conf.rx_chains_static==max(base_static,nan_chains));
            assert(p.conf.rx_chains_dynamic==max(base_dynamic,nan_chains));
            old_wrong+=p.conf.rx_chains_static!=a.conf.rx_chains_static ||
                       p.conf.rx_chains_dynamic!=a.conf.rx_chains_dynamic;cases++;
        }
    }
    printf("{\"mixed_user_cases\":%u,\"ack_lost_requirements\":%u,\"unchanged_non_nan_cases\":%u}\n",cases,old_wrong,non_nan);
}
'''
with tempfile.TemporaryDirectory(prefix='nan-rx-chains-') as tmp:
    c=Path(tmp)/'test.c';c.write_text(code);binary=Path(tmp)/'test'
    subprocess.run(['clang','-fsanitize=address,undefined','-g','-O1','-I',str(ROOT),str(c),'-o',str(binary)],check=True)
    results=json.loads(subprocess.check_output([str(binary)],text=True))
report=dict(results=results,function_sha256=hashlib.sha256(port.encode()).hexdigest(),
            limitations='Actual SMPS aggregation body under ASan/UBSan with preselected iterator users and notification/lock shims. Covers both NAN/link iteration orders, 1..8 chains, all interface enums, three SMPS modes and association states. Does not validate the real iterator, hardware callbacks, concurrency or radio reception.')
(ROOT/'Documentation/android-port/evidence/nan-rx-chains-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
