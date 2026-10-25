#!/usr/bin/env python3
"""Exercise the actual regulatory interface check with deterministic channel shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
PRE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/nl80211.h"
#define BIT(n) (1U << (n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define IEEE80211_CHAN_DISABLED 1U
struct ieee80211_channel { unsigned id; bool usable; };
struct cfg80211_chan_def { struct ieee80211_channel *chan; };
struct net_device { bool running; };
struct cfg80211_internal_bss { struct { struct ieee80211_channel *channel; } pub; };
struct wireless_dev {
    enum nl80211_iftype iftype;
    struct net_device *netdev;
    bool is_running;
    unsigned valid_links;
    struct {
        struct { unsigned beacon_interval; struct cfg80211_chan_def chandef; } ap;
        struct { struct cfg80211_internal_bss *current_bss; } client;
    } links[4];
    struct {
        struct { unsigned n_channels; struct cfg80211_chan_def chandefs[4]; } nan;
        struct { unsigned beacon_interval; struct cfg80211_chan_def chandef; } mesh;
        struct { unsigned ssid_len; struct cfg80211_chan_def chandef; } ibss;
        struct { struct cfg80211_chan_def chandef; } ocb;
    } u;
};
struct wiphy { int unused; };
struct cfg80211_ops { bool get_channel; };
struct cfg80211_registered_device { struct cfg80211_ops *ops; };
static struct cfg80211_ops ops;
static struct cfg80211_registered_device rdev = { .ops=&ops };
static struct ieee80211_channel channels[4];
static bool get_success;
static struct trace { unsigned calls, gets, warnings, hash; } trace;
#define WARN_ON_ONCE(x) ((void)(trace.warnings += !!(x)))
static bool netif_running(struct net_device *d) { return d->running; }
static struct cfg80211_registered_device *wiphy_to_rdev(struct wiphy *w) { return &rdev; }
static bool check(struct cfg80211_chan_def const *c, unsigned kind) {
    trace.calls++;
    trace.hash = trace.hash * 31U + kind * 16 + (c->chan ? c->chan->id + 1 : 0);
    return c->chan && c->chan->usable;
}
static bool cfg80211_reg_can_beacon(struct wiphy *w, struct cfg80211_chan_def const *c,
                                  enum nl80211_iftype t) { return check(c,1); }
static bool cfg80211_reg_can_beacon_relax(struct wiphy *w, struct cfg80211_chan_def const *c,
                                        enum nl80211_iftype t) { return check(c,2); }
static bool cfg80211_chandef_usable(struct wiphy *w, struct cfg80211_chan_def const *c,
                                  unsigned flags) { return check(c,3); }
static int rdev_get_channel(struct cfg80211_registered_device *r, struct wireless_dev *w,
                            int link, struct cfg80211_chan_def *c) {
    trace.gets++;
    if (!get_success) return -1;
    c->chan=&channels[(link+1)%4]; return 0;
}
static void cfg80211_chandef_create(struct cfg80211_chan_def *c,
                                  struct ieee80211_channel *ch, int type) { c->chan=ch; }
'''
MAIN = r'''
int main(void) {
    struct wiphy wiphy={0};
    unsigned nan_cases=0, ack_failures=0, other_cases=0;
    for(unsigned present=0;present<2;present++) for(unsigned running=0;running<2;running++)
    for(unsigned is_running=0;is_running<2;is_running++) for(unsigned n=0;n<=4;n++)
    for(unsigned mask=0;mask<16;mask++) {
        struct net_device netdev={.running=running};
        struct wireless_dev w={.iftype=NL80211_IFTYPE_NAN,
            .netdev=present ? &netdev : NULL,.is_running=is_running,.u.nan.n_channels=n};
        bool expected=true, active=present ? running : is_running;
        unsigned calls=0;
        for(unsigned i=0;i<4;i++) {
            channels[i]=(struct ieee80211_channel){.id=i,.usable=!!(mask&BIT(i))};
            w.u.nan.chandefs[i].chan=&channels[i];
            if(active && i<n && expected) { calls++; expected=channels[i].usable; }
        }
        trace=(struct trace){0};
        bool result=port_reg_wdev_chan_valid(&wiphy,&w);
        assert(result==expected && trace.calls==calls);
        trace=(struct trace){0};
        result=ack_reg_wdev_chan_valid(&wiphy,&w);
        if(result!=expected || trace.calls!=calls) {
            assert(!present && is_running && n>0);
            ack_failures++;
        }
        nan_cases++;
    }
    assert(ack_failures>0);
    for(unsigned type=0;type<NUM_NL80211_IFTYPES;type++) {
        if(type==NL80211_IFTYPE_NAN) continue;
        for(unsigned state=0;state<8;state++) for(unsigned links=0;links<16;links++)
        for(unsigned scenario=0;scenario<32;scenario++) {
            struct net_device netdev={.running=!!(state&2)};
            struct cfg80211_internal_bss bss[4];
            struct wireless_dev w={.iftype=type,.netdev=(state&1)?&netdev:NULL,
                .is_running=!!(state&4),.valid_links=links};
            ops.get_channel=scenario&8; get_success=scenario&16;
            for(unsigned i=0;i<4;i++) {
                channels[i]=(struct ieee80211_channel){.id=i,.usable=!!(scenario&BIT(i))};
                bss[i].pub.channel=(scenario&4)?&channels[i]:NULL;
                w.links[i].client.current_bss=(scenario&2)?&bss[i]:NULL;
                w.links[i].ap.beacon_interval=scenario&1;
                w.links[i].ap.chandef.chan=&channels[i];
            }
            w.u.mesh.beacon_interval=w.u.ibss.ssid_len=scenario&1;
            w.u.mesh.chandef.chan=w.u.ibss.chandef.chan=&channels[0];
            w.u.ocb.chandef.chan=(scenario&1)?&channels[0]:NULL;
            trace=(struct trace){0};
            bool expected=ack_reg_wdev_chan_valid(&wiphy,&w);
            struct trace old=trace;
            trace=(struct trace){0};
            bool result=port_reg_wdev_chan_valid(&wiphy,&w);
            assert(result==expected && trace.calls==old.calls && trace.gets==old.gets &&
                   trace.warnings==old.warnings && trace.hash==old.hash);
            other_cases++;
        }
    }
    printf("{\"nan_cases\":%u,\"ack_control_failures\":%u,\"non_nan_equivalence_cases\":%u}\n",
           nan_cases,ack_failures,other_cases);
}
'''


def main():
    current = function((ROOT/'net/wireless/reg.c').read_text(), 'reg_wdev_chan_valid')
    old = function(subprocess.check_output(['git', 'show', ACK+':net/wireless/reg.c'],
                                          cwd=ROOT, text=True), 'reg_wdev_chan_valid')
    running = function((ROOT/'include/net/cfg80211.h').read_text(), 'wdev_running')
    code = (PRE + running + current.replace('reg_wdev_chan_valid(', 'port_reg_wdev_chan_valid(', 1)
            + old.replace('reg_wdev_chan_valid(', 'ack_reg_wdev_chan_valid(', 1) + MAIN)
    with tempfile.TemporaryDirectory(prefix='nan-regulatory-') as tmp:
        source = Path(tmp)/'test.c'
        executable = Path(tmp)/'test'
        source.write_text(code)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', str(ROOT),
                        str(source), '-o', str(executable)], check=True)
        run = subprocess.run([str(executable)], check=True, text=True, capture_output=True)
        assert not run.stderr, run.stderr
    print(json.dumps(dict(results=json.loads(run.stdout),
                         extracted_sha256={n: hashlib.sha256(s.encode()).hexdigest()
                                           for n, s in [('port', current), ('ack_control', old),
                                                        ('wdev_running', running)]},
                         limitations='Actual functions with host ASan/UBSan and deterministic channel, netdev and callback shims. NAN covers zero to four channels, all validity masks and active/inactive netdev/non-netdev states. Other interface types compare return values and callback traces against ACK across link/state combinations. This does not exercise radio/regulatory database behavior, kernel locking, teardown concurrency or emulator runtime.'), indent=2))


if __name__ == '__main__':
    main()
