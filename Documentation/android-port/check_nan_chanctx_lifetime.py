#!/usr/bin/env python3
"""Exercise actual NAN removal/evacuation bodies across replacement states."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
source = (ROOT/'net/mac80211/nan.c').read_text()
old = subprocess.check_output(['git', 'show', ACK+':net/mac80211/nan.c'], cwd=ROOT, text=True)
helper = function((ROOT/'net/mac80211/chan.c').read_text(), 'ieee80211_chanctx_has_replace_partner')
names = ['ieee80211_nan_remove_channel', 'ieee80211_nan_evacuate_channel', 'ieee80211_nan_find_evac_chan']
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define WARN_ON(c) (c)
#define lockdep_assert_wiphy(w) ((void)0)
#define GFP_KERNEL 0
#define BSS_CHANGED_NAN_LOCAL_SCHED 1
#define IEEE80211_NAN_MAX_CHANNELS 3
#define CFG80211_NAN_SCHED_NUM_TIME_SLOTS 32
#define NL80211_IFTYPE_NAN 12
enum { IEEE80211_CHANCTX_REPLACE_NONE, IEEE80211_CHANCTX_WILL_BE_REPLACED, IEEE80211_CHANCTX_REPLACES_OTHER };
struct ieee80211_chanctx_conf { int dummy; };
struct ieee80211_chanctx { struct ieee80211_chanctx_conf conf; int replace_state; struct ieee80211_chanctx *replace_ctx; int assigned, refs; bool freed; };
struct ieee80211_nan_channel { struct { struct { int *chan; } oper; } chanreq; struct ieee80211_chanctx_conf *chanctx_conf; };
struct ieee80211_nan_sched_cfg { struct ieee80211_nan_channel channels[3]; struct ieee80211_nan_channel *schedule[32]; };
struct ieee80211_local { struct { int wiphy; } hw; };
struct ieee80211_sub_if_data { struct ieee80211_local *local; struct { int type; struct { struct ieee80211_nan_sched_cfg nan_sched; } cfg; } vif; int wdev; };
static int updates, notifications, carriers;
static int ieee80211_chanctx_refcount(struct ieee80211_local *l, struct ieee80211_chanctx *c) { return c->refs; }
static int ieee80211_chanctx_num_assigned(struct ieee80211_local *l, struct ieee80211_chanctx *c) { return c->assigned; }
static void ieee80211_free_chanctx(struct ieee80211_local *l, struct ieee80211_chanctx *c, bool skip) { c->freed=true; }
static void ieee80211_recalc_chanctx_chantype(struct ieee80211_local *l, struct ieee80211_chanctx *c) {}
static void ieee80211_recalc_smps_chanctx(struct ieee80211_local *l, struct ieee80211_chanctx *c) {}
static void ieee80211_recalc_chanctx_min_def(struct ieee80211_local *l, struct ieee80211_chanctx *c) {}
static void ieee80211_nan_update_peer_channels(struct ieee80211_sub_if_data *s, struct ieee80211_chanctx_conf *c) { updates++; }
static void drv_vif_cfg_changed(struct ieee80211_local *l, struct ieee80211_sub_if_data *s, int flags) { notifications++; }
static void cfg80211_nan_channel_evac(int *w, void *c, int flags) {}
static void ieee80211_nan_update_all_ndi_carriers(struct ieee80211_local *l) { carriers++; }
'''
code = pre + 'bool\n' + helper
for tag, text in [('port', source), ('ack', old)]:
    for i, name in enumerate(names):
        body = function(text, name)
        code += ('struct ieee80211_nan_channel *\n' if i == 2 else 'void\n') + body.replace(name+'(', tag+'_'+name+'(')
code += r'''
int main(void) {
    int channel, cases=0, old_bad=0, selections=0;
    struct ieee80211_local l={0};
    for(int action=0;action<2;action++) for(int state=0;state<3;state++)
    for(int paired=0;paired<2;paired++) for(int refs=0;refs<3;refs++) {
        struct ieee80211_chanctx partner={0};
        struct ieee80211_chanctx p={.replace_state=state,.replace_ctx=paired?&partner:NULL,.refs=refs,.assigned=refs}, a=p;
        struct ieee80211_sub_if_data s={.local=&l,.vif.type=NL80211_IFTYPE_NAN};
        struct ieee80211_nan_channel *nc=&s.vif.cfg.nan_sched.channels[0];
        *nc=(struct ieee80211_nan_channel){.chanreq.oper.chan=&channel,.chanctx_conf=&p.conf};
        s.vif.cfg.nan_sched.schedule[0]=nc;updates=notifications=carriers=0;
        if(action) port_ieee80211_nan_evacuate_channel(&s,nc);
        else port_ieee80211_nan_remove_channel(&s,nc);
        assert(p.freed==(refs==0 && !(paired && state==IEEE80211_CHANCTX_WILL_BE_REPLACED)));
        assert(nc->chanctx_conf==NULL && updates==1 && notifications==1);
        assert(carriers==action);
        if(!action) assert(!s.vif.cfg.nan_sched.schedule[0]);
        *nc=(struct ieee80211_nan_channel){.chanreq.oper.chan=&channel,.chanctx_conf=&a.conf};
        if(action) ack_ieee80211_nan_evacuate_channel(&s,nc);
        else ack_ieee80211_nan_remove_channel(&s,nc);
        old_bad+=a.freed!=p.freed;cases++;
    }
    for(int which=0;which<2;which++) {
        struct ieee80211_chanctx partner={0},ctx[2]={{.refs=1},{.refs=1}};
        ctx[which].replace_state=IEEE80211_CHANCTX_WILL_BE_REPLACED;
        ctx[which].replace_ctx=&partner;
        struct ieee80211_sub_if_data s={.local=&l,.vif.type=NL80211_IFTYPE_NAN};
        for(int i=0;i<2;i++) s.vif.cfg.nan_sched.channels[i]=(struct ieee80211_nan_channel){.chanreq.oper.chan=&channel,.chanctx_conf=&ctx[i].conf};
        assert(port_ieee80211_nan_find_evac_chan(&l,&s,NULL)==&s.vif.cfg.nan_sched.channels[1-which]);
        assert(port_ieee80211_nan_find_evac_chan(&l,&s,&ctx[which])==&s.vif.cfg.nan_sched.channels[which]);
        selections+=2;
    }
    printf("{\"release_cases\":%d,\"ack_premature_releases\":%d,\"selection_cases\":%d}\n",cases,old_bad,selections);
}
'''
with tempfile.TemporaryDirectory(prefix='nan-chanctx-lifetime-') as tmp:
    c = Path(tmp)/'test.c'; c.write_text(code); binary = Path(tmp)/'test'
    subprocess.run(['clang', '-fsanitize=address,undefined', '-g', '-O1', str(c), '-o', str(binary)], check=True)
    results = json.loads(subprocess.check_output([str(binary)], text=True))
report = dict(results=results, functions={n:hashlib.sha256(function(source,n).encode()).hexdigest() for n in names},
              limitations='Actual removal, evacuation and candidate-selection bodies with synthetic channel references and driver/iterator callbacks. Checks lifetime decisions and explicit versus automatic evacuation. Does not exercise real context reservations, RCU, locks, concurrency or hardware. No exploit demonstrated.')
(Path(__file__).resolve().parent/'evidence/nan-chanctx-lifetime-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
