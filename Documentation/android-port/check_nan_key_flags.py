#!/usr/bin/env python3
"""Exercise the actual key-interface dispatch, with peer/key flag shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
UPSTREAM = '014eec318fc00f0b497bffa04f1a45255ba7ff5e'

def source(ref):
    return subprocess.check_output(['git', 'show', ref + ':net/mac80211/cfg.c'],
                                   cwd=ROOT, text=True)

def block(text):
    body = function(text, 'ieee80211_add_key')
    begin = body.index('\tswitch (sdata->vif.type) {')
    end = body.index('\n\terr = ieee80211_key_link', begin)
    return body[begin:end]

port_source = (ROOT / 'net/mac80211/cfg.c').read_text()
port = block(port_source)
ack = block(source(ACK))
upstream = block(source(UPSTREAM))
# The only conflict adaptation retains the existing peer-device rejection.
assert port.replace('\tcase NL80211_IFTYPE_PD:\n', '') == upstream
assert function(port_source, 'ieee80211_add_key').replace(port, ack) == \
    function(source(ACK), 'ieee80211_add_key')
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "include/uapi/linux/nl80211.h"
#define IEEE80211_MFP_DISABLED 0
#define IEEE80211_MESH_SEC_NONE 0
#define IEEE80211_KEY_FLAG_RX_MGMT 64
#define WLAN_STA_MFP 1
#define test_sta_flag(s,f) ((s)->mfp)
#define WARN_ON_ONCE(x) (warnings += !!(x))
static unsigned warnings;
struct sdata { struct { unsigned type; } vif;
    union { struct { unsigned mfp; } mgd; struct { unsigned security; } mesh; } u; };
struct station { bool mfp; };
struct key { struct { unsigned flags; } conf; };
'''
code = pre
for name, body in [('port', port), ('ack', ack)]:
    code += 'static void ' + name + '(struct sdata *sdata, struct station *sta, struct key *key) {\n' + body + '\n}\n'
code += r'''
int main(void) {
    unsigned cases=0, fixed_warnings=0, fixed_flags=0;
    for(unsigned t=0;t<=NUM_NL80211_IFTYPES;t++)
    for(unsigned has_sta=0;has_sta<2;has_sta++)
    for(unsigned peer_mfp=0;peer_mfp<2;peer_mfp++)
    for(unsigned own_mfp=0;own_mfp<2;own_mfp++) {
        struct sdata s={.vif.type=t,.u.mgd.mfp=own_mfp};
        struct station st={.mfp=peer_mfp};
        struct key a={.conf.flags=0x100},p=a;
        warnings=0;ack(&s,has_sta?&st:NULL,&a);unsigned aw=warnings;
        warnings=0;port(&s,has_sta?&st:NULL,&p);
        if(t==NL80211_IFTYPE_NAN || t==NL80211_IFTYPE_NAN_DATA) {
            assert(aw==1 && warnings==0);fixed_warnings++;
            assert(p.conf.flags==(0x100 | ((has_sta && peer_mfp)?64:0)));
            fixed_flags += a.conf.flags!=p.conf.flags;
        } else assert(aw==warnings && a.conf.flags==p.conf.flags);
        cases++;
    }
    printf("{\"cases\":%u,\"fixed_warnings\":%u,\"fixed_management_flags\":%u}\n",
           cases,fixed_warnings,fixed_flags);
}
'''
results = {}
with tempfile.TemporaryDirectory(prefix='nan-key-flags-') as tmp:
    c = Path(tmp) / 'test.c'; c.write_text(code)
    for mesh in [False, True]:
        binary = Path(tmp) / ('test-' + str(mesh))
        command = ['clang', '-fsanitize=address,undefined', '-g', '-O1', '-I', str(ROOT)]
        if mesh: command += ['-DCONFIG_MAC80211_MESH']
        subprocess.run(command + [str(c), '-o', str(binary)], check=True)
        results['mesh_' + str(mesh).lower()] = json.loads(subprocess.check_output([str(binary)], text=True))
report = dict(results=results, local_upstream=UPSTREAM,
              dispatch_sha256=hashlib.sha256(port.encode()).hexdigest(),
              limitations='Actual key-interface switch under host ASan/UBSan, both mesh configurations. All other add_key code equals ACK; upstream switch equals port except preserved PD rejection. Does not exercise key allocation, crypto, driver offload or runtime.')
(ROOT / 'Documentation/android-port/evidence/nan-key-flags-test.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
