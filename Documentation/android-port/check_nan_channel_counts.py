#!/usr/bin/env python3
"""Exercise actual NAN request preflight through the allocation boundary."""
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
#include <errno.h>
#include "include/uapi/linux/nl80211.h"
#define U8_MAX UINT8_MAX
#define __free(x)
#define GENL_HDRLEN 0
#define NL_SET_ERR_MSG(...) ((void)0)
#define NL_SET_ERR_MSG_FMT(...) ((void)0)
struct sk_buff { int unused; };
struct nlattr { int unused; };
struct cfg80211_registered_device { int unused; };
struct cfg80211_nan_channel { int unused; };
struct cfg80211_nan_local_sched { int unused; };
struct cfg80211_nan_peer_sched { int unused; };
struct wireless_dev {
    enum nl80211_iftype iftype; bool running;
    struct { struct { uint8_t n_channels; } nan; } u;
};
struct genl_info { void *user_ptr[2]; struct nlattr *attrs[NL80211_ATTR_MAX+1]; unsigned nchannels; };
static struct nlattr attr;
static bool wdev_running(struct wireless_dev *w) { return w->running; }
#define nlmsg_for_each_attr_type(channel,type,hdr,len,rem) \
    for ((rem)=0,(channel)=&attr; (rem)<info->nchannels; (rem)++)
'''
MAIN = r'''
int main(void) {
    unsigned local_cases=0, peer_cases=0, old_local_failures=0, old_peer_failures=0;
    struct cfg80211_registered_device rdev={0};
    struct wireless_dev w={0};
    struct genl_info info={.user_ptr={&rdev,&w}};
    for(unsigned type=0;type<2;type++) for(unsigned active=0;active<2;active++)
    for(unsigned slots=0;slots<2;slots++) for(unsigned count=0;count<=513;count++) {
        w.iftype=type ? NL80211_IFTYPE_NAN : NL80211_IFTYPE_STATION;w.running=active;
        info.nchannels=count;info.attrs[NL80211_ATTR_NAN_TIME_SLOTS]=slots?&attr:NULL;
        int expected=!type ? -EOPNOTSUPP : !active ? -ENOTCONN : (!slots || count>255) ? -EINVAL : 0;
        int result=port_local(NULL,&info);assert(result==expected);
        result=ack_local(NULL,&info);
        if(result!=expected) { assert(type && active && slots && count>255 && !result);old_local_failures++; }
        local_cases++;
    }
    const unsigned local[]={0,1,2,31,32,255};
    info.attrs[NL80211_ATTR_MAC]=info.attrs[NL80211_ATTR_NAN_COMMITTED_DW]=&attr;
    for(unsigned type=0;type<2;type++) for(unsigned i=0;i<6;i++)
    for(unsigned flags=0;flags<4;flags++) for(unsigned count=0;count<=513;count++) {
        w.iftype=type ? NL80211_IFTYPE_NAN : NL80211_IFTYPE_STATION;
        w.u.nan.n_channels=local[i];info.nchannels=count;
        info.attrs[NL80211_ATTR_NAN_SEQ_ID]=(flags&1)?&attr:NULL;
        info.attrs[NL80211_ATTR_NAN_PEER_MAPS]=(flags&2)?&attr:NULL;
        bool complete=(count && flags==3) || (!count && !flags);
        int expected=!type ? -EOPNOTSUPP : (!complete || count>255 || count>local[i]*8) ? -EINVAL : 0;
        int result=port_peer(NULL,&info);assert(result==expected);
        result=ack_peer(NULL,&info);
        if(result!=expected) { assert(type && complete && count>255 && count<=local[i]*8 && !result);old_peer_failures++; }
        peer_cases++;
    }
    assert(old_local_failures && old_peer_failures);
    printf("{\"local_cases\":%u,\"peer_cases\":%u,\"ack_local_unrepresentable_counts\":%u,\"ack_peer_unrepresentable_counts\":%u}\n",
           local_cases,peer_cases,old_local_failures,old_peer_failures);
}
'''


def main():
    bodies = {}
    for label, source in [('port', (ROOT/'net/wireless/nl80211.c').read_text()),
                          ('ack', subprocess.check_output(['git', 'show', ACK+':net/wireless/nl80211.c'],
                                                          cwd=ROOT, text=True))]:
        for kind, stop in [('local', '\tsched = kzalloc('), ('peer', '\tif (n_channels) {')]:
            name = 'nl80211_nan_set_'+kind+'_sched'
            body = function(source, name).split(stop, 1)[0]
            assert stop in function(source, name)
            # Test only the unmodified pre-allocation prefix, then return success.
            bodies[label+'_'+kind] = body
    code = PRE + ''.join(body.replace('nl80211_nan_set_'+name.split('_')[1]+'_sched(', name+'(', 1)
                         + '\treturn 0;\n}\n' for name, body in bodies.items()) + MAIN
    with tempfile.TemporaryDirectory(prefix='nan-counts-') as tmp:
        src=Path(tmp)/'test.c';exe=Path(tmp)/'test';src.write_text(code)
        subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer','-fno-pie','-no-pie','-I',str(ROOT),
                        str(src),'-o',str(exe)],check=True)
        run=subprocess.run([str(exe)],check=True,text=True,capture_output=True)
        assert not run.stderr,run.stderr
    print(json.dumps(dict(results=json.loads(run.stdout),
                         extracted_prefix_sha256={n:hashlib.sha256(s.encode()).hexdigest() for n,s in bodies.items()},
                         limitations='Actual local/peer request function prefixes ending immediately before channel allocation, with synthetic attribute iteration and device state under ASan/UBSan. Covers counts 0..513, interface/activity/required-field combinations and local channel limits. ACK accepts unrepresentable counts at this boundary; later channel validation could still reject some requests. Does not claim demonstrated memory corruption, complete netlink parsing, allocation/failure behavior, scheduling, drivers or runtime coverage.'),indent=2))


if __name__ == '__main__':
    main()
