#!/usr/bin/env python3
"""Test actual GET_STATION control flow and cleanup using callback/allocation shims."""
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "include/uapi/linux/nl80211.h"
typedef uint8_t u8; typedef uint32_t u32;
#define GFP_KERNEL 0
#define NLMSG_DEFAULT_SIZE 256
#define IEEE80211_MLD_MAX_NUM_LINKS 16
struct net_device { int id; };
struct wireless_dev { struct net_device *netdev; enum nl80211_iftype iftype; };
struct cfg80211_ops { bool get_station; };
struct cfg80211_registered_device { struct cfg80211_ops *ops; };
struct link_info { int unused; };
struct station_info { struct link_info *links[16]; unsigned valid_links; };
struct sk_buff { int unused; };
struct nlattr { u8 data[6]; };
struct genl_info { void *user_ptr[2]; struct nlattr *attrs[NL80211_ATTR_MAX+1]; u32 snd_portid,snd_seq; };
static unsigned alloc_calls,live,fail_alloc,driver_calls;
static bool driver_error,send_error,mlo;
static struct wireless_dev *expected_wdev;
static void *kzalloc(size_t n,int gfp) {
    alloc_calls++; if(alloc_calls==fail_alloc) return NULL;
    void *p=calloc(1,n);assert(p);live++;return p;
}
static void drop(void *p) { if(p) { assert(live);live--;free(p); } }
static void cfg80211_sinfo_release_content(struct station_info *s) {
    for(unsigned i=0;i<16;i++) { drop(s->links[i]);s->links[i]=NULL; }
}
static void *nla_data(struct nlattr *a) { return a->data; }
static int rdev_get_station(struct cfg80211_registered_device *r,struct wireless_dev *w,
                           const u8 *mac,struct station_info *s) {
    assert(w==expected_wdev);driver_calls++;s->valid_links=mlo;return driver_error?-ENOENT:0;
}
static struct sk_buff *nlmsg_new(unsigned n,int gfp) { return kzalloc(n,gfp); }
static void nlmsg_free(struct sk_buff *s) { drop(s); }
static void cfg80211_sta_set_mld_sinfo(struct station_info *s) { assert(s->valid_links); }
static int nl80211_send_station(struct sk_buff *m,u32 cmd,u32 port,u32 seq,int flags,
        struct cfg80211_registered_device *r,struct wireless_dev *w,const u8 *mac,
        struct station_info *s,bool links) {
    assert(w==expected_wdev);cfg80211_sinfo_release_content(s);return send_error?-1:0;
}
static int genlmsg_reply(struct sk_buff *s,struct genl_info *info) { drop(s);return 0; }
'''
MAIN = r'''
int main(void) {
    unsigned cases=0,ack_nan_rejections=0;
    struct net_device dev={0};struct nlattr mac={0};
    struct cfg80211_ops ops={0};struct cfg80211_registered_device rdev={.ops=&ops};
    struct wireless_dev w={0};struct genl_info info={.user_ptr={&rdev,&w}};
    expected_wdev=&w;
    for(unsigned type=0;type<NUM_NL80211_IFTYPES;type++) for(unsigned present=0;present<2;present++)
    for(unsigned has_mac=0;has_mac<2;has_mac++) for(unsigned callback=0;callback<2;callback++)
    for(fail_alloc=0;fail_alloc<=17;fail_alloc++) for(unsigned errors=0;errors<8;errors++) {
        w.iftype=type;w.netdev=present?&dev:NULL;ops.get_station=callback;
        info.attrs[NL80211_ATTR_MAC]=has_mac?&mac:NULL;
        driver_error=errors&1;send_error=errors&2;mlo=errors&4;
        int expected=0;
        if((!present && type!=NL80211_IFTYPE_NAN) || !has_mac) expected=-EINVAL;
        else if(!callback) expected=-EOPNOTSUPP;
        else if(fail_alloc>=1 && fail_alloc<=16) expected=-ENOMEM;
        else if(driver_error) expected=-ENOENT;
        else if(fail_alloc==17) expected=-ENOMEM;
        else if(send_error) expected=-ENOBUFS;
        alloc_calls=driver_calls=0;assert(!live);
        int result=port_get_station(NULL,&info);assert(result==expected && !live);
        unsigned port_calls=driver_calls;
        alloc_calls=driver_calls=0;
        result=ack_get_station(NULL,&info);assert(!live);
        if(!present && type==NL80211_IFTYPE_NAN) {
            assert(result==-EINVAL && !driver_calls);
            if(port_calls) ack_nan_rejections++;
        } else assert(result==expected && driver_calls==port_calls);
        cases++;
    }
    assert(ack_nan_rejections);
    printf("{\"cases\":%u,\"ack_rejected_nan_queries_reaching_port_driver\":%u,\"live_allocations_at_exit\":%u}\n",
           cases,ack_nan_rejections,live);
}
'''


def main():
    bodies = {'port': function((ROOT/'net/wireless/nl80211.c').read_text(), 'nl80211_get_station'),
              'ack': function(subprocess.check_output(['git', 'show', ACK+':net/wireless/nl80211.c'],
                                                     cwd=ROOT, text=True), 'nl80211_get_station')}
    code=PRE+''.join(b.replace('nl80211_get_station(',n+'_get_station(',1) for n,b in bodies.items())+MAIN
    with tempfile.TemporaryDirectory(prefix='nan-get-sta-') as tmp:
        s=Path(tmp)/'test.c';exe=Path(tmp)/'test';s.write_text(code)
        subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer','-fno-pie','-no-pie','-I',str(ROOT),str(s),'-o',str(exe)],check=True)
        run=subprocess.run([str(exe)],check=True,text=True,capture_output=True)
        assert not run.stderr,run.stderr
    print(json.dumps(dict(results=json.loads(run.stdout),function_sha256={n:hashlib.sha256(b.encode()).hexdigest() for n,b in bodies.items()},
                         limitations='Actual GET_STATION command body under host ASan/UBSan with allocation/callback/serialization shims. Covers all interface enum values, netdev presence, required MAC, callback availability, each of 16 link allocations, message allocation, driver/serialization failure and MLO summary selection. Serialization shim follows actual ownership contract; netlink pre-dispatch, real station lookup, data serialization, driver lifetime/locking and runtime are not exercised.'),indent=2))


if __name__ == '__main__':
    main()
