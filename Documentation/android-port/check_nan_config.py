#!/usr/bin/env python3
"""Test the extracted NAN configuration parser with prevalidated netlink shims."""
import hashlib
import json
import re
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
#include <errno.h>
#include "include/uapi/linux/nl80211.h"
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16; typedef uint32_t u32;
#define ETH_ALEN 6
#define BIT(n) (1U << (n))
#define __aligned(n) __attribute__((aligned(n)))
#define NL_SET_ERR_MSG_ATTR(...) ((void)0)
#define CFG80211_NAN_CONF_CHANGED_PREF BIT(0)
#define CFG80211_NAN_CONF_CHANGED_BANDS BIT(1)
#define CFG80211_NAN_CONF_CHANGED_CONFIG BIT(2)
struct ieee80211_channel { int freq; };
struct wiphy { unsigned nan_supported_bands; };
struct nlattr { unsigned len; u8 data[8]; };
struct genl_info { struct nlattr *attrs[NL80211_ATTR_MAX+1]; void *extack; };
static struct nlattr *nested[NL80211_NAN_CONF_ATTR_MAX+1];
static struct ieee80211_channel channels[3]={{2437},{5745},{5220}};
static unsigned allowed, random_calls;
static int parse_error;
static struct ieee80211_channel *nl80211_get_nan_channel(struct wiphy *w, int freq) {
    for(unsigned i=0;i<3;i++) if(channels[i].freq==freq && (allowed&BIT(i))) return &channels[i];
    return NULL;
}
static int nla_parse_nested(struct nlattr **tb, int max, struct nlattr *a, void *p, void *e) {
    assert(max==NL80211_NAN_CONF_ATTR_MAX); memcpy(tb,nested,sizeof(nested)); return parse_error;
}
/* Band-config iteration is deliberately excluded from this focused test. */
#define nla_for_each_nested(pos, head, rem) for ((rem)=0; (rem)<0; (rem)++)
static const void *nla_data(const struct nlattr *a) { return a->data; }
static unsigned nla_len(const struct nlattr *a) { return a->len; }
static u8 nla_get_u8(const struct nlattr *a) { return a->data[0]; }
static u16 nla_get_u16(const struct nlattr *a) { u16 v; memcpy(&v,a->data,2); return v; }
static u32 nla_get_u32(const struct nlattr *a) { u32 v; memcpy(&v,a->data,4); return v; }
static bool nla_get_flag(const struct nlattr *a) { return !!a; }
static void ether_addr_copy(u8 *dst, const void *src) { memcpy(dst,src,6); }
static bool is_zero_ether_addr(const u8 *a) { static const u8 zero[6]; return !memcmp(a,zero,6); }
static void get_random_bytes(void *dst, unsigned n) { assert(n==2); memset(dst,0xa5,n); random_calls++; }
'''
SHIMS = r'''
static int nl80211_parse_nan_band_config(struct wiphy *w, struct nlattr **tb,
        struct cfg80211_nan_band_config *c, enum nl80211_band b) { assert(0); return -EINVAL; }
'''
MAIN = r'''
int main(void) {
    unsigned cases=0, control_failures=0;
    const u8 supplied[6]={0x50,0x6f,0x9a,1,0x12,0x34};
    const u8 generated[6]={0x50,0x6f,0x9a,1,0xa5,0xa5};
    for(unsigned start=0;start<2;start++) for(unsigned config=0;config<3;config++)
    for(unsigned bands=0;bands<4;bands++) for(allowed=0;allowed<8;allowed++)
    for(unsigned invalid=0;invalid<2;invalid++) {
        struct wiphy w={.nan_supported_bands=3};
        struct genl_info info={0};
        struct cfg80211_nan_conf conf={0};
        struct nlattr band_attr={.len=4},config_attr={0},id_attr={.len=6};
        memcpy(band_attr.data,&bands,4); memcpy(id_attr.data,supplied,6);
        info.attrs[NL80211_ATTR_BANDS]=&band_attr;
        info.attrs[NL80211_ATTR_NAN_CONFIG]=config ? &config_attr : NULL;
        memset(nested,0,sizeof(nested));
        if(config==2) nested[NL80211_NAN_CONF_CLUSTER_ID]=&id_attr;
        parse_error=invalid ? -EINVAL : 0; random_calls=0;
        u32 changed=0;
        int ret=nl80211_parse_nan_conf(&w,&info,&conf,&changed,start);
        bool good=(bands!=2) && (allowed&1) && (!config || !invalid) &&
                  (!(bands&2) || (allowed&6));
        assert((ret==0)==good);
        if(good) {
            assert(changed==(CFG80211_NAN_CONF_CHANGED_BANDS |
                   (config ? CFG80211_NAN_CONF_CHANGED_CONFIG : 0)));
            if(start) {
                const u8 *expected=config==2 ? supplied : generated;
                if(memcmp(conf.cluster_id,expected,6)) {
                    assert(!PORT && !config && is_zero_ether_addr(conf.cluster_id));
                    control_failures++;
                }
                assert(random_calls==((config!=2 && (PORT || config)) ? 1U : 0U));
            } else {
                assert(is_zero_ether_addr(conf.cluster_id) && !random_calls);
            }
        }
        cases++;
    }
    assert(PORT ? !control_failures : control_failures>0);
    printf("{\"cases\":%u,\"missing_default_cluster_failures\":%u}\n",cases,control_failures);
}
'''


def main():
    header = (ROOT/'include/net/cfg80211.h').read_text()
    declarations = '\n'.join(re.search(r'^struct '+n+r' \{.*?^\};', header,
                                       re.M | re.S).group(0)
                             for n in ['cfg80211_nan_band_config', 'cfg80211_nan_conf'])
    results = {}
    with tempfile.TemporaryDirectory(prefix='nan-config-') as tmp:
        for label, ref in [('port', None), ('ack_control', ACK)]:
            source = ((ROOT/'net/wireless/nl80211.c').read_text() if ref is None else
                      subprocess.check_output(['git', 'show', ref+':net/wireless/nl80211.c'],
                                              cwd=ROOT, text=True))
            body = function(source, 'nl80211_parse_nan_conf')
            src = Path(tmp)/(label+'.c')
            exe = src.with_suffix('')
            src.write_text(PRE+declarations+SHIMS+body+MAIN)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', str(ROOT),
                            '-DPORT='+str(int(ref is None)), str(src), '-o', str(exe)], check=True)
            run = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
            assert not run.stderr, run.stderr
            results[label] = dict(extracted_sha256=hashlib.sha256(body.encode()).hexdigest(),
                                 **json.loads(run.stdout))
    print(json.dumps(dict(results=results, limitations='Actual parser and configuration structures with prevalidated attribute/channel shims under host ASan/UBSan. Checks omitted/empty/supplied cluster configuration, start versus change, supported bands, channel availability and nested parse failure. Does not test netlink policy traversal, nested band configuration iteration, RNG quality, driver behavior or radio runtime.'), indent=2))


if __name__ == '__main__':
    main()
