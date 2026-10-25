#!/usr/bin/env python3
"""Test the real FTM parser with prevalidated-attribute shims, not radio I/O."""
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "include/uapi/linux/nl80211.h"
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(n) (1UL << (n))
#define NL_SET_ERR_MSG(...) ((void)0)
#define NL_SET_ERR_MSG_ATTR(...) ((void)0)
'''
SHIMS = r'''
struct ieee80211_channel { enum nl80211_band band; };
struct cfg80211_chan_def { struct ieee80211_channel *chan; unsigned width; };
struct cfg80211_pmsr_request_peer {
    struct cfg80211_chan_def chandef;
    struct cfg80211_pmsr_ftm_request_peer ftm;
};
struct cfg80211_registered_device {
    struct { struct cfg80211_pmsr_capabilities *pmsr_capa; } wiphy;
};
struct genl_info { void *extack; };
struct nlattr { unsigned len; unsigned char data[8]; };
static struct nlattr attr[NL80211_PMSR_FTM_REQ_ATTR_MAX+1];
static struct nlattr *attrs[NL80211_PMSR_FTM_REQ_ATTR_MAX+1];
static unsigned width_mismatches, cases;
static void nla_parse_nested_deprecated(struct nlattr **tb, int max,
    struct nlattr *a, void *p, void *x) {
    memcpy(tb,attrs,sizeof(attrs));
}
#define GET(bits) static u##bits nla_get_u##bits(const struct nlattr *a) { \
    u##bits val; width_mismatches += a->len != sizeof(val); \
    memcpy(&val,a->data,sizeof(val)); return val; }
GET(8) GET(16) GET(32) GET(64)
static bool nla_get_flag(const struct nlattr *a) { return !!a; }
static void set(unsigned id, uint64_t value, unsigned len) {
    attr[id]=(struct nlattr){.len=len}; attrs[id]=&attr[id];
    if(len==1) { u8 v=value; memcpy(attr[id].data,&v,1); }
    if(len==2) { u16 v=value; memcpy(attr[id].data,&v,2); }
    if(len==4) { u32 v=value; memcpy(attr[id].data,&v,4); }
    if(len==8) { u64 v=value; memcpy(attr[id].data,&v,8); }
}
#define SET(n,v,l) set(NL80211_PMSR_FTM_REQ_ATTR_##n,v,l)
static struct cfg80211_pmsr_capabilities cap;
static struct cfg80211_registered_device rdev={.wiphy={.pmsr_capa=&cap}};
static struct ieee80211_channel chan={.band=NL80211_BAND_5GHZ};
static struct genl_info info;
static struct cfg80211_pmsr_request_peer out;
static void init(unsigned pd) {
    memset(attrs,0,sizeof(attrs));
    cap=(struct cfg80211_pmsr_capabilities){.ftm={
        .supported=1,.preambles=~0U,.bandwidths=~0U,
        .pd_preambles=~0U,.pd_bandwidths=~0U,.max_bursts_exponent=15,
        .max_ftms_per_burst=255,.asap=1,.non_asap=1,
        .trigger_based=1,.non_trigger_based=1,
        .rsta={.support_ntb=1,.support_tb=1,.support_edca=1}}};
    out=(struct cfg80211_pmsr_request_peer){.chandef={.chan=&chan,
        .width=NL80211_CHAN_WIDTH_20},.ftm={.request_type=pd}};
    SET(PREAMBLE,NL80211_PREAMBLE_HE,4);
}
'''
MAIN = r'''
static int parse(void) { return pmsr_parse_ftm(&rdev,NULL,&out,&info); }
int main(int argc,char **argv) {
    if(argc>1) {
        init(0); SET(NON_TRIGGER_BASED,0,0);
        assert(parse()==0 && out.ftm.nominal_time==0);
        puts("legacy NTB without nominal time accepted"); return 0;
    }
    const unsigned ftms[]={0,1,4,5,31,32};
    for(unsigned pd=0;pd<2;pd++) for(unsigned mode=0;mode<4;mode++)
    for(unsigned nominal=0;nominal<2;nominal++) for(unsigned rsta=0;rsta<2;rsta++)
    for(unsigned feedback=0;feedback<2;feedback++) for(unsigned suppress=0;suppress<2;suppress++)
    for(unsigned f=0;f<6;f++) {
        /* The ACK crash is verified separately in a sanitizer subprocess. */
        if(!PORT && !pd && mode==2 && !nominal) continue;
        init(pd);
        if(mode&1) SET(TRIGGER_BASED,0,0);
        if(mode&2) SET(NON_TRIGGER_BASED,0,0);
        if(nominal) SET(NOMINAL_TIME,1234567890,4);
        if(rsta) SET(RSTA,0,0);
        if(feedback) SET(LMR_FEEDBACK,0,0);
        if(suppress) SET(PD_SUPPRESS_RESULTS,0,0);
        SET(FTMS_PER_BURST,ftms[f],1);
        int expected=0;
        if(pd && (mode&1)) expected=-EINVAL;
        else if(mode==3) expected=-EINVAL;
        else if(pd && mode==2 && ftms[f]>4) expected=-ERANGE;
        else if(mode==0 && ftms[f]>31) expected=-ERANGE;
        else if(mode==0 && feedback) expected=-EINVAL;
        else if(rsta && mode && !feedback) expected=-EINVAL;
        else if(pd && mode==2 && !nominal) expected=-EINVAL;
        else if(!pd && suppress) expected=-EINVAL;
        int ret=parse(); assert(ret==expected);
        if(!ret) {
            assert(out.ftm.ftms_per_burst==ftms[f]);
            assert(out.ftm.nominal_time==(mode==2 && nominal ? 1234567890 : 0));
            assert(out.ftm.burst_duration==(mode ? 0 : 15));
        }
        cases++;
    }
    for(unsigned value=0;value<256;value++) {
        init(1); SET(NON_TRIGGER_BASED,0,0); SET(NOMINAL_TIME,0,4);
        SET(AW_DURATION,value,4); SET(NUM_MEASUREMENTS,UINT32_MAX,4);
        SET(MIN_TIME_BETWEEN_MEASUREMENTS,UINT32_MAX,4);
        SET(MAX_TIME_BETWEEN_MEASUREMENTS,UINT32_MAX,4);
        SET(INGRESS,UINT64_MAX,8); SET(EGRESS,UINT64_MAX-1,8);
        assert(parse()==0 && out.ftm.availability_window==value);
        assert(out.ftm.num_measurements==UINT32_MAX);
        assert(out.ftm.min_time_between_measurements==UINT32_MAX);
        assert(out.ftm.max_time_between_measurements==UINT32_MAX);
        assert(out.ftm.ingress_distance==UINT64_MAX && out.ftm.egress_distance==UINT64_MAX-1);
        cases++;
    }
    for(unsigned pd=0;pd<2;pd++) for(unsigned mode=0;mode<3;mode++) {
        if(pd && mode==1) continue;
        init(pd); SET(RSTA,0,0);
        if(mode) SET(LMR_FEEDBACK,0,0);
        if(mode==1) SET(TRIGGER_BASED,0,0);
        if(mode==2) { SET(NON_TRIGGER_BASED,0,0); SET(NOMINAL_TIME,0,4); }
        cap.ftm.rsta.support_ntb=cap.ftm.rsta.support_tb=cap.ftm.rsta.support_edca=0;
        assert(parse()==-EOPNOTSUPP);cases++;
    }
    if(PORT) {
        init(0); SET(REQUEST_LCI,0,0); assert(parse()==-EOPNOTSUPP); cases++;
        init(0); SET(REQUEST_CIVICLOC,0,0); assert(parse()==-EOPNOTSUPP); cases++;
        init(0); SET(REQUEST_LCI,0,0); cap.ftm.request_lci=1; assert(parse()==0); cases++;
        init(0); SET(REQUEST_CIVICLOC,0,0); cap.ftm.request_civicloc=1; assert(parse()==0); cases++;
        assert(width_mismatches==0);
    }
    printf("{\"cases\":%u,\"getter_width_mismatches\":%u}\n",cases,width_mismatches);
}
'''


def struct(text, name):
    return re.search(r'^struct '+name+r' \{.*?^\};', text, re.M | re.S).group(0)


def main():
    header = (ROOT/'include/net/cfg80211.h').read_text()
    declarations = '\n'.join(struct(header, n) for n in [
        'cfg80211_pmsr_ftm_request_peer', 'cfg80211_pmsr_capabilities'])
    results = {}
    with tempfile.TemporaryDirectory(prefix='pmsr-parser-') as tmp:
        for label, ref in [('port', None), ('ack_control', ACK)]:
            source = ((ROOT/'net/wireless/pmsr.c').read_text() if ref is None else
                      subprocess.check_output(['git', 'show', ref+':net/wireless/pmsr.c'], cwd=ROOT, text=True))
            body = function(source, 'pmsr_parse_ftm')
            src = Path(tmp)/(label+'.c')
            exe = src.with_suffix('')
            src.write_text(PRE+declarations+SHIMS+body+MAIN)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', str(ROOT),
                            '-DPORT='+str(int(ref is None)), str(src), '-o', str(exe)],
                           check=True, capture_output=True, text=True)
            run = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
            assert not run.stderr, run.stderr
            probe = subprocess.run([str(exe), 'missing-nominal'], capture_output=True, text=True)
            if ref is None:
                assert probe.returncode == 0 and not probe.stderr
            else:
                assert probe.returncode != 0 and 'null pointer' in probe.stderr
            results[label] = dict(extracted_sha256=hashlib.sha256(body.encode()).hexdigest(),
                                 **json.loads(run.stdout),
                                 missing_nominal_probe_returncode=probe.returncode,
                                 missing_nominal_null_dereference='null pointer' in probe.stderr)
    assert results['ack_control']['getter_width_mismatches'] > 0
    print(json.dumps(dict(results=results, limitations='Actual extracted FTM parser and structures with prevalidated attribute, channel and error-message shims under host ASan/UBSan. Tests do not exercise netlink policy traversal, peer-list validation, driver callbacks, radio I/O, concurrency or big-endian execution. Getter widths are checked against supplied payload lengths; no hardware ranging or boot is verified.'), indent=2))


if __name__ == '__main__':
    main()
