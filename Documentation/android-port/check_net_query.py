#!/usr/bin/env python3
"""Host checks of actual BPF query and sockmap ioctl functions, with stubs."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
query = function((ROOT/'kernel/bpf/mprog.c').read_text(), 'bpf_mprog_query')
old_query = function(subprocess.check_output(
    ['git', 'show', LTS+':kernel/bpf/mprog.c'], cwd=ROOT, text=True), 'bpf_mprog_query')
old_query = old_query.replace('bpf_mprog_query(', 'old_query(').replace(
    'struct bpf_mprog_entry *entry)', 'u32 uattr_size, struct bpf_mprog_entry *entry)')
ioctl = function((ROOT/'net/ipv4/tcp_bpf.c').read_text(), 'tcp_bpf_ioctl')
prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
'''+f'#include "{ROOT}/include/uapi/linux/bpf.h"\n'+r'''
typedef uint32_t u32;
typedef uint64_t u64;
#define __user
#define READ_ONCE(x) (x)
#define unlikely(x) (x)
#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t *)0)->m))
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
struct aux { u32 id; };
struct bpf_prog { struct aux *aux; };
struct bpf_mprog_fp { struct bpf_prog *prog; };
struct link { u32 id; };
struct bpf_mprog_cp { struct link *link; };
struct bpf_mprog_entry { int count; struct bpf_mprog_fp fp[3]; struct bpf_mprog_cp cp[3]; };
static u64 bpf_mprog_revision(struct bpf_mprog_entry *e) { return 7; }
static u32 bpf_mprog_total(struct bpf_mprog_entry *e) { return e->count; }
static int bpf_mprog_max(void) { return 3; }
static void bpf_mprog_read(struct bpf_mprog_entry *e,int i,struct bpf_mprog_fp **fp,struct bpf_mprog_cp **cp) { *fp=&e->fp[i];*cp=&e->cp[i]; }
static union bpf_attr *user_attr;
static size_t user_size;
static int overrun;
static int copy_to_user(void *dst,const void *src,size_t len) {
    uintptr_t d=(uintptr_t)dst,b=(uintptr_t)user_attr;
    if(d>=b && d<b+sizeof(*user_attr) && d+len>b+user_size) {
        overrun++;return 1;
    }
    memcpy(dst,src,len);return 0;
}
#define SIOCINQ 1
#define TCP_LISTEN 10
struct sk_psock { struct { bool stream_verdict,skb_verdict; } progs; int msg_len; };
struct sock { int sk_state,inq; struct sk_psock *psock; };
static int locked,gets,put_count,fallback;
static bool lock_sock_fast(struct sock *sk) { assert(!locked);locked=1;return true; }
static void unlock_sock_fast(struct sock *sk,bool slow) { assert(locked && slow);locked=0; }
static struct sk_psock *sk_psock_get(struct sock *sk) { assert(locked);gets++;return sk->psock; }
static void sk_psock_put(struct sock *sk,struct sk_psock *psock) { assert(locked && psock);put_count++; }
static int sk_psock_get_msg_len_nolock(struct sk_psock *p) { assert(locked);return p->msg_len; }
static int tcp_inq(struct sock *sk) { assert(locked);return sk->inq; }
static int tcp_ioctl(struct sock *sk,int cmd,int *out) { assert(!locked);fallback++;*out=sk->inq;return cmd==SIOCINQ?0:19; }
'''
main = r'''
int main(void) {
    int query_cases=0,old_overruns=0,ioctl_cases=0;
    for(int old=0;old<2;old++)
    for(unsigned size=offsetofend(union bpf_attr,query.count);size<=sizeof(union bpf_attr);size++)
    for(int populated=0;populated<2;populated++) {
        union bpf_attr attr={0},out;
        struct bpf_mprog_entry entry={.count=3};
        memset(&out,0xa5,sizeof(out));
        user_attr=&out;user_size=size;overrun=0;
        int ret=old?old_query(&attr,&out,size,populated?&entry:NULL):
            bpf_mprog_query(&attr,&out,size,populated?&entry:NULL);
        if(old && size<offsetofend(union bpf_attr,query.revision)) {
            assert(ret==-EFAULT && overrun==1);old_overruns++;
        } else {
            assert(!ret && !overrun);
            assert(out.query.count==(populated?3:0) && !out.query.attach_flags);
            if(size>=offsetofend(union bpf_attr,query.revision))
                assert(out.query.revision==(populated?7:1));
            else assert(out.query.revision==0xa5a5a5a5a5a5a5a5ULL);
        }
        for(unsigned i=size;i<sizeof(out);i++) assert(((unsigned char *)&out)[i]==0xa5);
        query_cases++;
    }
    for(int cmd=0;cmd<2;cmd++) for(int listen=0;listen<2;listen++)
    for(int present=0;present<2;present++) for(int verdict=0;verdict<4;verdict++)
    for(int msg=0;msg<3;msg++) for(int rx=0;rx<3;rx++) {
        struct sk_psock psock={.progs={!!(verdict&1),!!(verdict&2)},.msg_len=msg*100};
        struct sock sk={.sk_state=listen?TCP_LISTEN:1,.inq=rx*200,.psock=present?&psock:NULL};
        int out=-1;locked=gets=put_count=fallback=0;
        int ret=tcp_bpf_ioctl(&sk,cmd,&out);
        assert(!locked);
        if(!cmd) assert(ret==19 && fallback==1 && !gets && !put_count && out==rx*200);
        else if(listen) assert(ret==-EINVAL && !fallback && !gets && !put_count && out==-1);
        else if(!present) assert(!ret && fallback==1 && gets==1 && !put_count && out==rx*200);
        else assert(!ret && !fallback && gets==1 && put_count==1 && out==msg*100+(verdict?0:rx*200));
        ioctl_cases++;
    }
    printf("{\"query_cases\":%d,\"lts_revision_writes_beyond_size\":%d,\"ioctl_cases\":%d}\n",query_cases,old_overruns,ioctl_cases);
}
'''
with tempfile.TemporaryDirectory(prefix='net-query-') as tmp:
    source=Path(tmp)/'check.c';binary=Path(tmp)/'check'
    source.write_text(prefix+query+'\n'+old_query+'\n'+ioctl+'\n'+main)
    subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(binary)],check=True)
    results=json.loads(subprocess.check_output([str(binary)],text=True))
report=dict(results=results,source_sha256={
    'mprog_query':hashlib.sha256(query.encode()).hexdigest(),
    'tcp_bpf_ioctl':hashlib.sha256(ioctl.encode()).hexdigest()},
    limitations='Actual functions with synthetic socket locks, references, BPF entries and user copies. Query exercises count-only requests, absent/present entries and every size from the legacy count field through the current attr size; smaller-than-legacy buffers and nonempty program-array copying are not tested. Old revision overrun is detected without performing the invalid copy. Ioctl covers disjoint queue accounting and fallback ordering, not concurrent socket operations or kernel runtime.')
(Path(__file__).resolve().parent/'evidence/net-query-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
