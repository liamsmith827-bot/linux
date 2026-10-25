#!/usr/bin/env python3
"""Exercise the actual inet_create cleanup labels and notification ordering."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT=Path(__file__).resolve().parents[2]
ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
pre=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
struct sock { bool released; };
struct socket { struct sock *sk; };
static int notifications,stale,unlocks;
static void sk_common_release(struct sock *sk) { assert(!sk->released);sk->released=true; }
static void rcu_read_unlock(void) { unlocks++; }
static void trace_android_vh_inet_create(struct sock *sk,bool error) {
    notifications++;
    if(sk && sk->released) stale++;
    if(!error) assert(sk && !sk->released);
}
'''
code=pre;hashes={}
for family,path,name in [('v4','net/ipv4/af_inet.c','inet_create'),('v6','net/ipv6/af_inet6.c','inet6_create')]:
    for tag in ['port','ack']:
        s=(ROOT/path).read_text() if tag=='port' else subprocess.check_output(['git','show',ACK+':'+path],cwd=ROOT,text=True)
        f=function(s,name);tail=f[f.index('\nout:\n'):]
        hashes[tag+'_'+family]=hashlib.sha256(tail.encode()).hexdigest()
        code+='int '+tag+'_'+family+r'''(int path) {
    struct sock object={0},*sk=path==0||path==3?NULL:&object;
    struct socket socket={.sk=sk},*sock=&socket;int err=path?-1:0;
    if(path==0) { sk=&object;sock->sk=sk;goto out; }
    if(path==1) goto out_sk_release;
    if(path==2) { sk=NULL;goto out_rcu_unlock; }
    goto out;
'''+tail
code+=r'''
int main(void) {
    int (*funcs[])(int)={port_v4,port_v6,ack_v4,ack_v6};int cases=0,old_stale=0;
    for(int f=0;f<4;f++) for(int path=0;path<4;path++) {
        notifications=stale=unlocks=0;
        int ret=funcs[f](path);
        assert(ret==(path?-1:0) && notifications==1 && unlocks==(path==2));
        if(f<2) assert(!stale);else old_stale+=stale;
        cases++;
    }
    assert(old_stale==2);
    printf("{\"cleanup_cases\":%d,\"ack_released_socket_notifications\":%d}\n",cases,old_stale);
}
'''
with tempfile.TemporaryDirectory(prefix='inet-create-hook-') as tmp:
    c=Path(tmp)/'test.c';c.write_text(code);binary=Path(tmp)/'test'
    subprocess.run(['clang','-fsanitize=address,undefined','-g','-O1',str(c),'-o',str(binary)],check=True)
    results=json.loads(subprocess.check_output([str(binary)],text=True))
report=dict(results=results,cleanup_sha256=hashes,limitations='Actual final cleanup labels with synthetic entry states, RCU callback and release marker. Demonstrates notification of a logically released socket in ACK and null in port; no memory is freed by the marker, and no real socket, protocol initialization, RCU concurrency or malicious module is tested.')
(Path(__file__).resolve().parent/'evidence/inet-create-hook-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
