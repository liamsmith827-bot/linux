#!/usr/bin/env python3
"""Check allocation scope and safety branches in the actual port/LTS SPI bodies."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
name = 'xfrm_alloc_spi'
port = function((ROOT/'net/xfrm/xfrm_state.c').read_text(), name)
native = function(subprocess.check_output(['git','show',LTS+':net/xfrm/xfrm_state.c'],cwd=ROOT,text=True),name)
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint32_t u32; typedef uint32_t __be32;
#define ERESTARTSYS 512
#define XFRM_STATE_DEAD 9
#define NL_SET_ERR_MSG(e,s) ((void)0)
struct netlink_ext_ack { int dummy; };
struct net { struct { int xfrm_state_lock; int state_byspi[2]; } xfrm; };
struct xfrm_state { struct net *net; int lock, byspi, refs; struct { int state; } km; struct { u32 spi,daddr; int proto; } id; struct { u32 v,m; } mark; struct { int family; } props; struct { int type; } xso; };
static struct xfrm_state existing;
static bool present, pending;
static unsigned insertions, attempts;
#define current 0
static struct net *xs_net(struct xfrm_state *s) { return s->net; }
static void spin_lock_bh(int *l) { assert(!*l);*l=1; }
static void spin_unlock_bh(int *l) { assert(*l);*l=0; }
static bool signal_pending(int t) { return pending; }
static u32 get_random_u32_inclusive(u32 lo,u32 hi) { attempts++;return lo; }
static unsigned xfrm_spi_hash(struct net *n,u32 *d,u32 spi,int proto,int family) { return 0; }
static struct xfrm_state *xfrm_state_lookup_spi_proto(struct net *n,u32 spi,int proto) {
    assert(n->xfrm.xfrm_state_lock);
    if(present && existing.id.spi==spi && existing.id.proto==proto) { existing.refs++;return &existing; }
    return NULL;
}
static struct xfrm_state *xfrm_state_lookup(struct net *n,u32 mark,u32 *dst,u32 spi,int proto,int family) {
    assert(n->xfrm.xfrm_state_lock);
    if(present && existing.id.spi==spi && existing.id.proto==proto && existing.id.daddr==*dst && existing.props.family==family && (mark & existing.mark.m)==existing.mark.v) { existing.refs++;return &existing; }
    return NULL;
}
static void xfrm_state_put(struct xfrm_state *s) { assert(s->refs>0);s->refs--; }
#define XFRM_STATE_INSERT(...) do { assert(net->xfrm.xfrm_state_lock && x->lock && x->id.spi);insertions++; } while(0)
'''
code = pre + port.replace(name+'(', 'port_alloc(') + native.replace(name+'(', 'lts_alloc(')
code += r'''
int main(void) {
    int cases=0,scope_differences=0;
    for(int old=0;old<2;old++) for(int dst=0;dst<2;dst++) for(int proto=0;proto<2;proto++)
    for(int fam=0;fam<2;fam++) for(int mark=0;mark<2;mark++) for(int spi=0;spi<3;spi++)
    for(int signal=0;signal<2;signal++) for(int range=0;range<2;range++) {
        int rets[2];
        for(int variant=0;variant<2;variant++) {
            struct net net={0};struct xfrm_state x={.net=&net,.id={.daddr=1,.proto=50},.props.family=2,.mark={.v=1,.m=~0U}};
            existing=(struct xfrm_state){.id={.spi=htonl(1),.daddr=dst?2:1,.proto=proto?51:50},.props.family=fam?10:2,.mark={.v=mark?2:1,.m=~0U}};
            present=old;pending=signal;insertions=attempts=0;
            int ret=variant?lts_alloc(&x,spi,spi+range,NULL):port_alloc(&x,spi,spi+range,NULL);
            bool collision=old && spi==1 && !proto && (variant || (!dst && !fam && !mark));
            bool success=spi!=0 && !collision;
            assert((ret==0)==success);
            assert(insertions==success && !x.lock && !net.xfrm.xfrm_state_lock && existing.refs==0);
            if(!success) assert(ret==(signal?-ERESTARTSYS:-ENOENT));
            rets[variant]=ret;cases++;
        }
        scope_differences+=rets[0]!=rets[1];
    }
    for(int dead=0;dead<2;dead++) for(int assigned=0;assigned<2;assigned++) {
        struct net net={0};struct xfrm_state x={.net=&net,.km.state=dead?XFRM_STATE_DEAD:0,.id.spi=assigned?htonl(7):0};
        present=pending=false;insertions=0;
        int ret=port_alloc(&x,1,1,NULL);
        assert((ret==0)==!dead && insertions==(!dead && !assigned));
        assert(!x.lock && !net.xfrm.xfrm_state_lock);cases++;
    }
    printf("{\"allocation_cases\":%d,\"scope_differences\":%d}\n",cases,scope_differences);
}
'''
with tempfile.TemporaryDirectory(prefix='xfrm-spi-scope-') as tmp:
    c=Path(tmp)/'test.c';c.write_text(code);binary=Path(tmp)/'test'
    subprocess.run(['clang','-fsanitize=address,undefined','-O1','-g',str(c),'-o',str(binary)],check=True)
    results=json.loads(subprocess.check_output([str(binary)],text=True))
report=dict(results=results,function_sha256=hashlib.sha256(port.encode()).hexdigest(),lts=LTS,
            limitations='Actual allocation bodies with synthetic lookup tables, random-source, reference and lock callbacks. Checks zero rejection, destination/mark/protocol/family collision scope, dead/existing states, lock balance, reference release and signal exit. Does not validate actual hash tables, concurrent allocation, IPsec packet selection, cryptography, socket permissions or CTS/runtime behavior.')
(Path(__file__).resolve().parent/'evidence/xfrm-spi-scope-test.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
