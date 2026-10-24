#!/usr/bin/env python3
"""Exercise actual post-submit tail with modeled bio/request completion lifetimes.

Native submission, refcount primitives, driver completion and hook registration
are host models. This is not block IO, concurrency or kernel runtime validation.
"""
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
from check_scx_donor_retry import function

ROOT=Path(__file__).resolve().parents[2]
CONTROL='e43fbaaa4eaf8d766329854c00e292b438e16cb7'
PRE=r'''
#include <stdbool.h>
#include <stdint.h>
#define RQF_USE_SCHED 1
struct bio {unsigned bi_opf;int refs;};
struct request_queue {int nr_hw_queues;};
struct blk_mq_hw_ctx {int dispatch_busy;};
struct request {unsigned rq_flags;struct blk_mq_hw_ctx *mq_hctx;int refs;};
struct blk_plug {int unused;};
static struct bio object_bio;
static struct request object_rq;
static int registration,initial_enabled,enabled,complete_early,flush_consumed;
static int events,bad,refs_taken,bio_gets,bio_puts,rq_puts,completions,path,pre_calls;
static void complete(void) {
 if(completions++) {bad++;return;}
 if(object_bio.refs<=0||object_rq.refs<=0)bad++;
 object_bio.refs--;object_rq.refs--;
}
static void handed_off(int step) {
 path=step;
 if(registration==2)enabled=1;
 if(complete_early)complete();
}
static void trace_android_rvh_submit_bio_pre(struct bio *b,struct request *r) {
 pre_calls++;if(registration==1)enabled=1;
 if(b->refs<=0||r->refs<=0)bad++;
}
static bool trace_android_rvh_submit_bio_post_enabled(void) {return enabled;}
static bool req_ref_inc_not_zero(struct request *r) {if(!r->refs)return false;r->refs++;refs_taken++;return true;}
static void bio_get(struct bio *b) {b->refs++;bio_gets++;}
static void bio_put(struct bio *b) {if(b->refs<=0)bad++;b->refs--;bio_puts++;}
static void blk_mq_put_rq_ref(struct request *r) {if(r->refs<=0)bad++;r->refs--;rq_puts++;}
static void trace_android_rvh_submit_bio_post(struct bio *b,struct request *r) {
 if(!enabled)return;
 events++;if(b->refs<=0||r->refs<=0)bad++;
}
static bool op_is_flush(unsigned op) {return op;}
static bool blk_insert_flush(struct request *r) {if(flush_consumed)handed_off(1);return flush_consumed;}
static void blk_add_rq_to_plug(struct blk_plug *p,struct request *r) {handed_off(2);}
static void blk_mq_insert_request(struct request *r,int flags) {}
static void blk_mq_run_hw_queue(struct blk_mq_hw_ctx *h,bool async) {handed_off(3);}
static void blk_mq_try_issue_directly(struct blk_mq_hw_ctx *h,struct request *r) {handed_off(4);}
#define blk_mq_run_dispatch_ops(q,op) op
'''
POST=r'''
void probe(int initial,int when,int early,int flush,int consumed,int plugged,int sched,int busy,int queues,int sync,int *out) {
 struct request_queue q={queues};struct blk_mq_hw_ctx hctx={busy};struct blk_plug plug={0};
 object_bio=(struct bio){flush,1};object_rq=(struct request){sched,&hctx,1};
 initial_enabled=enabled=initial;registration=when;complete_early=early;flush_consumed=consumed;
 events=bad=refs_taken=bio_gets=bio_puts=rq_puts=completions=path=pre_calls=0;
 submit_tail(&object_bio,&object_rq,&q,&hctx,plugged?&plug:0,sync);
 out[0]=events;out[1]=bad;out[2]=path;out[3]=pre_calls;
 out[4]=object_bio.refs;out[5]=object_rq.refs;
 out[6]=refs_taken;out[7]=bio_gets;out[8]=bio_puts;out[9]=rq_puts;
 if(!completions)complete();
 out[10]=object_bio.refs;out[11]=object_rq.refs;out[12]=completions;
}
'''
def tail(source):
    f=function(source,'blk_mq_submit_bio')
    a=f.index('\ttrace_android_rvh_submit_bio_pre(bio, rq);')
    b=f.index('\nqueue_exit:',a)
    return f[a:b]

def main():
    git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
    report={'source_head':git('rev-parse','HEAD').strip(),'control':CONTROL,'scope':__doc__,'results':{},'remote_sources_used':[]}
    cases=list(itertools.product(range(2),range(3),range(2),range(2),range(2),range(2),range(2),range(2),[1,2],range(2)))
    with tempfile.TemporaryDirectory(prefix='block-submit-lifetime-') as tmp:
        for label,ref in [('port',None),('unprotected_control',CONTROL)]:
            src=(ROOT/'block/blk-mq.c').read_text() if ref is None else git('show',ref+':block/blk-mq.c')
            code=tail(src)
            wrapper='\nstatic void submit_tail(struct bio *bio,struct request *rq,struct request_queue *q,struct blk_mq_hw_ctx *hctx,struct blk_plug *plug,int is_sync) {bool post_hook __attribute__((unused));\n'+code+'\n}\n'
            c=Path(tmp)/(label+'.c');c.write_text(PRE+wrapper+POST);lib=c.with_suffix('.so')
            cp=subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror','-Wno-unused-function',str(c),'-o',str(lib)],check=True,capture_output=True,text=True)
            dll=ctypes.CDLL(str(lib));dll.probe.argtypes=[ctypes.c_int]*10+[ctypes.POINTER(ctypes.c_int)];dll.probe.restype=None
            bad_cases=controlflow_failures=default_cases=late_registration=0
            for case in cases:
                initial,when,early,flush,consumed,plugged,sched,busy,queues,sync=case
                takes=int(bool(initial or when==1));events=takes if label=='port' else int(bool(initial or when in (1,2)))
                selected=1 if flush and consumed else 2 if plugged else 3 if sched or busy and (queues==1 or not sync) else 4
                refs=takes if label=='port' else 0
                out=(ctypes.c_int*13)();dll.probe(*case,out)
                expected=[events,0,selected,1,1-early,1-early,refs,refs,refs,refs,0,0,1]
                bad_cases+=out[1]>0
                controlflow_failures+=any(out[i]!=expected[i] for i in range(13) if i!=1)
                if not initial and when==0:
                    default_cases+=1;assert list(out)==expected
                if not initial and when==2:late_registration+=1
            report['results'][label]={'cases':len(cases),'callback_lifetime_failures':bad_cases,'controlflow_or_ref_balance_failures':controlflow_failures,'no_callback_cases':default_cases,'registration_after_snapshot_cases':late_registration,'tail_sha256':hashlib.sha256(code.encode()).hexdigest(),'compiler_stderr':cp.stderr}
    assert report['results']['port']['callback_lifetime_failures']==0
    assert report['results']['port']['controlflow_or_ref_balance_failures']==0
    assert report['results']['unprotected_control']['callback_lifetime_failures']>0
    assert report['results']['unprotected_control']['controlflow_or_ref_balance_failures']==0
    report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
    (ROOT/'Documentation/android-port/evidence/block-submit-hook-lifetime-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
