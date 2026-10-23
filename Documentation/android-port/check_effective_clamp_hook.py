#!/usr/bin/env python3
"""Check extracted effective-clamp selection and downstream bucket indexing.

Use the real bit-field layout and bucket-index helper with modeled task/group
inputs. SDK-equivalent zero stack initialization makes the old uninitialized
override deterministic; it does not demonstrate a leak in the SDK configuration.
No scheduler concurrency, frequency policy or real kernel fault is exercised.
"""
import ctypes
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
#define SCHED_CAPACITY_SCALE 1024U
#define UCLAMP_BUCKETS 5U
#define UCLAMP_BUCKET_DELTA 205U
#define bits_per(n) (32-__builtin_clz(n))
#define unlikely(x) (x)
#define min_t(type,a,b) ((type)(a)<(type)(b)?(type)(a):(type)(b))
enum uclamp_id {UCLAMP_MIN,UCLAMP_MAX,UCLAMP_CNT};
'''
MIDDLE=r'''
struct task_struct {struct uclamp_se req;};
static struct uclamp_se uclamp_default[UCLAMP_CNT];
static int mode,retval,proposal,proposed_bucket;
static struct uclamp_se uclamp_tg_restrict(struct task_struct *p,enum uclamp_id id) {return p->req;}
static void trace_android_rvh_uclamp_eff_get(struct task_struct *p,enum uclamp_id id,struct uclamp_se *max,struct uclamp_se *eff,int *ret) {
 *ret=retval;
 if(mode&1)eff->value=proposal;
 if(mode&2)eff->bucket_id=proposed_bucket;
 if(mode&4)max->value=proposal;
 if(mode&8)max->bucket_id=proposed_bucket;
}
'''
POST=r'''
void probe(int req,int max,int cb,int ret,int val,int bkt,int *out) {
 struct task_struct p={.req={.value=req,.bucket_id=uclamp_bucket_id(req),.user_defined=1}};
 uclamp_default[0]=(struct uclamp_se){.value=max,.bucket_id=uclamp_bucket_id(max)};
 mode=cb;retval=ret;proposal=val;proposed_bucket=bkt;
 struct uclamp_se r=uclamp_eff_get(&p,UCLAMP_MIN);
 out[0]=r.value;out[1]=r.bucket_id;out[2]=r.bucket_id>=UCLAMP_BUCKETS;
}
'''

def main():
    git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
    control=git('rev-parse','c65061c360d3').strip()
    report=dict(source_head=git('rev-parse','HEAD').strip(),control=control,scope=__doc__,results={},remote_sources_used=[])
    header=(ROOT/'include/linux/sched.h').read_text();struct=header[header.index('struct uclamp_se {'):].split('};',1)[0]+'};\n'
    helper=function((ROOT/'kernel/sched/sched.h').read_text(),'uclamp_bucket_id')
    total_cases=0
    with tempfile.TemporaryDirectory(prefix='effective-clamp-hook-') as temp:
        for count in [5,20]:
            delta=(1024+count//2)//count
            bucket=lambda v:min(v//delta,count-1)
            cases=list(itertools.product([0,1,205,512,1024],[0,205,512,1024],range(16),[-1,0,1],[0,1,delta-1,delta,512,1024,2047],range(1<<count.bit_length())))
            total_cases+=len(cases)
            for label,ref in [('port',None),('pre_fix_control',control)]:
                source=(ROOT/'kernel/sched/core.c').read_text() if ref is None else git('show',ref+':kernel/sched/core.c')
                body='static inline struct uclamp_se\n'+function(source,'uclamp_eff_get')
                prefix=PRE.replace('#define UCLAMP_BUCKETS 5U',f'#define UCLAMP_BUCKETS {count}U').replace('#define UCLAMP_BUCKET_DELTA 205U',f'#define UCLAMP_BUCKET_DELTA {delta}U')
                c=Path(temp)/(label+str(count)+'.c');c.write_text(prefix+struct+helper+MIDDLE+body+POST);lib=c.with_suffix('.so')
                subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror','-ftrivial-auto-var-init=zero',str(c),'-o',str(lib)],check=True)
                dll=ctypes.CDLL(str(lib));dll.probe.argtypes=[ctypes.c_int]*6+[ctypes.POINTER(ctypes.c_int)];dll.probe.restype=None
                failures=bad=0
                for req,maxval,mode,ret,value,bkt in cases:
                    maximum=value if mode&4 else maxval
                    expected=(value if mode&1 else 0) if ret else min(req,maximum)
                    out=(ctypes.c_int*3)();dll.probe(req,maxval,mode,ret,value,bkt,out)
                    failures+=list(out)!=[expected,bucket(expected),0];bad+=out[2]
                report['results'].setdefault(label,{})[str(count)]=dict(cases=len(cases),failures=failures,modeled_out_of_bounds_bucket_accesses=bad,function_sha256=hashlib.sha256(body.encode()).hexdigest())
    report.update(cases=total_cases,bucket_counts=[5,20],sdk_bucket_count=20,layout_sha256=hashlib.sha256(struct.encode()).hexdigest(),bucket_helper_sha256=hashlib.sha256(helper.encode()).hexdigest(),compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0])
    assert all(r['failures']==0 for r in report['results']['port'].values())
    assert all(r['modeled_out_of_bounds_bucket_accesses']>0 for r in report['results']['pre_fix_control'].values())
    (ROOT/'Documentation/android-port/evidence/effective-clamp-hook-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
