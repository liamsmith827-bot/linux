#!/usr/bin/env python3
"""Extracted utilization callback checks; host shims, not scheduler execution.

The pre-fix build uses zero automatic-variable initialization as the SDK does.
The explicit fits initialization removes reliance on that build option; it is
not claimed as a runtime failure reproduced in the SDK configuration.
"""
import ctypes, hashlib, itertools, json, subprocess, tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
PRE=r'''
#include <stdbool.h>
#include <stdint.h>
#define SCHED_CAPACITY_SCALE 1024
#define UCLAMP_MIN 0
#define UCLAMP_MAX 1
#define SCHED_FLAG_UTIL_CLAMP_MIN 1
#define SCHED_FLAG_UTIL_CLAMP_MAX 2
#define EINVAL 22
#define min(a,b) ((a)<(b)?(a):(b))
struct task_struct { struct {unsigned int value;} uclamp_req[2]; };
struct sched_attr {unsigned int sched_flags, sched_util_min, sched_util_max;};
static int mode, result, enables, used;
static unsigned long cap, orig, actual;
static void sched_uclamp_enable(void) {enables++;}
static void trace_android_vh_uclamp_validate(struct task_struct *p, const struct sched_attr *a, int *ret, bool *done) {
 if(mode) {*done=true;*ret=result;}
}
static unsigned long capacity_of(int cpu) {return cap;}
static unsigned long arch_scale_cpu_capacity(int cpu) {return orig;}
static unsigned long get_actual_cpu_capacity(int cpu) {return actual;}
static bool uclamp_is_used(void) {return used;}
static bool fits_capacity(unsigned long util, unsigned long capacity) {return util*1280 < capacity*1024;}
static void trace_android_rvh_util_fits_cpu(unsigned long util, unsigned long mi, unsigned long ma, int cpu, bool *fits, bool *done) {
 if(mode) {*done=true; if(mode==2) *fits=result;}
}
'''
POST=r'''
void probe_validate(int mi, int ma, unsigned int flags, unsigned int ami, unsigned int ama, int active, int ret, int *out) {
 struct task_struct p={{{mi},{ma}}};struct sched_attr a={flags,ami,ama};
 mode=active;result=ret;enables=0;
 out[0]=uclamp_validate(&p,&a);out[1]=enables;
}
int probe_fits(unsigned long util, unsigned long mi, unsigned long ma, unsigned long capacity, unsigned long original, unsigned long avail, int clamped, int active, int ret) {
 cap=capacity;orig=original;actual=avail;used=clamped;mode=active;result=ret;
 return util_fits_cpu(util,mi,ma,0);
}
'''
def main():
 git=lambda *a:subprocess.check_output(['git','-C',str(ROOT),*a],text=True)
 old=git('rev-parse','b46e8cbd7368').strip();lts='2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
 report=dict(source_head=git('rev-parse','HEAD').strip(),control=old,scope=__doc__,results={},remote_sources_used=[])
 libs={};sha={}
 with tempfile.TemporaryDirectory(prefix='utilization-hooks-') as temp:
  for label,ref in [('port',None),('pre_fix_control',old),('lts',lts)]:
   source=lambda p:(ROOT/p).read_text() if ref is None else git('show',ref+':'+p)
   bodies=[function(source('kernel/sched/syscalls.c'),'uclamp_validate'),function(source('kernel/sched/fair.c'),'util_fits_cpu')]
   if label=='port':assert 'bool fits = false, uclamp_max_fits, done = false;' in bodies[1]
   code=PRE+'\n'.join(bodies)+POST;c=Path(temp)/(label+'.c');c.write_text(code);lib=c.with_suffix('.so')
   extra=['-Wno-error=maybe-uninitialized'] if label=='pre_fix_control' else []
   compiled=subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror','-Wno-unused-function','-ftrivial-auto-var-init=zero',*extra,str(c),'-o',str(lib)],check=True,capture_output=True,text=True)
   if compiled.stderr:
    report.setdefault('compiler_diagnostics',{})[label]=compiled.stderr.replace(temp,'<temporary directory>')
   dll=ctypes.CDLL(str(lib));dll.probe_validate.argtypes=[ctypes.c_int]*7+[ctypes.POINTER(ctypes.c_int)];dll.probe_validate.restype=None
   dll.probe_fits.argtypes=[ctypes.c_ulong]*6+[ctypes.c_int]*3;dll.probe_fits.restype=ctypes.c_int
   libs[label]=dll;sha[label]=[hashlib.sha256(b.encode()).hexdigest() for b in bodies]
  validation=list(itertools.product([0,512],[512,1024],[1,2,3],[0,512,1024,1025,2048,-1],[0,512,1024,1025,2048,-1],range(2),[-22,0,1]))
  fitness=list(itertools.product([0,512,1024,2048],[0,512,1024],[512,1024],[1,512,1024],[512,1024],[256,1024],range(2),range(3),range(2)))
  for label in ['port','pre_fix_control']:
   badv=badf=miss=0
   for args in validation:
    out=(ctypes.c_int*2)();libs[label].probe_validate(*args,out)
    if args[5]:expect=[args[6],int(args[6]==0)]
    else:
     native=(ctypes.c_int*2)();libs['lts'].probe_validate(*args,native);expect=list(native)
    badv+=list(out)!=expect;miss+=out[0]==0 and not out[1]
   for args in fitness:
    actual=libs[label].probe_fits(*args)
    expect=libs['lts'].probe_fits(*args) if args[7]==0 else (args[8] if args[7]==2 else 0)
    badf+=actual!=expect
   report['results'][label]=dict(validation_failures=badv,successful_validation_without_enable=miss,fitness_failures=badf,function_sha256=sha[label])
  report['validation_cases']=len(validation);report['fitness_cases']=len(fitness)
 assert report['results']['port']['validation_failures']==report['results']['port']['fitness_failures']==0
 assert report['results']['pre_fix_control']['successful_validation_without_enable']>0
 report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
 (ROOT/'Documentation/android-port/evidence/utilization-hooks-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
