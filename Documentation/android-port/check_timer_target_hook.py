#!/usr/bin/env python3
"""Exercise extracted timer selector with a modeled topology and callback.

Masks, RCU and timer-base consumption are host shims. Invalid accesses are
counted without touching out-of-range memory. No actual timer, hotplug race,
power-saving measurement or kernel fault is exercised.
"""
import ctypes
import hashlib
import itertools
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
PRE = r'''
#include <stdbool.h>
#include <limits.h>
#define nr_cpu_ids 4U
#define HK_TYPE_KERNEL_NOISE 1
#define unlikely(x) (x)
#define guard(x) fake_guard
struct cpumask {unsigned bits;};
struct sched_domain {struct cpumask span;};
static struct cpumask online, housekeeping, idle;
static struct sched_domain domains[4];
static int current_cpu, mode, proposal, invalid_accesses;
static int test_cpu(int cpu,const struct cpumask *m) {
 if ((unsigned)cpu>=nr_cpu_ids) {invalid_accesses++;return 0;}
 return !!(m->bits & (1U<<cpu));
}
static inline int cpu_online(int cpu) {return test_cpu(cpu,&online);}
static int housekeeping_cpu(int cpu,int type) {return test_cpu(cpu,&housekeeping);}
static int idle_cpu(int cpu) {return test_cpu(cpu,&idle);}
static int smp_processor_id(void) {return current_cpu;}
static const struct cpumask *housekeeping_cpumask(int type) {return &housekeeping;}
static int housekeeping_any_cpu(int type) {
 unsigned mask=housekeeping.bits & online.bits;
 for(int i=0;i<4;i++) if(mask&(1U<<i)) return i;
 return current_cpu;
}
static void trace_android_rvh_get_nohz_timer_target(int *cpu,bool *done) {
 if(mode&1)*cpu=proposal;
 if(mode&2)*done=true;
}
static void fake_guard(void) {}
static struct sched_domain *domain(int cpu) {
 if ((unsigned)cpu>=nr_cpu_ids) {invalid_accesses++;return 0;}
 return &domains[cpu];
}
#define for_each_domain(cpu,sd) for(sd=domain(cpu);sd;sd=0)
#define sched_domain_span(sd) (&(sd)->span)
#define for_each_cpu_and(i,a,b) for(i=0;i<4;i++) if(test_cpu(i,a)&&test_cpu(i,b))
'''
POST = r'''
void probe(int cpu,int om,int hm,int im,int dm,int cb,int dest,int *out) {
 current_cpu=cpu;online.bits=om;housekeeping.bits=hm;idle.bits=im;
 for(int i=0;i<4;i++) domains[i].span.bits=dm ? (om & (3U<<((i/2)*2))) : om;
 mode=cb;proposal=dest;invalid_accesses=0;
 out[0]=get_nohz_timer_target();
 /* Caller immediately consumes the returned per-CPU base. */
 if((unsigned)out[0]>=nr_cpu_ids) invalid_accesses++;
 out[1]=invalid_accesses;
}
'''

def main():
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True)
    control = git('rev-parse', '5cfb4a4f0488').strip()
    lts = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
    path = 'kernel/sched/core.c'
    choices = [-2147483648, -1, 0, 1, 2, 3, 4, 2147483647]
    report = dict(source_head=git('rev-parse', 'HEAD').strip(), control=control,
                  scope=__doc__, results={}, remote_sources_used=[])
    valid = lambda cpu, mask: 0 <= cpu < 4 and bool(mask & (1 << cpu))
    first = lambda mask: next(i for i in range(4) if mask & (1 << i))
    with tempfile.TemporaryDirectory(prefix='timer-target-hook-') as temp:
        libs = {}
        for label, ref in [('port', None), ('pre_fix_control', control), ('lts', lts)]:
            source = (ROOT/path).read_text() if ref is None else git('show', ref+':'+path)
            body = function(source, 'get_nohz_timer_target')
            prefix = PRE if ref != lts else PRE.replace('static void trace_android_rvh_get_nohz_timer_target', 'static inline void trace_android_rvh_get_nohz_timer_target')
            c = Path(temp)/(label+'.c')
            c.write_text(prefix + body + POST)
            lib = c.with_suffix('.so')
            subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Werror',str(c),'-o',str(lib)], check=True)
            dll = ctypes.CDLL(str(lib)); dll.probe.argtypes=[ctypes.c_int]*7+[ctypes.POINTER(ctypes.c_int)];dll.probe.restype=None
            libs[label]=dll
            report['results'][label]=dict(failures=0,modeled_invalid_accesses=0,function_sha256=hashlib.sha256(body.encode()).hexdigest())
        cases=0; baseline=0; preserved=0
        for cpu, om, hm, im, dm, mode, dest in itertools.product(range(4), range(1,16), range(1,16), range(16), range(2), range(4), choices):
            if not valid(cpu,om) or not (om & hm): continue
            selected = dest if mode & 1 else cpu
            done = bool(mode & 2)
            if not valid(selected,om): selected=cpu;done=False
            native = lambda seed: (seed if valid(seed,hm) and not valid(seed,im) else
                next((i for i in range(4) if i!=seed and valid(i,om & hm & ~im & ((3<<((seed//2)*2)) if dm else 15))),
                     seed if valid(seed,hm) else first(om & hm)))
            expected = selected if done and valid(selected,hm) else native(selected)
            outs={}
            for label,dll in libs.items():
                out=(ctypes.c_int*2)();dll.probe(cpu,om,hm,im,dm,mode,dest,out);outs[label]=list(out)
                wanted=native(cpu) if label=='lts' else expected
                r=report['results'][label];r['failures']+=list(out)!=[wanted,0];r['modeled_invalid_accesses']+=out[1]
            if mode==0:
                baseline+=1;assert outs['port']==outs['lts']
            if valid(dest if mode&1 else cpu,om) and (not done or valid(selected,hm)):
                preserved+=1;assert outs['port']==outs['pre_fix_control']
            cases+=1
    report.update(cases=cases,native_default_comparisons=baseline,valid_callback_behavior_comparisons=preserved)
    assert report['results']['port']['failures']==report['results']['lts']['failures']==0
    assert report['results']['pre_fix_control']['modeled_invalid_accesses']>0
    report['compiler']=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]
    (ROOT/'Documentation/android-port/evidence/timer-target-hook-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
