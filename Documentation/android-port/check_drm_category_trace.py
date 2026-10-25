#!/usr/bin/env python3
"""Check extracted DRM printer routing and atomic-commit flow with host shims.

No kernel, tracefs, display hardware or concurrent parameter updates are tested.
"""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
PRE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#define unlikely(x) (x)
#define BIT(x) (1UL << (x))
#define _THIS_IP_ ((uintptr_t)1)
#define KERN_DEBUG "debug"
#define dev_info(...) (syslog_lines++)
#define drm_dbg_atomic(...) ((void)0)
enum drm_debug_category { DRM_UT_OTHER, DRM_UT_STATE };
static unsigned long __drm_debug, __drm_debug_trace;
static int syslog_lines, trace_lines, dumps, checks, commits, check_error, commit_error;
struct device { int unused; };
struct drm_atomic_state;
struct drm_device;
struct drm_mode_config_funcs {
    int (*atomic_commit)(struct drm_device *, struct drm_atomic_state *, bool);
};
struct drm_mode_config { const struct drm_mode_config_funcs *funcs; };
struct drm_device { struct device *dev; struct drm_mode_config mode_config; };
struct drm_atomic_state { struct drm_device *dev; };
struct va_format { int unused; };
struct drm_printer {
    void (*printfn)(struct drm_printer *, struct va_format *);
    void *arg;
    const void *origin;
    const char *prefix;
    enum drm_debug_category category;
};
static void __drm_dev_vprintk(const struct device *dev, const char *level,
                             const void *origin, const char *prefix, struct va_format *vaf) {
    syslog_lines++;
}
static void drm_trace_printf(const char *fmt, ...) { trace_lines++; }
'''
MACROS = r'''
#if DYNAMIC
#define __drm_debug_enabled(category) true
#else
#define __drm_debug_enabled(category) drm_debug_enabled_raw(category)
#endif
#define drm_debug_enabled(category) drm_debug_enabled_raw(category)
'''
SHIMS = r'''
static void drm_atomic_print_new_state(struct drm_atomic_state *state, struct drm_printer *p) {
    struct va_format v = {0};
    assert(checks == 0 && commits == 0);
    dumps++;
    p->printfn(p, &v);
}
static int drm_atomic_check_only(struct drm_atomic_state *state) {
    checks++;
    assert(commits == 0);
    return check_error;
}
static int driver_commit(struct drm_device *dev, struct drm_atomic_state *state, bool nonblock) {
    assert(dev == state->dev && checks == 1 && !nonblock);
    commits++;
    return commit_error;
}
'''
MAIN = r'''
int main(void) {
    struct device dev = {0};
    const struct drm_mode_config_funcs funcs = {.atomic_commit=driver_commit};
    struct drm_device drm = {.dev=&dev, .mode_config={.funcs=&funcs}};
    struct drm_atomic_state state = {.dev=&drm};
    const unsigned long masks[] = {0, BIT(DRM_UT_STATE), BIT(DRM_UT_OTHER),
                                   BIT(DRM_UT_STATE)|BIT(DRM_UT_OTHER)};
    int lost_trace = 0, unexpected_syslog = 0, atomic_cases = 0, direct_cases = 0;
    for (unsigned d=0; d<4; d++) for (unsigned t=0; t<4; t++) {
        __drm_debug=masks[d]; __drm_debug_trace=masks[t];
        int log_enabled=!!(__drm_debug & BIT(DRM_UT_STATE));
        int trace_enabled=!!(__drm_debug_trace & BIT(DRM_UT_STATE));
        for (int failure=0; failure<3; failure++) {
            syslog_lines=trace_lines=dumps=checks=commits=0;
            check_error=failure==1 ? -EDEADLK : 0;
            commit_error=failure==2 ? -ENOSPC : 0;
            int ret=drm_atomic_commit(&state);
            assert(ret==(check_error ? check_error : commit_error));
            assert(checks==1 && commits==!check_error);
            assert(dumps<=1 && syslog_lines<=1 && trace_lines<=1);
            lost_trace += trace_enabled && !trace_lines;
            unexpected_syslog += !log_enabled && syslog_lines;
            if (PORT) {
                assert(dumps==(log_enabled || trace_enabled));
                assert(syslog_lines==log_enabled && trace_lines==trace_enabled);
            }
            atomic_cases++;
        }
        if (!NATIVE) {
            syslog_lines=trace_lines=0;
            struct va_format v={0};
            struct drm_printer p=drm_debug_category_printer(DRM_UT_STATE, "direct");
            p.printfn(&p,&v);
            unexpected_syslog += !log_enabled && syslog_lines;
            if (PORT) assert(syslog_lines==log_enabled && trace_lines==trace_enabled);
            direct_cases++;
        }
    }
    printf("{\"atomic_cases\":%d,\"direct_printer_cases\":%d,\"lost_trace\":%d,\"unexpected_syslog\":%d}\n",
           atomic_cases,direct_cases,lost_trace,unexpected_syslog);
    return 0;
}
'''


def main():
    results = {}
    with tempfile.TemporaryDirectory(prefix='drm-category-trace-') as tmp:
        for label, ref in [('port', None), ('ack_control', ACK), ('native_control', LTS)]:
            def read(path, override=None):
                revision = override or ref
                return ((ROOT/path).read_text() if revision is None else
                        subprocess.check_output(['git', 'show', revision+':'+path], cwd=ROOT, text=True))
            # Native atomic flow uses its info printer; the unused category shim
            # is supplied only so the same harness compiles for that control.
            header = read('include/drm/drm_print.h', ACK if label=='native_control' else None)
            printer = read('drivers/gpu/drm/drm_print.c', ACK if label=='native_control' else None)
            atomic = read('drivers/gpu/drm/drm_atomic.c')
            helpers = ''.join(function(header, n) for n in ['drm_debug_enabled_raw','drm_debug_trace_enabled'])
            callbacks = ''.join(function(printer, n) for n in ['__drm_printfn_info','__drm_printfn_dbg','__drm_printfn_trace','__drm_printfn_noop'])
            constructor = 'static inline struct drm_printer\n'+function(header,'drm_debug_category_printer')
            info = function(header,'drm_info_printer')
            commit = function(atomic,'drm_atomic_commit')
            code = PRE+helpers+MACROS+callbacks+constructor+info+SHIMS+commit+MAIN
            variants = {}
            for dynamic in [0,1]:
                src=Path(tmp)/(label+str(dynamic)+'.c');exe=src.with_suffix('')
                src.write_text(code)
                subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
                                '-fno-omit-frame-pointer','-fno-pie','-no-pie',
                                '-DDYNAMIC='+str(dynamic),'-DPORT='+str(int(label=='port')),
                                '-DNATIVE='+str(int(label=='native_control')),str(src),'-o',str(exe)],
                               check=True,capture_output=True,text=True)
                run=subprocess.run([str(exe)],check=True,capture_output=True,text=True)
                assert not run.stderr,run.stderr
                variants[str(dynamic)]=json.loads(run.stdout)
            results[label]=dict(atomic_function_sha256=hashlib.sha256(commit.encode()).hexdigest(),
                                category_function_sha256=hashlib.sha256(constructor.encode()).hexdigest(),variants=variants)
    for r in results['port']['variants'].values():
        assert r['lost_trace']==r['unexpected_syslog']==0
    assert results['ack_control']['variants']['1']['unexpected_syslog']>0
    assert results['ack_control']['variants']['0']['lost_trace']>0
    print(json.dumps(dict(results=results,limitations='Extracted-function host shims with ASan/UBSan; no kernel display, tracefs, dyndbg callsite machinery or concurrent parameter-update test.'),indent=2))


if __name__=='__main__':
    main()
