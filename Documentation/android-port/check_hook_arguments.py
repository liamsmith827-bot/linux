#!/usr/bin/env python3
"""Check hook forwarding with extracted tracepoint macros and host dispatch shims.

This exercises argument transport, not kernel registration, RCU, or static-call
patching. The old header is a negative control for both corrected signatures.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
baseline = '7a6afb06646edc0aae0378cff8c8c1d68f75413e'

def parenthesized(s, start):
    start = s.index('(', start) + 1
    end, depth = start, 1
    while depth:
        depth += (s[end] == '(') - (s[end] == ')')
        end += 1
    return s[start:end-1]

def split(s):
    parts, start, depth = [], 0, 0
    for i, c in enumerate(s):
        depth += (c in '([') - (c in ')]')
        if c == ',' and depth == 0:
            parts.append(s[start:i].strip())
            start = i + 1
    parts.append(s[start:].strip())
    return parts

def declaration(text, name):
    start = text.index('DECLARE_HOOK(' + name + ',')
    return 'DECLARE_HOOK(' + parenthesized(text, start) + ');\n'

def macro(text, name):
    start = text.index('#define ' + name + '(')
    end = text.index('\n', start)
    while text[end-1] == '\\':
        end = text.index('\n', end+1)
    return text[start:end+1]

exceptions = {'android_rvh_rq_qos_wait', 'android_rvh_blk_mq_get_tag',
              'android_rvh_io_schedule_prepare'}
allowed, declarations = [], 0
for path in sorted((root/'include/trace/hooks').glob('*.h')):
    text = path.read_text()
    for match in re.finditer(r'DECLARE_(?:RESTRICTED_)?HOOK\(\s*(android_\w+)', text):
        declarations += 1
        d = parenthesized(text, match.start())
        proto = split(parenthesized(d, d.index('TP_PROTO')))
        args = split(parenthesized(d, d.index('TP_ARGS')))
        names = []
        for param in proto:
            f = re.search(r'\(\s*\*\s*(\w+)\s*\)', param)
            if f:
                names.append(f[1])
            elif param != 'void':
                names.append(re.findall(r'[a-zA-Z_]\w*', re.sub(r'\[[^]]*\]', '', param))[-1])
        if args == ['']:
            args = []
        if names != args:
            assert match[1] in exceptions and names == ['ignored'] and args == ['NULL'], (path, match[1], names, args)
            allowed.append(match[1])
assert set(allowed) == exceptions

tracepoint = (root/'include/linux/tracepoint.h').read_text()
macros = ''.join(macro(tracepoint, n) for n in
                 ('__DO_TRACE_CALL', '__DECLARE_TRACE', '__DEFINE_TRACE_EXT'))
shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#define PARAMS(...) __VA_ARGS__
#define TP_PROTO(...) __VA_ARGS__
#define TP_ARGS(...) __VA_ARGS__
#define __section(x)
#define __used
#define STATIC_CALL_KEY(n) key_##n
#define STATIC_CALL_TRAMP_ADDR(n) NULL
#define STATIC_KEY_FALSE_INIT 0
#define __TRACEPOINT_ENTRY(n)
#define CFI_NOSEAL(n)
#define DEFINE_STATIC_CALL(n, f)
#define DEFINE_RUST_DO_TRACE(n, proto, args)
#define READ_ONCE(x) (x)
#define rcu_dereference_raw(x) (x)
#define static_branch_unlikely(x) (*(x))
#define guard(x) empty_guard
#define IS_ENABLED(x) 0
#define WARN_ONCE(...) ((void)0)
#define static_call(n) dispatch_##n
static void empty_guard(void) {}
static bool online = true, single;
struct static_call_key { int dummy; };
struct tracepoint_func { void *func, *data; };
struct tracepoint {
    const char *name;
    int key;
    struct static_call_key *static_call_key;
    void *static_call_tramp, *iterator, *probestub, *ext;
    struct tracepoint_func *funcs;
};
#define __DECLARE_TRACE_COMMON(name, proto, args, data_proto) \
    int __traceiter_##name(data_proto); \
    extern struct tracepoint __tracepoint_##name; \
    struct static_call_key key_tp_func_##name; \
    static void dispatch_tp_func_##name(data_proto);
#define DECLARE_HOOK(name, proto, args) \
    __DECLARE_TRACE(name, PARAMS(proto), PARAMS(args), online, PARAMS(void *__data, proto)) \
    __DEFINE_TRACE_EXT(name, NULL, PARAMS(proto), PARAMS(args))
'''
test = r'''
static unsigned long seen_reclaimed, seen_target, seen_start, seen_end;
static unsigned seen_order, calls;
static bool *seen_bypass;
static int cookie;
static void reclaim_observer(void *data, unsigned long reclaimed,
                             unsigned long target, unsigned order, bool *bypass)
{
    assert(data == &cookie);
    seen_reclaimed = reclaimed; seen_target = target;
    seen_order = order; seen_bypass = bypass; calls++;
}
static void range_observer(void *data, unsigned long start, RANGE_END end)
{
    assert(data == &cookie); seen_start = start; seen_end = end; calls++;
}
static void dispatch_tp_func_android_vh_mglru_should_abort_scan(void *data,
        unsigned long reclaimed, unsigned long target, unsigned order, bool *bypass)
{
    if (single) reclaim_observer(data, reclaimed, target, order, bypass);
    else __traceiter_android_vh_mglru_should_abort_scan(data, reclaimed, target, order, bypass);
}
static void dispatch_tp_func_android_vh_alloc_contig_range_not_isolated(void *data,
        unsigned long start, RANGE_END end)
{
    if (single) range_observer(data, start, end);
    else __traceiter_android_vh_alloc_contig_range_not_isolated(data, start, end);
}
int main(void)
{
    struct tracepoint_func reclaim[] = {{reclaim_observer, &cookie}, {reclaim_observer, &cookie}, {0}};
    struct tracepoint_func range[] = {{range_observer, &cookie}, {range_observer, &cookie}, {0}};
    struct tracepoint *r = &__tracepoint_android_vh_mglru_should_abort_scan;
    struct tracepoint *c = &__tracepoint_android_vh_alloc_contig_range_not_isolated;
    unsigned failures = 0, cases = 0;
    bool bypass = false;
    _Static_assert(sizeof(unsigned long) == 8, "64-bit host required");
    r->funcs = reclaim; c->funcs = range;
    for (unsigned count = 0; count <= 2; count++) {
        single = count == 1;
        r->key = c->key = count != 0;
        reclaim[1].func = count == 2 ? reclaim_observer : NULL;
        range[1].func = count == 2 ? range_observer : NULL;
        for (unsigned on = 0; on <= 1; on++) {
            online = on;
            calls = 0;
            trace_android_vh_mglru_should_abort_scan(7, 31, 9, &bypass);
            assert(calls == (on ? count : 0));
            if (calls) {
                assert(seen_order == 9 && seen_bypass == &bypass);
                failures += seen_reclaimed != 7 || seen_target != 31;
            }
            cases++;
            for (unsigned high = 0; high <= 1; high++) {
                unsigned long start = high ? (1UL << 33) + 5 : 5;
                unsigned long end = start + 71;
                calls = 0;
                trace_android_vh_alloc_contig_range_not_isolated(start, end);
                assert(calls == (on ? count : 0));
                if (calls) failures += seen_start != start || seen_end != end;
                cases++;
            }
        }
    }
    printf("{\"cases\":%u,\"argument_failures\":%u}\n", cases, failures);
    return 0;
}
'''
paths = [('include/trace/hooks/vmscan.h', 'android_vh_mglru_should_abort_scan'),
         ('include/trace/hooks/mm.h', 'android_vh_alloc_contig_range_not_isolated')]
results = {}
with tempfile.TemporaryDirectory(prefix='sdk-hook-args-') as tmp:
    tmp = Path(tmp)
    for version in ('current', 'old'):
        decls = ''
        for path, hook in paths:
            text = (root/path).read_text() if version == 'current' else subprocess.check_output(
                ['git', 'show', baseline+':'+path], cwd=root, text=True)
            decls += declaration(text, hook)
        for dispatch in ('static', 'iterator'):
            definitions = macros
            if dispatch == 'iterator':
                definitions += '\n#undef __DO_TRACE_CALL\n#define __DO_TRACE_CALL(name, args) __traceiter_##name(NULL, args)\n'
            code = shim + definitions + decls + test.replace('RANGE_END', 'unsigned long' if version == 'current' else 'unsigned int')
            src, exe = tmp/'test.c', tmp/'test'
            src.write_text(code)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                            '-Wno-unused-function', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                            str(src), '-o', str(exe)], check=True)
            result = json.loads(subprocess.check_output([str(exe)], text=True))
            assert result['argument_failures'] == (0 if version == 'current' else (3 if dispatch == 'static' else 4)), (version, dispatch, result)
            result['extracted_declarations_sha256'] = hashlib.sha256(decls.encode()).hexdigest()
            results[version+'_'+dispatch] = result
report = {'declarations_checked': declarations, 'intentional_null_forwarding': sorted(allowed),
          'old_header_commit': baseline, 'tracepoint_macros_sha256': hashlib.sha256(macros.encode()).hexdigest(),
          'results': results,
          'scope': 'Extracted kernel tracepoint macros with host shims for CPU/static keys, dispatch and lifetime. No kernel execution, registration, RCU or code-patching validation.'}
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
