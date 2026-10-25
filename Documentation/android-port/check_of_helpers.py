#!/usr/bin/env python3
"""Check extracted OF helper bounds and root references using host shims.

Does not execute a kernel, read a device tree or load a module. The ACK u8
negative control deliberately exercises its U32_MAX index addition wrap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
ack = '23112ce1886ea26b19be03207c0227a06a6ca009'
def function(source, name):
    match = re.search(r'^[\w][^\n]*\b' + name + r'\([^;]*?\n\{.*?^\}', source, re.M | re.S)
    assert match, name
    return match[0]
sources = {p: (root / p).read_text() for p in ['drivers/of/property.c', 'drivers/of/base.c']}
u8 = function(sources['drivers/of/property.c'], 'of_property_read_u8_index')
old = function(subprocess.check_output(['git', 'show', ack + ':drivers/of/property.c'], cwd=root, text=True), 'of_property_read_u8_index').replace('of_property_read_u8_index(', 'old_read(')
wrappers = '\n'.join(function(sources['drivers/of/base.c'], name) for name in ['of_machine_device_match', 'of_machine_get_match_data'])
shim = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef uint8_t u8;
struct device_node { int unused; };
struct of_device_id { const void *data; };
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static const u8 bytes[] = {17, 33, 255};
static int error;
static size_t property_size;
static void *of_find_property_value_of_size(const struct device_node *np,
        const char *name, u32 min, u32 max, size_t *len) {
    (void)np; (void)name; (void)max;
    if (error) return ERR_PTR(error);
    if (property_size < min) return ERR_PTR(-EOVERFLOW);
    if (len) *len = property_size;
    return (void *)bytes;
}
static struct device_node node;
static int refs, gets, puts;
static bool have_root, have_match;
static const struct of_device_id table[] = {{&node}, {NULL}};
static struct device_node *of_find_node_by_path(const char *path) {
    assert(!strcmp(path, "/")); gets++;
    if (!have_root) return NULL;
    refs++; return &node;
}
static const struct of_device_id *of_match_node(const struct of_device_id *matches,
                                               const struct device_node *n) {
    assert(n == &node && refs == 1);
    return have_match ? matches : NULL;
}
static void of_node_put(struct device_node *n) {
    assert(n == &node && refs == 1); refs--; puts++;
}
'''
main = r'''
int main(int argc, char **argv) {
    u8 out;
    property_size = sizeof(bytes);
    if (argc > 1) { (void)argv; return old_read(NULL, "p", UINT32_MAX, &out); }
    for (size_t len = 0; len <= sizeof(bytes); len++) {
        property_size = len;
        for (u32 i = 0; i <= sizeof(bytes); i++) {
            out = 91;
            int result = of_property_read_u8_index(NULL, "p", i, &out);
            assert(result == (i < len ? 0 : -EOVERFLOW));
            assert(out == (i < len ? bytes[i] : 91));
        }
        out = 91;
        assert(of_property_read_u8_index(NULL, "p", UINT32_MAX, &out) == -EOVERFLOW);
        assert(out == 91);
    }
    for (int e = 0; e < 3; e++) {
        error = (int[]){-EINVAL, -ENODATA, -EOVERFLOW}[e]; out = 91;
        assert(of_property_read_u8_index(NULL, "p", 0, &out) == error && out == 91);
    }
    for (int mode = 0; mode < 4; mode++) {
        have_root = mode & 1; have_match = mode & 2;
        gets = puts = refs = 0;
        assert(of_machine_device_match(table) == (have_root && have_match));
        assert(refs == 0 && gets == 1 && puts == (int)have_root);
        gets = puts = 0;
        assert(of_machine_get_match_data(table) == (have_root && have_match ? &node : NULL));
        assert(refs == 0 && gets == 1 && puts == (int)have_root);
    }
    puts("OF bounds/errors and root-reference checks passed");
}
'''
# Avoid collision between the C library puts function and the reference counter.
shim = shim.replace('puts', 'put_count')
main = main.replace('puts =', 'put_count =').replace('puts ==', 'put_count ==')
code = shim + u8 + '\n' + old + '\n' + wrappers + '\n' + main
flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
with tempfile.TemporaryDirectory(prefix='of-helper-check-') as temp:
    p = Path(temp); (p / 'check.c').write_text(code)
    subprocess.run(['cc', *flags, str(p / 'check.c'), '-o', str(p / 'check')], check=True)
    passed = subprocess.check_output([str(p / 'check')], text=True).strip()
    negative = subprocess.run([str(p / 'check'), 'old-index-wrap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert negative.returncode != 0 and 'AddressSanitizer' in negative.stderr, negative.stderr
args.output.write_text(json.dumps({
    'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'source_files_sha256': {p: hashlib.sha256(s.encode()).hexdigest() for p, s in sources.items()},
    'extracted_code_sha256': hashlib.sha256(code.encode()).hexdigest(),
    'compiler_flags': flags,
    'result': passed,
    'negative_control': {'source_commit': ack, 'index': 4294967295, 'result': 'Original helper bypassed length validation after index+1 wrap and ASan rejected out-of-bounds read'},
    'scope': __doc__,
}, indent=2) + '\n')
print(passed)
