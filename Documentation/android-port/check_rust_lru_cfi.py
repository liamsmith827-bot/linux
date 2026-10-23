#!/usr/bin/env python3
"""Compare a compiled Rust Binder callback CFI tag with the native C enum signature."""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
WORK = ROOT.parent / 'kernel_manifest-6.18'
BIN = WORK / 'prebuilts/clang/host/linux-x86/clang-r584948c/bin'
module = WORK / 'common_dist/rust_binder.ko'
module_sha = hashlib.sha256(module.read_bytes()).hexdigest()
runs = json.loads((D/'evidence/build-results.json').read_text())['runs']
matching_runs = [r for r in runs if r['artifact_sha256'].get('common_dist/rust_binder.ko') == module_sha]
assert matching_runs, 'Record a completed build before checking its artifact'
built = matching_runs[-1]
header = (ROOT/'include/linux/list_lru.h').read_text()
enum = re.search(r'enum lru_status \{.*?\};', header, re.S).group()
typedef = re.search(r'typedef enum lru_status \(\*list_lru_walk_cb\).*?;', header, re.S).group()
prefix = 'struct list_head; struct list_lru_one;\n' + enum + '\n' + typedef + '\n'
fixture = prefix + '''
enum lru_status expected_callback(struct list_head *item, struct list_lru_one *list, void *cb_arg)
{ return LRU_SKIP; }
list_lru_walk_cb verify_signature = expected_callback;
unsigned int incorrect_integer_callback(struct list_head *item, struct list_lru_one *list, void *cb_arg)
{ return LRU_SKIP; }
'''

def command(*args):
    return subprocess.check_output([str(x) for x in args], text=True)

def tag(obj, symbol):
    dump = command(BIN/'llvm-objdump', '--disassemble-symbols=__cfi_'+symbol, obj)
    match = re.search(r'movl?\s+\$(0x[0-9a-fA-F]+|[0-9]+),\s*%eax', dump)
    assert match, dump
    return int(match[1],0), dump

with tempfile.TemporaryDirectory(prefix='rust-lru-cfi-') as td:
    src, obj = Path(td)/'signature.c', Path(td)/'signature.o'
    src.write_text(fixture)
    flags = ['-target','x86_64-linux-gnu','-O2','-fsanitize=kcfi',
             '-fsanitize-cfi-icall-experimental-normalize-integers']
    command(BIN/'clang', *flags, '-c', src, '-o', obj)
    rust, rd = tag(module, 'rust_shrink_free_page')
    native, nd = tag(obj, 'expected_callback')
    wrong, wd = tag(obj, 'incorrect_integer_callback')
    assert rust == native and rust != wrong, (rust,native,wrong)
report = {'scope': __doc__, 'source_head': command('git','-C',ROOT,'rev-parse','HEAD').strip(),
          'built_source': built['linux_commit'], 'built_run': built['run'],
          'module_sha256':module_sha,
          'clang_version':command(BIN/'clang','--version').strip(), 'clang_flags':flags,
          'c_fixture':fixture,'c_fixture_sha256':hashlib.sha256(fixture.encode()).hexdigest(),
          'cfi_tags':{'built_rust':hex(rust),'native_enum':hex(native),'wrong_integer_control':hex(wrong)},
          'disassembly':{'built_rust':rd,'native_enum':nd,'wrong_integer_control':wd},
          'limitations':'Offline comparison of the exact module callback tag and a C signature fixture extracted from the native header. Does not execute the indirect call, shrinker, or CFI failure path. Fixture uses forward-declared pointer types, not a second kernel build.'}
(D/'evidence/rust-lru-cfi-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report['cfi_tags'],indent=2))
