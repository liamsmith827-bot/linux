#!/usr/bin/env python3
"""Exercise extracted swap I/O dispatch and accounting with host I/O shims."""
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
source = (root / 'mm/page_io.c').read_text()
header = (root / 'include/linux/swap.h').read_text()
baseline = subprocess.check_output(['git', 'rev-parse', '6dcd44cc22af'], cwd=root, text=True).strip()
old = subprocess.check_output(['git', 'show', baseline + ':mm/page_io.c'], cwd=root, text=True)

def function(text, signature):
    start = text.index(signature)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

flags = '\n'.join('#define ' + name + ' ' + re.search(r'^\s*' + name + r'\s*=\s*(.*),', header, re.M)[1]
                  for name in ['SWP_FS_OPS', '__SWP_READ_SYNCHRONOUS_IO', '__SWP_WRITE_SYNCHRONOUS_IO', 'SWP_SYNCHRONOUS_IO'])
shim = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
struct page { int unused; };
struct folio { struct page page; int swap; bool workingset,cache,locked,uptodate; };
struct swap_info_struct { unsigned long flags; };
struct swap_iocb { int unused; };
static struct swap_info_struct device;
static int route,psi,delay,thrash,begin,end,zprotection;
static int special,start_hook,end_hook;
static unsigned long cookie;
static bool write_override;
#define data_race(x) (x)
#define VM_BUG_ON_FOLIO(x,f) assert(!(x))
static struct swap_info_struct *__swap_entry_to_info(int s) {(void)s;return &device;}
static bool folio_test_swapcache(struct folio *f) {return f->cache;}
static bool folio_test_locked(struct folio *f) {return f->locked;}
static bool folio_test_uptodate(struct folio *f) {return f->uptodate;}
static bool folio_test_workingset(struct folio *f) {return f->workingset;}
static void folio_unlock(struct folio *f) {assert(f->locked);f->locked=false;}
static void trace_android_vh_swapin_start(unsigned long *t) {begin++;if(start_hook)*t=123;}
static void trace_android_vh_swap_writepage_start(unsigned long *t) {trace_android_vh_swapin_start(t);}
static void trace_android_vh_swapin_end(struct folio *f,unsigned long t) {(void)f;end++;if(end_hook)cookie=t;}
static void trace_android_vh_swap_writepage_end(struct page *p,unsigned long t) {(void)p;end++;if(end_hook)cookie=t;}
static void trace_android_vh_swap_writepage(unsigned long *flags,struct page *p) {
    (void)p;if(write_override)*flags^=__SWP_WRITE_SYNCHRONOUS_IO;
}
static void delayacct_thrashing_start(bool *t) {*t=true;thrash++;}
static void delayacct_thrashing_end(bool *t) {assert(*t && thrash==1);thrash--;}
static void psi_memstall_enter(unsigned long *p) {*p=42;psi++;}
static void psi_memstall_leave(unsigned long *p) {assert(*p==42 && psi==1);psi--;}
static void delayacct_swapin_start(void) {delay++;}
static void delayacct_swapin_end(void) {assert(delay==1);delay--;}
static bool swap_read_folio_zeromap(struct folio *f) {
    if(special!=1 && special!=2)return false;
    f->uptodate=special==1;return true;
}
static int zswap_load(struct folio *f) {
    if(special!=3 && special!=4)return -ENOENT;
    f->uptodate=special==3;folio_unlock(f);return special==3?0:-EIO;
}
static void zswap_folio_swapin(struct folio *f) {(void)f;zprotection++;}
static void swap_read_folio_fs(struct folio *f,struct swap_iocb **p) {(void)f;(void)p;route=1;}
static void swap_read_folio_bdev_sync(struct folio *f,struct swap_info_struct *s) {
    (void)s;route=2;f->uptodate=true;folio_unlock(f);
}
static void swap_read_folio_bdev_async(struct folio *f,struct swap_info_struct *s) {(void)f;(void)s;route=3;}
static void swap_writepage_fs(struct folio *f,struct swap_iocb **p) {(void)p;route=1;folio_unlock(f);}
static void swap_writepage_bdev_sync(struct folio *f,struct swap_info_struct *s) {(void)s;route=2;folio_unlock(f);}
static void swap_writepage_bdev_async(struct folio *f,struct swap_info_struct *s) {(void)s;route=3;folio_unlock(f);}
'''
tests = r'''
static void setup(struct folio *f,unsigned long flags,int ws) {
    *f=(struct folio){.workingset=ws,.cache=true,.locked=true};device.flags=flags;
    route=psi=delay=thrash=begin=end=zprotection=0;cookie=999;
}
int main(void) {
    struct folio f;unsigned int cases=0;
    for(unsigned int bits=0;bits<8;bits++) for(int ws=0;ws<2;ws++)
    for(special=0;special<5;special++) for(start_hook=0;start_hook<2;start_hook++)
    for(end_hook=0;end_hook<2;end_hook++) {
        unsigned long flags=(bits&1?__SWP_READ_SYNCHRONOUS_IO:0)|
            (bits&2?__SWP_WRITE_SYNCHRONOUS_IO:0)|(bits&4?SWP_FS_OPS:0);
        setup(&f,flags,ws);swap_read_folio(&f,NULL);
        assert(!psi && !delay && !thrash && begin==1 && end==1);
        assert(cookie==(end_hook?(start_hook?123UL:0UL):999UL));
        if(special) {
            assert(!route && !zprotection && !f.locked);
            assert(f.uptodate==(special==1 || special==3));
        } else {
            int expected=bits&4?1:bits&1?2:3;
            assert(route==expected && zprotection==1);
            assert(f.locked==(expected!=2));
        }
        cases++;
    }
    special=0;
    for(unsigned int bits=0;bits<8;bits++) for(start_hook=0;start_hook<2;start_hook++)
    for(end_hook=0;end_hook<2;end_hook++) for(int override=0;override<2;override++) {
        unsigned long flags=(bits&1?__SWP_READ_SYNCHRONOUS_IO:0)|
            (bits&2?__SWP_WRITE_SYNCHRONOUS_IO:0)|(bits&4?SWP_FS_OPS:0);
        setup(&f,flags,0);write_override=override;__swap_writepage(&f,NULL);
        assert(route==(bits&4?1:((bool)(bits&2)^write_override)?2:3));
        assert(!f.locked && begin==1 && end==1);
        assert(cookie==(end_hook?(start_hook?123UL:0UL):999UL));
        assert(device.flags==flags);cases++;
    }
    /* Old implementation incorrectly selects synchronous read on a write-only device. */
    start_hook=1;end_hook=0;setup(&f,__SWP_WRITE_SYNCHRONOUS_IO,0);
    old_swap_read_folio(&f,NULL);assert(route==2);cases++;
    setup(&f,__SWP_WRITE_SYNCHRONOUS_IO,0);
    swap_read_folio(&f,NULL);assert(route==3);cases++;
    /* Cacheless read remains permitted for devices with the read flag. */
    setup(&f,__SWP_READ_SYNCHRONOUS_IO,1);f.cache=false;
    swap_read_folio(&f,NULL);assert(route==2 && !psi && !delay && !thrash);cases++;
    printf("%u read/write dispatch, callback and pressure-accounting cases passed\n",cases);
}
'''
body = flags + '\n' + shim + function(source, 'void swap_read_folio(') + function(source, 'void __swap_writepage(')
body += function(old, 'void swap_read_folio(').replace('void swap_read_folio(', 'void old_swap_read_folio(', 1) + tests
with tempfile.TemporaryDirectory(prefix='ack-swap-io-') as d:
    c, binary = Path(d)/'check.c', Path(d)/'check'
    c.write_text(body)
    subprocess.run(['cc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(c),'-o',str(binary)],check=True)
    result = subprocess.run([str(binary)],text=True,capture_output=True,check=True)
cacheless = {}
for name in ['mm/memory.c', 'mm/shmem.c']:
    text = (root/name).read_text()
    expressions = re.findall(r'data_race\(si->flags & ([A-Z_]+SYNCHRONOUS_IO)\)', text)
    assert expressions == ['__SWP_READ_SYNCHRONOUS_IO'], (name, expressions)
    cacheless[name] = expressions[0]
report = {'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
          'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'baseline':baseline,
          'result':result.stdout.strip(),'cacheless_read_guards':cacheless,
          'limits':'Actual dispatch functions with host I/O, zswap, zeromap, tracing and pressure shims plus UBSan. Real bios, device errors, completion races, PSI or swap faults are not executed; error shims check dispatcher cleanup only. Cacheless callers checked for consistent read capability.'}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(report['result'])
