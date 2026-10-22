#!/usr/bin/env python3
"""Test extracted cleancache wrappers against a modeled base-page cache.

Checks that replacing or invalidating a large folio removes stale small-page
cache entries, while native-page operations and disabled pools keep their
behavior. Old-source controls return stale data. No kernel I/O or cache backend
concurrency is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[2]
baseline='57131aee4cb9'
path='include/linux/cleancache.h'
def function(t,name):
    start=t.index(name);end=t.index('{',start)+1;depth=1
    while depth:
        depth+=(t[end]=='{')-(t[end]=='}');end+=1
    return t[start:end]+'\n'
parts=[]
for prefix in ['', 'old_']:
    t=(root/path).read_text() if not prefix else subprocess.check_output(['git','show',baseline+':'+path],cwd=root,text=True)
    for ret,name in [('int','cleancache_get_page'),('void','cleancache_put_page'),('void','cleancache_invalidate_page')]:
        body=function(t,'static inline '+ret+' '+name+'(')
        parts.append(body.replace(name+'(',prefix+name+'(',1))
shim=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
struct address_space { bool enabled,cached; int value; };
struct page { struct address_space *mapping; bool compound; int value; };
static bool cleancache_enabled=true;
static unsigned int inode_invalidations,page_invalidations,gets,cache_puts;
static bool cleancache_fs_enabled_mapping(struct address_space *m) {return m->enabled;}
static bool cleancache_fs_enabled(struct page *p) {return p->mapping->enabled;}
static bool PageCompound(struct page *p) {return p->compound;}
static int __cleancache_get_page(struct page *p) {gets++;if(!p->mapping->cached)return -1;p->value=p->mapping->value;return 0;}
static void __cleancache_put_page(struct page *p) {cache_puts++;p->mapping->cached=true;p->mapping->value=p->value;}
static void __cleancache_invalidate_page(struct address_space *m,struct page *p) {(void)p;page_invalidations++;m->cached=false;}
static void __cleancache_invalidate_inode(struct address_space *m) {inode_invalidations++;m->cached=false;}
'''
checks=r'''
int main(void) {
    struct address_space m={.enabled=true};struct page small={.mapping=&m,.value=1};
    struct page large={.mapping=&m,.compound=true,.value=2};
    for(int op=0;op<2;op++) {
        cleancache_put_page(&small);assert(m.cached);
        if(op)cleancache_invalidate_page(&m,&large);else cleancache_put_page(&large);
        assert(!m.cached && cleancache_get_page(&small)==-1);
        cleancache_put_page(&small);
        if(op)old_cleancache_invalidate_page(&m,&large);else old_cleancache_put_page(&large);
        small.value=0;assert(old_cleancache_get_page(&small)==0 && small.value==1);
    }
    assert(inode_invalidations==2 && !page_invalidations);
    cleancache_invalidate_page(&m,&small);assert(!m.cached && page_invalidations==1);
    cleancache_put_page(&small);unsigned int before=gets;
    assert(cleancache_get_page(&large)==-1 && gets==before);
    large.mapping=NULL;cleancache_invalidate_page(&m,&large);assert(!m.cached);
    large.mapping=&m;
    for(int disabled=0;disabled<2;disabled++) {
        cleancache_enabled=disabled!=0;m.enabled=disabled==0;m.cached=true;
        unsigned int n=inode_invalidations+page_invalidations+gets+cache_puts;
        cleancache_put_page(&large);cleancache_invalidate_page(&m,&large);
        assert(cleancache_get_page(&small)==-1 && m.cached);
        assert(n==inode_invalidations+page_invalidations+gets+cache_puts);
    }
    puts("Cleancache large-folio stale-data checks passed; old put/invalidate controls reproduced");
}
'''
with tempfile.TemporaryDirectory(prefix='cleancache-folio-check-') as tmp:
    src=Path(tmp)/'check.c';binary=Path(tmp)/'check';src.write_text(shim+''.join(parts)+checks)
    flags=['-std=gnu11','-Wall','-Wextra','-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run(['cc',*flags,str(src),'-o',str(binary)],check=True)
    r=subprocess.run([str(binary)],text=True,capture_output=True,timeout=15)
    if r.returncode:raise SystemExit(r.stderr or r.stdout)
record={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'negative_control_commit':subprocess.check_output(['git','rev-parse',baseline],cwd=root,text=True).strip(),
        'excerpts_sha256':hashlib.sha256(''.join(parts).encode()).hexdigest(),'compiler_flags':flags,
        'result':r.stdout.strip(),'scope':__doc__.strip()}
a.output.write_text(json.dumps(record,indent=2)+'\n');print(record['result'])
