#!/usr/bin/env python3
"""Exercise actual array lookup functions with device-iterator lifetime shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
PATH = 'drivers/power/supply/power_supply_core.c'
source = (ROOT / PATH).read_text()
ack = subprocess.check_output(['git', 'show', '23112ce1886e:' + PATH], cwd=ROOT, text=True)

def extract(text):
    start = text.index('struct match_fwnode_array_param {')
    return (text[start:text.index('\n};', start) + 3] + '\n' +
            function(text, 'power_supply_match_device_fwnode_array') + '\n' +
            function(text, 'power_supply_get_by_reference_array'))

shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
struct fwnode_handle { int refs; } target, other;
struct device { struct device *parent; struct fwnode_handle *node; int refs; };
struct power_supply { struct device dev; int use_cnt; } supplies[8];
struct device parents[8];
static int power_supply_class, fail_after, no_reference, checks;
static void check(int v, const char *what) {
 checks++; if (!v) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
}
static struct fwnode_handle *dev_fwnode(struct device *d) { return d->node; }
static struct power_supply *dev_to_psy(struct device *d) {
 return (struct power_supply *)((char *)d - offsetof(struct power_supply, dev));
}
static void atomic_inc(int *v) { ++*v; }
static struct device *get_device(struct device *d) { d->refs++; return d; }
static void put_device(struct device *d) { d->refs--; }
static void power_supply_put(struct power_supply *p) { p->use_cnt--; put_device(&p->dev); }
static struct fwnode_handle *fwnode_find_reference(struct fwnode_handle *f,
                                                const char *prop, int index) {
 if (no_reference) return (void *)(intptr_t)-ENOENT;
 target.refs++; return &target;
}
static void fwnode_handle_put(struct fwnode_handle *f) { f->refs--; }
static int class_for_each_device(const int *cls, void *start, void *data,
                                int (*fn)(struct device *, void *)) {
 for (int i=0;i<8;i++) {
  if (i==fail_after) return -EIO;
  get_device(&supplies[i].dev);
  int result=fn(&supplies[i].dev,data);
  put_device(&supplies[i].dev);
  if (result) return result;
 }
 return 0;
}
'''
body = r'''
int main(void) {
 int cases=0;
 fail_after=-1;
 for(int i=0;i<8;i++) {
  parents[i].node=i?&other:&target;
  supplies[i].dev=(struct device){.parent=&parents[i],.refs=1};
  supplies[i].use_cnt=1;
 }
 struct power_supply *first[1];
 check(power_supply_get_by_reference_array(&target,"supplies",first,1)==1,"first lookup");
 check(first[0]->dev.refs==2,"returned reference survives iterator");
 power_supply_put(first[0]);
 for (int mask=0;mask<256;mask++) for (int cap=-1;cap<=10;cap++)
 for (int injected=-1;injected<9;injected++) for (int missing=0;missing<2;missing++) {
  struct power_supply sentinel, *out[12];
  for(int i=0;i<12;i++) out[i]=&sentinel;
  target.refs=other.refs=0; no_reference=missing; fail_after=injected;
  int found=0, expected=0;
  for(int i=0;i<8;i++) {
   parents[i].node=mask & (1<<i)?&target:&other;
   supplies[i].dev=(struct device){.parent=&parents[i],.refs=1};
   if (!(mask & (1<<i)) && i%2) supplies[i].dev.parent=NULL;
   supplies[i].use_cnt=1;
  }
  if(cap<=0) expected=-EINVAL;
  else if(missing) expected=-ENODEV;
  else for(int i=0;i<8;i++) {
   if(i==injected) { expected=-EIO; break; }
   if(mask & (1<<i)) {
    if(found==cap) { expected=-EOVERFLOW; break; }
    found++;
   }
  }
  if(!expected) expected=found;
  int result=power_supply_get_by_reference_array(&target,"supplies",out+1,cap);
  check(result==expected,"error/count contract");
  check(!target.refs,"firmware reference leak");
  check(out[0]==&sentinel && out[11]==&sentinel,"array guard");
  if(result>=0) {
   int j=0;
   for(int i=0;i<8;i++) if(mask & (1<<i)) {
    check(out[1+j++]==&supplies[i],"matching array order");
    check(supplies[i].dev.refs==2 && supplies[i].use_cnt==2,"owned device and supply references");
   }
   for(int i=0;i<result;i++) power_supply_put(out[i+1]);
  } else for(int i=0;i<found;i++) check(out[i+1]==NULL,"error clears acquired entries");
  for(int i=0;i<8;i++) check(supplies[i].dev.refs==1 && supplies[i].use_cnt==1,"balanced references");
  for(int i=found+1;i<12;i++) check(out[i]==&sentinel,"untouched suffix");
  cases++;
 }
 check(power_supply_get_by_reference_array(&target,"supplies",NULL,2)==-EINVAL,"null array");
 struct power_supply *out[1];
 check(power_supply_get_by_reference_array(&target,"supplies",out,(ssize_t)INT_MAX+1)==-EINVAL,"int count bound");
 printf("PASS: %d cases, %d assertions\n",cases,checks);
}
'''
records = []
with tempfile.TemporaryDirectory(prefix='psy-array-check-') as tmp:
    for name, text in [('ack', ack), ('adapted', source)]:
        c = Path(tmp) / (name + '.c')
        binary = Path(tmp) / name
        c.write_text(shim + extract(text) + body)
        cmd = ['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer', str(c), '-o', str(binary)]
        subprocess.run(cmd, check=True)
        result = subprocess.run([str(binary)], text=True, capture_output=True)
        records.append(dict(case=name, compile_command=cmd, exit_code=result.returncode,
                            stdout=result.stdout, stderr=result.stderr,
                            harness_sha256=hashlib.sha256(c.read_bytes()).hexdigest()))
        if name == 'ack':
            assert result.returncode == 1 and 'returned reference survives iterator' in result.stderr, records[-1]
        else:
            assert result.returncode == 0, records[-1]
report = dict(source_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              source_sha256=hashlib.sha256(source.encode()).hexdigest(), records=records,
              remote_resources_used=[],
              limits='Extracted real C functions, host ASan/UBSan, simulated class iterator/device/fwnode references. No kernel runtime or unregister race test.')
(ROOT / 'Documentation/android-port/evidence/power-supply-array-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(records[1]['stdout'].strip())
