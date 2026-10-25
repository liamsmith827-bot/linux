#!/usr/bin/env python3
"""Exercise the real battery enumeration with changes between its two passes."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p='drivers/power/supply/power_supply_core.c';source=(ROOT/p).read_text()
start=source.index('static bool power_supply_is_system_battery(');end=source.index('EXPORT_SYMBOL_GPL(power_supply_put_system_batteries);',start)+len('EXPORT_SYMBOL_GPL(power_supply_put_system_batteries);');code=source[start:end]
shim=r'''
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EXPORT_SYMBOL_GPL(x)
#define __must_check
#define GFP_KERNEL 0
#define POWER_SUPPLY_TYPE_BATTERY 1
#define POWER_SUPPLY_PROP_SCOPE 0
#define POWER_SUPPLY_SCOPE_DEVICE 2
#define dev_dbg(...) ((void)0)
struct device {int refs;};
struct power_supply_desc {int type;};
struct power_supply {struct device dev;struct power_supply_desc *desc;int use_cnt;int scope;int error;} supplies[8];
struct power_supply_desc descs[8];
union power_supply_propval {int intval;};
static int pass,masks[2],fail_pass,fail_index,fail_alloc,allocations,checks;
static void check(int ok,const char *why){checks++;if(!ok){fprintf(stderr,"FAIL: %s\n",why);exit(1);}}
static void *alloc(size_t n,size_t size){if(fail_alloc)return NULL;void *p=calloc(n,size);check(p!=NULL,"host allocation");allocations++;return p;}
#define kzalloc_objs(obj,n,flags) alloc(n,sizeof(obj))
static void kfree(void *p){if(p){allocations--;free(p);}}
static void get_device(struct device *d){d->refs++;}
static void atomic_inc(int *p){++*p;}
static void power_supply_put(struct power_supply *p){p->dev.refs--;p->use_cnt--;}
static void power_supply_put_system_batteries(struct power_supply **psys,int count);
static int power_supply_get_property_direct(struct power_supply *p,int prop,union power_supply_propval *v){v->intval=p->scope;return p->error;}
static int power_supply_for_each_psy(void *data,int (*fn)(struct power_supply *,void *)){
 int round=pass++;
 for(int i=0;i<8;i++){
  if(round==fail_pass && i==fail_index)return -EIO;
  descs[i].type=(masks[round]>>i)&1;
  supplies[i].dev.refs++;
  int r=fn(&supplies[i],data);
  supplies[i].dev.refs--;
  if(r)return r;
 }
 return 0;
}
'''
body=r'''
static int eligible(unsigned mask,int i){return (mask&(1U<<i)) && i%4!=2;}
int main(void){
 int cases=0;
 for(unsigned a=0;a<256;a++)for(unsigned b=0;b<16;b++)
 for(int fault=-1;fault<16;fault++)for(int oom=0;oom<2;oom++){
  unsigned second=(a*37+b*19)&255;
  masks[0]=a;masks[1]=second;pass=0;fail_pass=fault<0?-1:fault/8;fail_index=fault%8;fail_alloc=oom;
  for(int i=0;i<8;i++){
   descs[i].type=0;supplies[i]=(struct power_supply){.dev={1},.desc=&descs[i],.use_cnt=1,.scope=i%4,.error=i%4==3?-EIO:0};
  }
  int capacity=0,got=0,expected=0;
  for(int i=0;i<8;i++){
   if(fail_pass==0&&fail_index==i){expected=-EIO;break;}
   if(eligible(a,i))capacity++;
  }
  if(!expected && capacity && oom)expected=-ENOMEM;
  if(!expected && capacity)for(int i=0;i<8;i++){
   if(fail_pass==1&&fail_index==i){expected=-EIO;break;}
   if(eligible(second,i)){
    if(got==capacity){expected=-EOVERFLOW;break;}
    got++;
   }
  }
  if(!expected)expected=got;
  struct power_supply **out=(void *)1;
  int ret=power_supply_get_system_batteries(NULL,&out);
  check(ret==expected,"count/error contract across changed passes");
  if(ret>0){
   check(out!=NULL&&allocations==1,"returned allocation");
   int j=0;for(int i=0;i<8;i++)if(eligible(second,i)){
    check(out[j++]==&supplies[i],"array contains selected supplies");
    check(supplies[i].dev.refs==2&&supplies[i].use_cnt==2,"owned references");
   }
   power_supply_put_system_batteries(out,ret);
  }else check(out==NULL,"error/empty output null");
  check(allocations==0,"no allocation leak");
  for(int i=0;i<8;i++)check(supplies[i].dev.refs==1&&supplies[i].use_cnt==1,"balanced supply and device references");
  cases++;
 }
 check(power_supply_get_system_batteries(NULL,NULL)==-EINVAL,"null output");
 int count=INT_MAX;descs[0].type=POWER_SUPPLY_TYPE_BATTERY;
 check(__power_supply_get_num_system_batteries(&supplies[0],&count)==-EOVERFLOW&&count==INT_MAX,"count overflow guard");
 power_supply_put_system_batteries(NULL,0);
 printf("PASS: %d cases, %d assertions\n",cases,checks);
}
'''
with tempfile.TemporaryDirectory(prefix='system-battery-') as tmp:
 c=Path(tmp)/'test.c';b=Path(tmp)/'test';c.write_text(shim+code+body)
 cmd=['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c),'-o',str(b)];subprocess.run(cmd,check=True);r=subprocess.run([str(b)],text=True,capture_output=True);assert r.returncode==0,(r.stdout,r.stderr)
 report=dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),source_sha256=hashlib.sha256(source.encode()).hexdigest(),compile_command=cmd,harness_sha256=hashlib.sha256(c.read_bytes()).hexdigest(),exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr,remote_resources_used=[],limits='Host extracted C with ASan/UBSan. Simulated class iteration, allocation, property and reference lifetimes; deterministic changes between two passes, no kernel registration/unregister race or charger runtime test.')
(ROOT/'Documentation/android-port/evidence/system-batteries-check.json').write_text(json.dumps(report,indent=2)+'\n');print(r.stdout.strip())
