#!/usr/bin/env python3
"""Exercise actual sysfs enum helpers with sparse ACK enum values on native code."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
p='drivers/power/supply/power_supply_sysfs.c';source=(ROOT/p).read_text();ack=subprocess.check_output(['git','show','23112ce1886e:'+p],cwd=ROOT,text=True)
h=(ROOT/'include/linux/power_supply.h').read_text()
charge=re.search(r'enum power_supply_charge_type \{.*?\n};',h,re.S)[0]
usb=re.search(r'enum power_supply_usb_type \{.*?\n};',h,re.S)[0]
common=r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define BIT(i) (1UL<<(i))
#define BITS_PER_TYPE(x) (sizeof(x)*8)
#define sysfs_emit(b,...) snprintf(b,4096,__VA_ARGS__)
#define sysfs_emit_at(b,n,...) snprintf(b+n,4096-(n),__VA_ARGS__)
#define dev_warn(...) ((void)0)
#define dev_dbg_ratelimited(...) ((void)0)
#define dev_err_ratelimited(...) ((void)0)
struct device { int unused; };
struct device_attribute { struct {const char *name;} attr; };
struct power_supply_desc {int type; unsigned int usb_types;};
struct power_supply {struct power_supply_desc *desc;};
struct power_supply_attr {int text_values_len; const char *const *text_values;};
union power_supply_propval {int intval;const char *strval;};
enum power_supply_property {POWER_SUPPLY_PROP_TYPE,POWER_SUPPLY_PROP_USB_TYPE,
 POWER_SUPPLY_PROP_CHARGE_BEHAVIOUR,POWER_SUPPLY_PROP_CHARGE_TYPES,
 POWER_SUPPLY_PROP_MODEL_NAME,POWER_SUPPLY_PROP_SERIAL_NUMBER,TEST_PROP};
static struct power_supply_desc desc;
static struct power_supply psy={&desc};
static struct power_supply_attr attr;
static int prop=TEST_PROP, value, checks;
static struct power_supply *dev_to_psy(struct device *dev) {return &psy;}
static const struct power_supply_attr *to_ps_attr(struct device_attribute *a) {return &attr;}
static enum power_supply_property dev_attr_psp(struct device_attribute *a) {return prop;}
static int power_supply_get_property(struct power_supply *p,int t,union power_supply_propval *v) {v->intval=value;return 0;}
static int power_supply_show_charge_behaviour(struct device *d,struct power_supply *p,union power_supply_propval *v,char *b) {return -EINVAL;}
static int power_supply_show_charge_types(struct device *d,struct power_supply *p,int t,char *b) {return -EINVAL;}
static void check(int ok,const char *why) {checks++;if(!ok){fprintf(stderr,"FAIL: %s\n",why);exit(1);}}
static int sysfs_streq(const char *a,const char *b) {size_t x=strcspn(a,"\n"),y=strcspn(b,"\n");return x==y&&!memcmp(a,b,x);}
static int __sysfs_match_string(const char *const *a,size_t n,const char *s) {for(size_t i=0;i<n&&a[i];i++)if(sysfs_streq(a[i],s))return i;return -EINVAL;}
static long strscpy(char *d,const char *s,size_t n) {size_t l=strlen(s),c=l<n?l:n-1;memcpy(d,s,c);d[c]=0;return l<n?(long)l:-E2BIG;}
static void strreplace(char *s,char a,char b) {for(;*s;s++)if(*s==a)*s=b;}
'''
body=r'''
int main(void) {
 char out[4096],expected[4096];
 const char *const *labels=POWER_SUPPLY_CHARGE_TYPE_TEXT;
 check(power_supply_match_string(labels,ARRAY_SIZE(POWER_SUPPLY_CHARGE_TYPE_TEXT),"Taper\n")==50,"Taper after holes");
 for(int i=0;i<51;i++) if(labels[i]) {
  check(power_supply_match_string(labels,51,labels[i])==i,"exact enum");
  power_supply_escape_spaces(labels[i],out,sizeof(out));
  check(power_supply_match_string(labels,51,out)==i,"escaped enum");
 }
 attr=(struct power_supply_attr){51,labels};
 for(int i=-512;i<1024;i++) {
  value=i;int n=power_supply_format_property(NULL,false,NULL,out);
  if(i>=0&&i<51&&labels[i])snprintf(expected,sizeof(expected),"%s\n",labels[i]);
  else snprintf(expected,sizeof(expected),"%d\n",i);
  check(n==(int)strlen(expected)&&!strcmp(out,expected),"format sparse and invalid enums");
 }
 for(unsigned mask=0;mask<512;mask++) {
  for(int i=0;i<9;i++) {
   check(power_supply_charge_types_parse(mask,labels[i])==((mask&BIT(i))?i:-EINVAL),"capability parser");
   int n=power_supply_show_enum_with_available(NULL,labels,51,mask,i,out);
   if(!(mask&BIT(i)))check(n==-EINVAL,"unavailable value");
   else {
    size_t pos=0;
    for(int j=0;j<9;j++)if(mask&BIT(j)) {
     char escaped[32];power_supply_escape_spaces(labels[j],escaped,sizeof(escaped));
     pos+=snprintf(expected+pos,sizeof(expected)-pos,j==i?"[%s] ":"%s ",escaped);
    }
    expected[pos-1]='\n';check(n==(int)pos&&!strcmp(expected,out),"exact capability list");
   }
  }
  check(power_supply_charge_types_parse(mask,"Taper")==-EINVAL,"Taper outside uint32 mask");
  check(power_supply_show_enum_with_available(NULL,labels,51,mask,50,out)==-EINVAL,"no wide shift on Taper");
 }
 check(power_supply_match_string(labels,51,"not-a-charge-type")==-EINVAL,"unrecognized string");
 labels=POWER_SUPPLY_USB_TYPE_TEXT;
 for(unsigned i=0;i<ARRAY_SIZE(POWER_SUPPLY_USB_TYPE_TEXT);i++) {
  check(labels[i]!=NULL,"USB labels complete");
  check(power_supply_match_string(labels,ARRAY_SIZE(POWER_SUPPLY_USB_TYPE_TEXT),labels[i])==(int)i,"USB exact enum");
  check(power_supply_show_enum_with_available(NULL,labels,ARRAY_SIZE(POWER_SUPPLY_USB_TYPE_TEXT),BIT(i),i,out)>0,"USB active label");
 }
 printf("PASS: %d assertions\n",checks);
}
'''
records=[]
with tempfile.TemporaryDirectory(prefix='power-sysfs-') as tmp:
 for name,text in [('ack',ack),('adapted',source)]:
  tables='\n'.join(re.search(r'static const char \* const '+n+r'\[\] = \{.*?\n};',text,re.S)[0] for n in ['POWER_SUPPLY_CHARGE_TYPE_TEXT','POWER_SUPPLY_USB_TYPE_TEXT'])
  functions='\n'.join(function(text,n) for n in ['power_supply_escape_spaces','power_supply_match_string','power_supply_show_enum_with_available','power_supply_charge_types_parse','power_supply_format_property'])
  c=Path(tmp)/(name+'.c');b=Path(tmp)/name;c.write_text(common+charge+'\n'+usb+'\n'+tables+'\n'+functions+'\n'+body)
  cmd=['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c),'-o',str(b)];subprocess.run(cmd,check=True)
  r=subprocess.run([str(b)],text=True,capture_output=True);records.append(dict(case=name,compile_command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr,harness_sha256=hashlib.sha256(c.read_bytes()).hexdigest()))
  if name=='ack':assert r.returncode!=0 and ('AddressSanitizer' in r.stderr or 'runtime error:' in r.stderr),records[-1]
  else:assert r.returncode==0,records[-1]
report=dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),source_sha256=hashlib.sha256(source.encode()).hexdigest(),records=records,remote_resources_used=[],limits='Host extracted C with ASan/UBSan and sysfs/property shims. No live sysfs, device, charger or kernel runtime test.')
(ROOT/'Documentation/android-port/evidence/power-supply-sysfs-check.json').write_text(json.dumps(report,indent=2)+'\n');print(records[1]['stdout'].strip())
