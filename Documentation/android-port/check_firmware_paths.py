#!/usr/bin/env python3
"""Compile the actual firmware-path code and exercise its public parameter contract."""
import hashlib,json,random,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
source=(ROOT/'drivers/base/firmware_loader/main.c').read_text()
start=source.index('#define CUSTOM_FW_PATH_COUNT')
end=source.index('/*\n * Typical usage',start)
code=source[start:end]
base=subprocess.check_output(['git','show','4c47477687b3:drivers/base/firmware_loader/main.c'],cwd=ROOT,text=True)
base=base[base.index('#define CUSTOM_FW_PATH_COUNT'):base.index('/*\n * Typical usage',base.index('#define CUSTOM_FW_PATH_COUNT'))]
inputs=['/old-a,/old-b','/replacement','',',,,',' /a,,/b, \n','/'+'a'*254,'/'+'b'*255,'/a,/b','/new','/x'*128,','.join('/'+str(i) for i in range(11)),','.join('/'+'m'*254 for _ in range(10)),','.join('/'+'n'*255 for _ in range(10)), 'x'*2560, ' , /keep-space , /last \n']
rng=random.Random(61857)
for _ in range(800):
 tokens=['/'+rng.choice('abcd')*rng.choice([0,1,12,253,254,255,256]) for _ in range(rng.randrange(13))]
 if rng.randrange(2):tokens.insert(rng.randrange(len(tokens)+1),'')
 inputs.append(','.join(tokens))
current='';cases=[]
for s in inputs:
 parts=[x for x in s.strip().split(',') if x]
 valid=len(s)<2560 and len(parts)<=10 and all(len(x)<256 for x in parts)
 if valid:current=','.join(parts)
 cases.append('{'+json.dumps(s)+','+json.dumps(current)+','+('0' if valid else '-ENOSPC')+'}')
shim=r'''
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define UTS_RELEASE "audit"
#define PAGE_SIZE 4096
#define DEFINE_MUTEX(n) pthread_mutex_t n = PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) do { if (pthread_mutex_lock(p)) exit(2); } while (0)
#define mutex_unlock(p) do { if (pthread_mutex_unlock(p)) exit(2); } while (0)
#define BUILD_BUG_ON(c) _Static_assert(!(c), "buffer bound")
struct kernel_param { int unused; };
static long strscpy(char *dst, const char *src, size_t size) {
 size_t n=strlen(src); if (!size) return -E2BIG;
 size_t copied=n<size?n:size-1; memcpy(dst,src,copied); dst[copied]=0;
 return n<size?(long)n:-E2BIG;
}
static char *strim(char *s) {
 size_t n=strlen(s); while(n && isspace((unsigned char)s[n-1])) s[--n]=0;
 while(isspace((unsigned char)*s)) s++; return s;
}
static int scnprintf(char *dst, size_t size, const char *fmt, ...) {
 va_list ap; va_start(ap,fmt); int n=vsnprintf(dst,size,fmt,ap); va_end(ap);
 return n<0?n:(size && (size_t)n>=size?(int)size-1:n);
}
'''
body=r'''
static void check(int ok, const char *label) { if (!ok) { fprintf(stderr,"FAIL: %s\n",label); exit(1); } }
struct testcase { const char *input, *expected; int result; };
static const struct testcase cases[] = { CASES };
#if HAVE_PATH
static void *writer(void *unused) {
 for (int i=0;i<20000;i++) check(!firmware_param_path_set(i&1?"/alpha,/beta":"/gamma",NULL),"concurrent set");
 return NULL;
}
static void *reader(void *unused) {
 for (int i=0;i<20000;i++) {
  char output[PAGE_SIZE]={0}, path[PATH_SIZE];
  int n=firmware_param_path_get(output,NULL);
  check(n==(int)strlen(output),"concurrent count");
  check(!strcmp(output,"/alpha,/beta") || !strcmp(output,"/gamma"),"atomic full-list read");
  const char *p=firmware_path(0,path);
  check(!strcmp(p,"/alpha") || !strcmp(p,"/gamma"),"directory snapshot");
 }
 return NULL;
}
#endif
int main(void) {
 for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
  char output[PAGE_SIZE+32]; memset(output,0,sizeof(output)); memset(output+PAGE_SIZE,0x5a,32);
  int ret=firmware_param_path_set(cases[i].input,NULL);
  check(ret==cases[i].result,"setter error/length contract");
  int count=firmware_param_path_get(output,NULL);
  check(count==(int)strlen(cases[i].expected),"getter count or stale directory");
  check(!memcmp(output,cases[i].expected,count),"exact getter content");
  for(int k=0;k<32;k++) check(output[PAGE_SIZE+k]==0x5a,"getter overflow");
#if HAVE_PATH
  char expected[PATH_SIZE*CUSTOM_FW_PATH_COUNT]; strcpy(expected,cases[i].expected);
  char *next=expected; unsigned int j=0;
  while(next && *next) {
   char *sep=strchr(next,','); if(sep) *sep=0;
   char custom[PATH_SIZE]; check(!strcmp(firmware_path(j++,custom),next),"loader path content");
   next=sep?sep+1:NULL;
  }
  while(j<CUSTOM_FW_PATH_COUNT) { char custom[PATH_SIZE]; check(!*firmware_path(j++,custom),"old loader directory cleared"); }
  char custom[PATH_SIZE];
  check(!strcmp(firmware_path(10,custom),"/lib/firmware/updates/audit"),"release update fallback");
  check(!strcmp(firmware_path(11,custom),"/lib/firmware/updates"),"update fallback");
  check(!strcmp(firmware_path(12,custom),"/lib/firmware/audit"),"release fallback");
  check(!strcmp(firmware_path(13,custom),"/lib/firmware"),"base fallback");
#endif
 }
#if HAVE_PATH
 check(!firmware_param_path_set("/alpha,/beta",NULL),"concurrency initial state");
 pthread_t threads[3];
 check(!pthread_create(&threads[0],NULL,writer,NULL),"start writer");
 check(!pthread_create(&threads[1],NULL,reader,NULL),"start reader");
 check(!pthread_create(&threads[2],NULL,reader,NULL),"start reader");
 for(int i=0;i<3;i++) check(!pthread_join(threads[i],NULL),"join");
#endif
 printf("PASS: %zu replacement/boundary cases\n",sizeof(cases)/sizeof(cases[0]));
 return 0;
}
'''.replace('CASES',',\n'.join(cases))
records=[]
with tempfile.TemporaryDirectory(prefix='firmware-path-check-') as tmp:
 for name,part in [('baseline',base),('adapted',code)]:
  c=Path(tmp)/(name+'.c');binary=Path(tmp)/name;c.write_text(shim+part+body)
  cmd=['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread','-DHAVE_PATH='+str(int(name=='adapted')),str(c),'-o',str(binary)]
  subprocess.run(cmd,check=True)
  result=subprocess.run([str(binary)],text=True,capture_output=True)
  records.append(dict(case=name,compile_command=cmd,harness_sha256=hashlib.sha256(c.read_bytes()).hexdigest(),exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr))
  if name=='baseline':assert result.returncode==1 and 'getter count or stale directory' in result.stderr,records[-1]
  else:assert result.returncode==0,records[-1]
report=dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),source_sha256=hashlib.sha256(source.encode()).hexdigest(),extracted_code_sha256=hashlib.sha256(code.encode()).hexdigest(),cases=len(cases),concurrency=dict(writes=20000,whole_list_and_path_reads=40000),records=records,remote_resources_used=[],limits='Host ASan/UBSan test of extracted actual functions with pthread mutex and libc string shims. It does not boot the kernel or test firmware loading/LSM policy.')
(ROOT/'Documentation/android-port/evidence/firmware-path-check.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: baseline stale-path failure reproduced; 815 adapted cases and concurrent readers/writer passed ASan/UBSan')
