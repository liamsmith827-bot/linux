#!/usr/bin/env python3
"""Check extracted printk hook boundaries with host commit/reuse observers.

Does not execute the kernel ringbuffer, IRQ/NMI handling, or real tracepoints.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_wakeup_reason_names import function

ROOT=Path(__file__).resolve().parents[2]
FILE='kernel/printk/printk.c'
ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
PRE=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define noinline __attribute__((noinline))
#define min_t(t,a,b) ((t)(a)<(t)(b) ? (t)(a):(t)(b))
#define PRINTKRB_RECORD_MAX 1024
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned long long u64;
enum printk_info_flags { LOG_NEWLINE=2, LOG_CONT=8 };
struct printk_info { u64 seq, ts_nsec; u16 text_len; unsigned facility,level,flags; u32 caller_id; };
struct printk_record { struct printk_info *info; char *text_buf; unsigned text_buf_size; };
struct printk_ringbuffer { int unused; };
struct prb_reserved_entry { struct printk_ringbuffer *rb; };
static struct printk_ringbuffer ring,*prb=&ring;
static struct printk_info source_info,expected_info;
static char source_text[2048],expected_text[1024];
static unsigned failures,cases,commits,finals,calls,mask,expected_len,expected_size,expected_added;
static bool expected_cont;
#define CHECK(x) do { if(!(x)) failures++; } while(0)
static bool trace_android_vh_logbuf_pr_cont_enabled(void) { return mask&4; }
static bool trace_android_rvh_logbuf_enabled(void) { return mask&1; }
static bool trace_android_vh_logbuf_enabled(void) { return mask&2; }
static void prb_commit(struct prb_reserved_entry *e) {
 CHECK(e->rb==prb); commits++;
 memset(&source_info,0xa5,sizeof(source_info)); memset(source_text,0x5a,sizeof(source_text));
}
static void prb_final_commit(struct prb_reserved_entry *e) { finals++; prb_commit(e); }
static void observe(struct printk_record *r,unsigned added,int kind) {
 if(!(mask&(1U<<kind))) return;
 CHECK(commits==1); CHECK(expected_cont==(kind==2)); calls++;
 CHECK(r->info!=&source_info); CHECK(r->text_buf!=source_text);
 CHECK(r->info->seq==expected_info.seq && r->info->ts_nsec==expected_info.ts_nsec);
 CHECK(r->info->caller_id==expected_info.caller_id);
 CHECK(r->info->flags==expected_info.flags);
 CHECK(r->info->text_len==expected_len && r->text_buf_size==expected_size);
 CHECK(!memcmp(r->text_buf,expected_text,expected_len));
 if(expected_size) CHECK(r->text_buf[expected_len]==0);
 if(kind==2) CHECK(added==expected_added);
}
static void trace_android_rvh_logbuf(struct printk_ringbuffer *rb,struct printk_record *r) { CHECK(rb==prb); observe(r,0,0); }
static void trace_android_vh_logbuf(struct printk_ringbuffer *rb,struct printk_record *r) { CHECK(rb==prb); observe(r,0,1); }
static void trace_android_vh_logbuf_pr_cont(struct printk_record *r,size_t n) { observe(r,n,2); }
'''
RECORD_MAIN=r'''
int main(void) {
 unsigned sizes[]={0,1,2,7,64,1023,1024,1536};
 for(unsigned si=0;si<sizeof(sizes)/sizeof(*sizes);si++)
 for(unsigned kind=0;kind<2;kind++) for(unsigned final=0;final<2;final++)
 for(mask=0;mask<8;mask++) for(unsigned scenario=0;scenario<4;scenario++) {
  unsigned size=sizes[si], length=scenario==0 ? 0 : scenario==1 ? size/2 : size ? size-1 : 0;
  unsigned added=scenario==3 ? length+1 : length/2;
  memset(&source_info,0,sizeof(source_info)); memset(source_text,'a'+si,sizeof(source_text));
  source_info=(struct printk_info){.seq=12345,.ts_nsec=678901,.text_len=length,
    .caller_id=0x80000001,.flags=final ? LOG_NEWLINE : 0};
  expected_info=source_info; expected_size=min_t(unsigned,size,1024);
  expected_len=min_t(unsigned,length,expected_size ? expected_size-1 : 0);
  memcpy(expected_text,source_text,expected_len); expected_added=min_t(unsigned,added,expected_len);
  expected_cont=kind; calls=commits=finals=0;
  struct printk_record record={&source_info,source_text,size}; struct prb_reserved_entry e={prb};
  printk_commit_record(&e,&record,source_info.flags,kind,added);
  CHECK(commits==1 && finals==final);
  CHECK(calls==(kind ? !!(mask&4) : !!(mask&1)+!!(mask&2))); cases++;
 }
 printf("{\"cases\":%u,\"failures\":%u}\n",cases,failures);
 return failures ? 1 : 0;
}
'''
FORMAT_PRE=r'''
#define CONFIG_PRINTK_CALLER 1
#define do_div(a,b) ((a)/=(b))
static unsigned mode;
static void formatter(char *caller,size_t size,int *ret) {
 if(mode==0) return;
 *ret=1;
 if(mode==1) memset(caller,'X',size);
 if(mode==2) { caller[0]='Q'; caller[1]=0; }
 if(mode==3) return;
 if(mode==4) { memset(caller,'Z',size); *ret=0; }
 if(mode==5) { memset(caller,'V',size-1); caller[size-1]=0; }
}
static void trace_android_vh_printk_caller(char *p,size_t n,u32 id,int *ret) { (void)id; formatter(p,n,ret); }
static void trace_android_vh_printk_ext_header(char *p,size_t n,u32 id,int *ret) { (void)id; formatter(p,n,ret); }
/* Observe bounded termination before a host printf could read past the array. */
static int checked_sprintf(char *buf,const char *fmt,const char *caller) {
 if(!memchr(caller,0,12)) { failures++; buf[0]=0; return 0; }
 return snprintf(buf,128,fmt,caller);
}
static int checked_scnprintf(char *buf,size_t size,const char *fmt,unsigned pri,u64 seq,u64 ts,int flag,const char *caller) {
 if(!memchr(caller,0,20)) { failures++; if(size) buf[0]=0; return 0; }
 int n=snprintf(buf,size,fmt,pri,seq,ts,flag,caller);
 return size ? (n<(int)size ? n : (int)size-1) : 0;
}
#define sprintf checked_sprintf
#define scnprintf checked_scnprintf
'''
FORMAT_MAIN=r'''
int main(void) {
 u32 ids[]={0,1,0x7fffffffU,0x80000000U,0xffffffffU}; char out[128],want[128],caller[20];
 for(mode=0;mode<6;mode++) for(unsigned i=0;i<sizeof(ids)/sizeof(*ids);i++) {
  u32 id=ids[i]; struct printk_info info={.seq=123,.ts_nsec=1234567,.facility=1,.level=2,.flags=LOG_CONT,.caller_id=id};
  if(mode==0 || mode==4) snprintf(caller,12,"%c%u",id&0x80000000 ? 'C':'T',id&~0x80000000);
  else if(mode==3) caller[0]=0;
  else if(mode==2) strcpy(caller,"Q");
  else { memset(caller,mode==1 ? 'X':'V',11); caller[11]=0; }
  snprintf(want,sizeof(want),"[%6s]",caller); print_caller(id,out); CHECK(!strcmp(want,out)); cases++;
  if(mode==0 || mode==4) snprintf(caller,20,",caller=%c%u",id&0x80000000 ? 'C':'T',id&~0x80000000);
  else if(mode==3) caller[0]=0;
  else if(mode==2) strcpy(caller,"Q");
  else { memset(caller,mode==1 ? 'X':'V',19); caller[19]=0; }
  for(unsigned size=0;size<=sizeof(out);size++) {
   memset(want,0,sizeof(want)); memset(out,0,sizeof(out));
   int n=snprintf(want,size,"10,123,1234,c%s;",caller); unsigned expected=size ? ((unsigned)n<size ? (unsigned)n:size-1):0;
   int got=info_print_ext_header(out,size,&info); CHECK(got==(int)expected && !memcmp(want,out,sizeof(out))); cases++;
  }
 }
 printf("{\"cases\":%u,\"failures\":%u}\n",cases,failures); return failures ? 1 : 0;
}
'''

def run(code, directory, name):
    p=directory/(name+'.c');p.write_text(code)
    subprocess.run(['cc','-std=gnu11','-O0','-ftrivial-auto-var-init=pattern',str(p),'-o',str(directory/name)],check=True)
    r=subprocess.run([str(directory/name)],capture_output=True,text=True)
    return dict(json.loads(r.stdout),exit_code=r.returncode,source_sha256=hashlib.sha256(code.encode()).hexdigest())

def main():
    current=(ROOT/FILE).read_text()
    ack=subprocess.check_output(['git','show',ACK+':'+FILE],cwd=ROOT,text=True)
    store=function(ack,'vprintk_store')
    cont=store[store.index('\t\t\tif (flags & LOG_NEWLINE) {'):store.index('\n\t\t\tret = text_len;')]
    normal=store[store.index('\tif (!(flags & LOG_NEWLINE))'):store.index('\n\tret = text_len + trunc_msg_len;')]
    control='static void printk_commit_record(struct prb_reserved_entry *entry, struct printk_record *record, enum printk_info_flags flags, bool continuation, u16 text_len) {\nstruct prb_reserved_entry e=*entry; struct printk_record r=*record;\nif(continuation) {\n'+cont+'\n} else {\n'+normal+'\n}\n}\n'
    with tempfile.TemporaryDirectory(prefix='printk-hook-check-') as tmp:
        d=Path(tmp)
        records=run(PRE+function(current,'printk_commit_record_with_hooks')+function(current,'printk_commit_record')+RECORD_MAIN,d,'records')
        old_records=run(PRE+control+RECORD_MAIN,d,'ack-records')
        fmt=PRE+FORMAT_PRE
        formats=run(fmt+function(current,'print_caller')+function(current,'info_print_ext_header')+FORMAT_MAIN,d,'formats')
        old_formats=run(fmt+function(ack,'print_caller')+function(ack,'info_print_ext_header')+FORMAT_MAIN,d,'ack-formats')
    assert records['failures']==formats['failures']==0
    assert old_records['failures']>0 and old_formats['failures']>0
    result=dict(current_source_sha256=hashlib.sha256(current.encode()).hexdigest(),records=records,ack_records_control=old_records,formats=formats,ack_formats_control=old_formats,scope='Extracted actual snapshot/commit wrappers and formatting functions. Commit observer immediately overwrites original ring storage before hooks. Original controls use the ACK call-site blocks/functions. Formatter observers check termination before host printf. No real kernel ringbuffer, tracepoints, IRQ/NMI concurrency or emulator execution.')
    (ROOT/'Documentation/android-port/evidence/printk-hook-buffers-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
