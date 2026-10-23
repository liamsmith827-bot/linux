#!/usr/bin/env python3
"""Run extracted C Binder destruction paths with vendor-allocation and lifetime shims."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;ROOT=D.parents[1]
CONTROL='00159c0f0f16'
def block(s,marker):
 start=s.index(marker);op=s.index('{',start);end=op+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
PRE=r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
struct binder_transaction;
struct binder_buffer {struct binder_transaction *transaction;};
struct binder_thread {int tmp_ref;};
struct binder_proc {int outstanding_txns;bool is_frozen;int freeze_wait,alloc;};
struct binder_node {int unused;};
struct binder_transaction {int lock;struct binder_proc *to_proc;struct binder_thread *to_thread;struct binder_buffer *buffer;};
struct secctx {void *context;};
static struct binder_transaction tx;
static struct binder_buffer buf;
static int calls,active,failures,cases,case_failed,buffer_live,fixups,freed,return_error_line;
#define CHECK(x) do {if (!(x)) {failures++;case_failed=1;}} while(0)
#define spin_lock(...) ((void)0)
#define spin_unlock(...) ((void)0)
#define binder_inner_proc_lock(...) ((void)0)
#define binder_inner_proc_unlock(...) ((void)0)
#define atomic_inc(p) (++*(p))
#define binder_thread_dec_tmpref(p) (--(p)->tmp_ref)
#define wake_up_interruptible_all(...) ((void)0)
#define pr_warn(...) ((void)0)
#define trace_binder_txn_latency_free_enabled() false
#define binder_txn_latency_free(...) ((void)0)
#define binder_stats_deleted(...) ((void)0)
#define binder_txn_error(...) ((void)0)
#define binder_dequeue_work(...) ((void)0)
#define binder_cleanup_deferred_txn_lists(...) ((void)0)
#define trace_binder_transaction_failed_buffer_release(...) ((void)0)
#define trace_binder_transaction_update_buffer_release(...) ((void)0)
#define binder_dec_node(...) ((void)0)
#define binder_dec_node_tmpref(...) ((void)0)
#define security_release_secctx(...) ((void)0)
#define binder_netlink_report(...) ((void)0)
static void trace_android_vh_free_oem_binder_struct(struct binder_transaction *t) {
 CHECK(t==&tx);CHECK(!freed);CHECK(!t->buffer || buffer_live);calls++;active=0;
}
static void binder_free_txn_fixups(struct binder_transaction *t) {CHECK(!freed);fixups=0;}
static void binder_transaction_buffer_release(struct binder_proc *p,void *thread,struct binder_buffer *b,int off,bool failure) {CHECK(buffer_live);CHECK(failure);}
static void binder_release_entire_buffer(struct binder_proc *p,void *thread,struct binder_buffer *b,bool failure) {CHECK(buffer_live);CHECK(failure);}
static void binder_alloc_free_buf(void *alloc,struct binder_buffer *b) {CHECK(buffer_live);buffer_live=0;}
static void kfree(void *p) {if(p==&tx){CHECK(calls==1);CHECK(!active);CHECK(!fixups);CHECK(!freed);freed=1;}}
static void setup(struct binder_proc *p,struct binder_thread *thread,bool buffer,bool vendor) {
 memset(&tx,0,sizeof(tx));memset(&buf,0,sizeof(buf));memset(p,0,sizeof(*p));memset(thread,0,sizeof(*thread));
 calls=active=buffer_live=fixups=freed=case_failed=0;tx.to_proc=p;tx.to_thread=thread;
 p->outstanding_txns=1;p->is_frozen=true;active=vendor;buffer_live=buffer;fixups=buffer;
 if(buffer){tx.buffer=&buf;buf.transaction=&tx;}
}
'''
def extract(s):
 normal=block(s,'static void binder_free_transaction(')
 start=s.index('\nerr_dead_proc_or_thread:');end=s.index('\nerr_alloc_t_failed:',start)
 errors=s[start:end]
 labels=re.findall(r'^([a-z][a-z0-9_]*):',errors,re.M)
 outdated=block(s[s.index('static int binder_proc_transaction('):],'if (t_outdated) {\n\t\tstruct binder_buffer')
 text=PRE+normal+'\n'
 # Compile each real goto entry with its native label fallthrough intact.
 for label in labels:
  text+='static void run_'+label+'(void) {\nstruct binder_transaction *t=&tx; struct binder_proc *proc=tx.to_proc,*target_proc=tx.to_proc; struct binder_thread *thread=tx.to_thread; struct binder_node *target_node=NULL; struct secctx lsmctx={0}; int tcomplete_storage; void *tcomplete=&tcomplete_storage; int buffer_offset=0; bool vendor_data_freed=false; goto '+label+';\n'+errors+'\n}\n'
 text+='static void run_outdated(void){struct binder_transaction *t_outdated=&tx;struct binder_proc *proc=tx.to_proc;'+outdated+'}\n'
 text+='int main(void){struct binder_proc proc;struct binder_thread thread;\n'
 late=True
 for label in labels:
  if label=='err_binder_alloc_buf_failed':late=False
  text+='for(int vendor=0;vendor<2;vendor++){setup(&proc,&thread,'+str(int(late))+',vendor);run_'+label+'();CHECK(freed);CHECK(calls==1);cases++;}\n'
 text+='for(int vendor=0;vendor<2;vendor++){setup(&proc,&thread,true,vendor);run_outdated();CHECK(freed);CHECK(calls==1);CHECK(!buffer_live);cases++;}\n'
 text+='for(int vendor=0;vendor<2;vendor++)for(int target=0;target<2;target++)for(int buffer=0;buffer<2;buffer++){setup(&proc,&thread,buffer,vendor);if(!target)tx.to_thread=NULL;binder_free_transaction(&tx);CHECK(freed);CHECK(calls==1);CHECK(proc.outstanding_txns==0);CHECK(thread.tmp_ref==0);cases++;}\n'
 text+='printf("%d cases, %d failed assertions\\n",cases,failures);return failures!=0;}\n'
 return text,labels,normal+errors+outdated
results={};path='drivers/android/binder.c'
cc=ROOT.parent/'kernel_manifest-6.18/prebuilts/clang/host/linux-x86/clang-r584948c/bin/clang'
with tempfile.TemporaryDirectory(prefix='binder-vendor-cleanup-') as tmp:
 for name in ['current','previous_port']:
  s=(ROOT/path).read_text() if name=='current' else subprocess.check_output(['git','show',CONTROL+':'+path],cwd=ROOT,text=True)
  src,labels,body=extract(s);p=Path(tmp)/(name+'.c');exe=Path(tmp)/name;p.write_text(src)
  c=subprocess.run([str(cc),'-std=gnu11','-Wall','-Wno-unused-variable','-Wno-unused-label',str(p),'-o',str(exe)],capture_output=True,text=True)
  if c.returncode:Path('/tmp/binder-vendor-cleanup-failed.c').write_text(src)
  assert c.returncode==0,c.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True)
  results[name]={'returncode':r.returncode,'stdout':r.stdout.strip(),'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'error_entry_labels':labels}
  assert (r.returncode==0)==(name=='current'),results[name]
report=dict(scope=__doc__,negative_control_source=subprocess.check_output(['git','rev-parse',CONTROL],cwd=ROOT,text=True).strip(),results=results,limitations='Executes extracted destruction function, all error labels through native cleanup fallthrough, and outdated-transaction destruction block with allocation, buffer, refcount and lock shims. Checks exactly one callback, no live simulated vendor allocation at free, callback before buffer destruction, and preserved native failure/fixup cleanup. Does not execute Binder syscalls, actual vendor modules, locking races or fault injection in a running kernel.',remote_sources_used=[])
(D/'evidence/binder-vendor-cleanup-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(results,indent=2))
