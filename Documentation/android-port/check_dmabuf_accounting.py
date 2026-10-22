#!/usr/bin/env python3
"""Run extracted DMA-buf accounting and procfs functions with host fault shims.

No real allocation fault, mmap, file-descriptor operation, kernel concurrency,
procfs access or LMK execution is performed.
"""
import hashlib, json, re, subprocess, tempfile
from pathlib import Path
D = Path(__file__).resolve().parent
root = D.parents[1]
sources = {p:(root/p).read_text() for p in
           ('drivers/dma-buf/dma-buf.c', 'fs/proc/base.c', 'include/linux/dma-buf.h')}
def function(s, name):
    start = s.rfind('\n', 0, s.index(name + '(')) + 1
    # Include the return type when it is on the preceding line.
    if s[start:s.index(name+'(')].strip() == '':
        start = s.rfind('\n', 0, start-1) + 1
    opening = s.index('{', s.index(name+'(', start))
    depth = 1
    end = opening + 1
    while depth:
        depth += (s[end] == '{') - (s[end] == '}')
        end += 1
    return s[start:end] + '\n'
dma_names = ['find_task_dmabuf_record','add_task_dmabuf_record',
             '__dma_buf_account_task','dma_buf_unaccount_task']
proc_names = ['proc_dmabuf_rss_show','proc_dmabuf_rss_hwm_show',
              'proc_dmabuf_rss_hwm_write','proc_dmabuf_pss_show']
dma = ''.join(function(sources['drivers/dma-buf/dma-buf.c'],n) for n in dma_names)
proc = ''.join(function(sources['fs/proc/base.c'],n) for n in proc_names)
header = sources['include/linux/dma-buf.h']
structs = '\n'.join(re.search(r'struct '+n+r' \{.*?\n\};',header,re.S)[0]
                    for n in ['task_dma_buf_record','task_dma_buf_info'])
prefix = r"""
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
typedef long long s64; typedef int refcount_t; typedef int spinlock_t;
static unsigned long checks, failures, cases;
#define CHECK(x) (++checks,(x)?0:(++failures,0))
#define __user
#define lockdep_assert_held(p) CHECK(*(p)==1)
static void spin_lock(int *p){CHECK(!*p);++*p;}
static void spin_unlock(int *p){CHECK(*p==1);--*p;}
struct list_head {struct list_head *next,*prev;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *it=(h)->next;it!=(h) && ((p)=container_of(it,typeof(*(p)),m),1);it=it->next)
static void init_list(struct list_head *p){p->next=p->prev=p;}
static void list_add(struct list_head *n,struct list_head *h){n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
struct dma_buf {unsigned long size;long long nr_task_refs;};
static void atomic64_inc(long long *p){++*p;}
static void atomic64_dec(long long *p){CHECK(*p>0);--*p;}
static long long atomic64_read(long long *p){return *p;}
#define trace_dmabuf_rss_stat(...) ((void)0)
#define pr_err(...) ((void)0)
static bool enabled=true;
static bool is_dmabuf_accounting_enabled(void){return enabled;}
"""
shims = r"""
static bool fail_preload, fail_alloc;
static unsigned pool_lock, preload_calls, allocations, frees;
static void (*preload_hook)(void);
static bool task_dmabuf_records_preload(size_t count){
 CHECK(count==1 && !pool_lock);preload_calls++;
 bool fail=fail_preload;
 if(preload_hook){void (*h)(void)=preload_hook;preload_hook=NULL;h();}
 if(fail)return false;
 pool_lock=1;return true;
}
static void task_dmabuf_records_preload_end(void){CHECK(pool_lock==1);pool_lock=0;}
static void trim_task_dmabuf_records_locked(void){CHECK(pool_lock==1);}
static struct task_dma_buf_record *alloc_task_dmabuf_record(void){
 CHECK(pool_lock==1);if(fail_alloc)return NULL;allocations++;
 return calloc(1,sizeof(struct task_dma_buf_record));
}
static void free_task_dmabuf_record(struct task_dma_buf_record *p){frees++;free(p);}
struct task_struct {struct task_dma_buf_info *info;};
struct inode {struct task_struct *task;};
struct file {struct inode *inode;};
struct seq_file {void *private;unsigned long value;unsigned writes;};
struct pid_namespace {};struct pid {};
static unsigned task_gets,task_puts,info_gets,info_puts;
static struct task_struct *get_proc_task(struct inode *p){if(p->task)task_gets++;return p->task;}
static void put_task_struct(struct task_struct *p){task_puts++;}
static struct task_dma_buf_info *get_task_dmabuf_info(struct task_struct *t){if(t->info)info_gets++;return t->info;}
static void put_dmabuf_info(struct task_dma_buf_info *p){info_puts++;}
static void seq_printf(struct seq_file *s,const char *fmt,unsigned long n){s->value=n;s->writes++;}
static struct inode *file_inode(struct file *f){return f->inode;}
static int kstrtoull_from_user(const char *p,size_t n,int b,unsigned long long *v){if(n!=1 || *p<'0' || *p>'9')return -EINVAL;*v=*p-'0';return 0;}
"""
main = r"""
static struct dma_buf buffers[2];
static struct task_dma_buf_info info;
static void reset(void){
 memset(&info,0,sizeof(info));init_list(&info.dmabufs);
 buffers[0]=(struct dma_buf){.size=4096};buffers[1]=(struct dma_buf){.size=12288};
 fail_preload=fail_alloc=false;preload_hook=NULL;pool_lock=preload_calls=allocations=frees=0;
 task_gets=task_puts=info_gets=info_puts=0;
}
static void verify(unsigned live[2],unsigned known[2],bool unknown,unsigned long *high){
 unsigned count=0,seen=0;unsigned long rss=0;struct task_dma_buf_record *r;
 for(unsigned i=0;i<2;i++){
  CHECK(known[i]<=live[i]);
  if(known[i]){count++;rss+=buffers[i].size;}
  CHECK(buffers[i].nr_task_refs==(known[i]!=0));
 }
 if(rss>*high)*high=rss;
 CHECK(info.incomplete==unknown && info.rss==rss && info.rss_hwm==*high && info.dmabuf_count==count);
 list_for_each_entry(r,&info.dmabufs,node){
  unsigned id=r->dmabuf-buffers;CHECK(id<2);if(id<2)CHECK(r->refcnt==known[id] && known[id]>0);seen++;
 }
 CHECK(seen==count && !info.lock && !pool_lock);
 struct task_struct task={&info};struct inode inode={&task};struct seq_file s={.private=&inode};
 int ret=proc_dmabuf_rss_show(&s,NULL,NULL,&task);
 CHECK(ret==(unknown?-EIO:0) && s.writes==!unknown);if(!unknown)CHECK(s.value==rss);
 s.writes=0;ret=proc_dmabuf_pss_show(&s,NULL,NULL,&task);
 CHECK(ret==(unknown?-EIO:0) && s.writes==!unknown);if(!unknown)CHECK(s.value==rss);
 s.writes=0;ret=proc_dmabuf_rss_hwm_show(&s,NULL);
 CHECK(ret==(unknown?-EIO:0) && s.writes==!unknown);if(!unknown)CHECK(s.value==*high);
 CHECK(task_gets==task_puts && info_gets==info_puts);
}
static void race_add(void){fail_preload=false;CHECK(__dma_buf_account_task(&buffers[0],&info,true)==0);}
static void race_fail_other(void){fail_preload=true;CHECK(__dma_buf_account_task(&buffers[1],&info,true)==-ENOMEM);fail_preload=false;}
int main(void){
 /* Enumerate reference acquire/release histories. Each acquisition is either
  * a successful reservation or an injected failure for one of two buffers.
  * 'known' counts abstract reference tokens, independent of list/pool code.
  */
 for(unsigned seq=0;seq<46656;seq++){
  reset();unsigned live[2]={0},known[2]={0},code=seq;bool unknown=false;unsigned long high=0;cases++;
  for(unsigned step=0;step<6;step++,code/=6){
   unsigned op=code%6,id=op%2;
   if(op<4){
    fail_preload=op>=2;bool was_known=known[id]>0;
    bool fail=!was_known && !unknown && fail_preload;
    unsigned before=preload_calls;
    int ret=__dma_buf_account_task(&buffers[id],&info,true);
    CHECK(ret==(fail?-ENOMEM:0));live[id]++;
    if(was_known || (!unknown && !fail))known[id]++;
    if(fail)unknown=true;
    if(was_known || (unknown && !fail))CHECK(preload_calls==before);
   }else if(live[id]){
    dma_buf_unaccount_task(&buffers[id],&info);live[id]--;
    if(known[id])known[id]--;
   }
   verify(live,known,unknown,&high);
  }
  struct task_struct task={&info};struct inode inode={&task};struct file f={&inode};
  CHECK(proc_dmabuf_rss_hwm_write(&f,"0",1,NULL)==(unknown?-EIO:1));
  CHECK(info.rss_hwm==(unknown?high:info.rss));
  CHECK(proc_dmabuf_rss_hwm_write(&f,"1",1,NULL)==-EINVAL);
  CHECK(proc_dmabuf_rss_hwm_write(&f,"x",1,NULL)==-EINVAL);
  for(unsigned i=0;i<2;i++)while(live[i]){dma_buf_unaccount_task(&buffers[i],&info);live[i]--;}
  CHECK(info.rss==0 && info.dmabuf_count==0 && allocations==frees && !pool_lock);
  CHECK(buffers[0].nr_task_refs==0 && buffers[1].nr_task_refs==0);
 }
 /* A record appearing during a failed preload makes the new reference
  * countable; an unrelated failure during successful preload forbids insert.
  */
 for(unsigned fail=0;fail<2;fail++){
  reset();cases++;fail_preload=fail;preload_hook=race_add;
  CHECK(__dma_buf_account_task(&buffers[0],&info,true)==0);
  unsigned live[2]={2,0},known[2]={2,0};unsigned long high=0;
  verify(live,known,false,&high);
  dma_buf_unaccount_task(&buffers[0],&info);dma_buf_unaccount_task(&buffers[0],&info);
  CHECK(allocations==frees && !pool_lock);
 }
 reset();cases++;preload_hook=race_fail_other;
 CHECK(__dma_buf_account_task(&buffers[0],&info,true)==0);
 unsigned live[2]={1,1},known[2]={0,0};unsigned long high=0;
 verify(live,known,true,&high);
 dma_buf_unaccount_task(&buffers[0],&info);dma_buf_unaccount_task(&buffers[1],&info);
 CHECK(allocations==frees && !pool_lock);
 /* Fork/exec callers own the preload lock. Exhaustion marks unavailable;
  * the account helper must never release their lock.
  */
 for(unsigned fail=0;fail<2;fail++){
  reset();cases++;pool_lock=1;fail_alloc=fail;
  CHECK(__dma_buf_account_task(&buffers[0],&info,false)==(fail?-ENOMEM:0));CHECK(pool_lock==1);
  pool_lock=0;unsigned l[2]={1,0},k[2]={!fail,0};unsigned long h=0;verify(l,k,fail,&h);
  dma_buf_unaccount_task(&buffers[0],&info);CHECK(allocations==frees);
 }
 reset();cases++;enabled=false;CHECK(__dma_buf_account_task(&buffers[0],&info,true)==0 && !preload_calls);
 enabled=true;CHECK(__dma_buf_account_task(&buffers[0],NULL,true)==0 && !preload_calls);
 struct task_struct task={NULL};struct inode inode={&task};struct seq_file s={.private=&inode};struct file f={&inode};
 CHECK(proc_dmabuf_rss_show(&s,NULL,NULL,&task)==0 && !s.writes);
 CHECK(proc_dmabuf_pss_show(&s,NULL,NULL,&task)==0 && !s.writes);
 CHECK(proc_dmabuf_rss_hwm_show(&s,NULL)==0 && !s.writes);
 CHECK(proc_dmabuf_rss_hwm_write(&f,"0",1,NULL)==-ENOENT);
 inode.task=NULL;CHECK(proc_dmabuf_rss_hwm_show(&s,NULL)==-ESRCH);
 CHECK(proc_dmabuf_rss_hwm_write(&f,"0",1,NULL)==-ESRCH);
 CHECK(task_gets==task_puts && info_gets==info_puts);
 printf("%lu cases, %lu assertions, %lu failures\n",cases,checks,failures);
 return failures!=0;
}
"""
body = prefix + structs + shims + dma + proc + main
# Each mutation must fail a substantive invariant in the same oracle suite.
mutations = {
 'allow_new_records_after_failure':
     (dma, dma.replace('if (dmabuf_info->incomplete) {','if (false) {',1).replace('else if (!dmabuf_info->incomplete)', 'else')),
 'allocate_before_duplicate_lookup':
     (dma, dma.replace('if (rec) {\n\t\t++rec->refcnt;', 'if (rec) {\n\t\tif (fail_preload) return -ENOMEM;\n\t\t++rec->refcnt;',1)),
 'do_not_mark_unavailable':
     (dma, dma.replace('dmabuf_info->incomplete = true;', 'dmabuf_info->incomplete = false;')),
 'publish_incomplete_procfs_values':
     (proc, proc.replace('incomplete = dmabuf_info->incomplete;', 'incomplete = false;').replace('if (dmabuf_info->incomplete)', 'if (false)')),
}
results={}
with tempfile.TemporaryDirectory(prefix='dmabuf-accounting-') as td:
    td=Path(td)
    for name, code in [('current',body)]+[(n,body.replace(a,b,1)) for n,(a,b) in mutations.items()]:
        path=td/(name+'.c');path.write_text(code)
        exe=td/name
        subprocess.run(['cc','-std=gnu11','-O1','-g','-Wall','-Werror=implicit-function-declaration',str(path),'-o',str(exe)],check=True,capture_output=True)
        result=subprocess.run([str(exe)],text=True,capture_output=True)
        results[name]={'returncode':result.returncode,'stdout':result.stdout.strip()}
        assert (result.returncode==0)==(name=='current'),(name,result.stdout,result.stderr)
report={'scope':__doc__, 'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},
        'extracted_functions':dma_names+proc_names,'results':results,
        'limitations':'Allocator, per-CPU pool, locks, tracepoints, task references and seq_file use host shims. Deterministic callbacks examine selected interleavings; this does not execute real kernel concurrency, fork/exec, FDs, mappings or LMK.'}
(D/'evidence/dmabuf-accounting-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(results,indent=2))
