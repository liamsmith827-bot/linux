#!/usr/bin/env python3
"""Execute extracted quota2 lifecycle functions with mocked procfs/netlink.

Interleavings are injected at lock-release/proc-create boundaries, not run as
kernel threads. Does not test real proc rundown, packet paths or netlink sockets.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
p='net/netfilter/xt_quota2.c';src=(ROOT/p).read_text()
OLD='3e2089059c3b';old=subprocess.check_output(['git','show',OLD+':'+p],cwd=ROOT,text=True)
pre_uaf=subprocess.check_output(['git','show','550e926637c5^:'+p],cwd=ROOT,text=True)
names=['q2_new_counter','q2_get_counter','quota_mt2_destroy','quota_mt2_init','quota_mt2_exit']
def body(text, name):
    value=function(text,name)
    if value.startswith(name+'('):
        assert name in ['q2_new_counter','q2_get_counter']
        value='static struct xt_quota_counter *\n'+value
    return value
preamble=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __init
#define __exit
#define GFP_KERNEL 0
#define NETLINK_NFLOG 5
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define pr_debug(...) ((void)0)
#define typeof __typeof__
#define IS_ERR_OR_NULL(p) (!(p) || (uintptr_t)(p)>=(uintptr_t)-4095)
typedef int spinlock_t;
typedef int atomic_t;
#define atomic_set(p,v) (*(p)=(v))
#define atomic_inc(p) (++*(p))
#define atomic_dec_and_test(p) (!--*(p))
#define spin_lock_init(p) (*(p)=0)
struct list_head {struct list_head *next,*prev;};
#define INIT_LIST_HEAD(p) ((p)->next=(p)->prev=(p))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(e,h,m) for(struct list_head *it=(h)->next; it!=(h) && ((e)=container_of(it,typeof(*(e)),m),1);it=it->next)
static void list_add_tail(struct list_head *p,struct list_head *h){p->prev=h->prev;p->next=h;h->prev->next=p;h->prev=p;}
static void list_del(struct list_head *p){p->prev->next=p->next;p->next->prev=p->prev;}
struct proc_dir_entry {char name[16];bool live;};
struct xt_quota_counter {uint64_t quota;spinlock_t lock;struct list_head list;atomic_t ref;char name[15];struct proc_dir_entry *procfs_entry;};
struct xt_quota_mtinfo2 {char name[15];unsigned char flags;uint64_t quota;struct xt_quota_counter *master;};
struct xt_mtdtor_param {void *matchinfo;};
struct sock {int unused;};
static struct sock socket_object,*nflognl;
static struct {struct proc_dir_entry *proc_net;} init_net;
static struct proc_dir_entry root,entries[64],*proc_xt_quota;
static struct list_head counter_list;
static spinlock_t counter_list_lock;
static unsigned quota_list_perms,quota_list_uid,quota_list_gid;
static int q2_counter_fops,quota_mt2_reg[2];
static unsigned live_allocs,fail_alloc,fail_create,borrow_on_create,entry_count;
static unsigned fail_socket,fail_mkdir,fail_register,socket_live,dir_live,registered;
static unsigned removals,missing_removals,cases;
static void (*unlock_hook)(void);
static struct xt_quota_counter *borrowed,*replacement;
static struct xt_quota_mtinfo2 request={.name="shared",.quota=1234};
static struct xt_quota_counter *q2_get_counter(const struct xt_quota_mtinfo2 *q);
static void spin_lock_bh(spinlock_t *p){assert(!*p);*p=1;}
static void spin_unlock_bh(spinlock_t *p){assert(*p);*p=0;if(unlock_hook){void (*fn)(void)=unlock_hook;unlock_hook=NULL;fn();}}
static void *kmalloc(size_t n,int g){if(fail_alloc)return NULL;void *p=malloc(n);assert(p);memset(p,0xa5,n);live_allocs++;return p;}
static void kfree(void *p){if(p){assert(live_allocs);live_allocs--;free(p);}}
static void strscpy(char *d,const char *s,size_t n){snprintf(d,n,"%s",s);}
static struct proc_dir_entry *proc_create_data(const char *name,unsigned perms,struct proc_dir_entry *parent,void *ops,void *e){
 assert(!counter_list_lock);
 if(borrow_on_create){borrow_on_create=0;borrowed=q2_get_counter(&request);assert(borrowed==e);}
 if(fail_create)return NULL;
 for(unsigned i=0;i<entry_count;i++)if(entries[i].live&&!strcmp(entries[i].name,name))return NULL;
 assert(entry_count<64);struct proc_dir_entry *p=&entries[entry_count++];strscpy(p->name,name,sizeof(p->name));p->live=true;return p;
}
static void proc_set_user(struct proc_dir_entry *p,unsigned u,unsigned g){assert(p&&p->live);}
static void remove_proc_entry(const char *name,struct proc_dir_entry *parent){
 assert(!counter_list_lock);if(!strcmp(name,"xt_quota")){assert(dir_live);dir_live=0;return;}
 for(unsigned i=0;i<entry_count;i++)if(entries[i].live&&!strcmp(entries[i].name,name)){entries[i].live=false;removals++;return;}missing_removals++;
}
static void proc_remove(struct proc_dir_entry *p){if(p){assert(p->live);remove_proc_entry(p->name,proc_xt_quota);}}
static struct sock *netlink_kernel_create(void *net,int proto,void *cfg){if(fail_socket)return NULL;assert(!socket_live);socket_live=1;return &socket_object;}
static void netlink_kernel_release(struct sock *p){assert(p==&socket_object&&socket_live);socket_live=0;}
static struct proc_dir_entry *proc_mkdir(const char *n,struct proc_dir_entry *p){if(fail_mkdir)return NULL;assert(!dir_live);dir_live=1;return &root;}
static int xt_register_matches(void *m,size_t n){if(fail_register)return -EINVAL;registered=1;return 0;}
static void xt_unregister_matches(void *m,size_t n){assert(registered);registered=0;}
static void reset(void){assert(!live_allocs);assert(!socket_live&&!dir_live&&!registered);INIT_LIST_HEAD(&counter_list);memset(entries,0,sizeof(entries));counter_list_lock=0;entry_count=fail_alloc=fail_create=borrow_on_create=removals=missing_removals=0;fail_socket=fail_mkdir=fail_register=0;unlock_hook=NULL;borrowed=replacement=NULL;proc_xt_quota=&root;}
'''
code=preamble+'\n'.join(body(src,n) for n in names)
code+='\n'+function(old,'quota_mt2_destroy').replace('quota_mt2_destroy','old_destroy')
code+='\n'+body(pre_uaf,'q2_get_counter').replace('q2_get_counter','pre_uaf_get_counter')
code+='\n'+function(old,'quota_mt2_init').replace('quota_mt2_init','old_init')
code+='\n'+function(old,'quota_mt2_exit').replace('quota_mt2_exit','old_exit')
code+=r'''
static void destroy(struct xt_quota_counter *e, bool anon, bool before){struct xt_quota_mtinfo2 q={.master=e};if(!anon)strscpy(q.name,"shared",sizeof(q.name));struct xt_mtdtor_param par={.matchinfo=&q};if(before)old_destroy(&par);else quota_mt2_destroy(&par);}
static void create_replacement(void){replacement=q2_get_counter(&request);assert(replacement&&replacement->procfs_entry->live);}
int main(int argc,char **argv){
 reset();
 if(argc>1&&!strcmp(argv[1],"uaf")){fail_create=borrow_on_create=1;assert(!pre_uaf_get_counter(&request));assert(borrowed);volatile uint64_t v=borrowed->quota;(void)v;return 0;}
 if(argc>1&&!strcmp(argv[1],"replacement")){fail_create=borrow_on_create=1;assert(!q2_get_counter(&request));assert(borrowed);fail_create=0;unlock_hook=create_replacement;destroy(borrowed,false,true);assert(replacement->procfs_entry->live);return 0;}
 if(argc>1&&!strcmp(argv[1],"socket")){
#ifdef CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG
  fail_mkdir=1;assert(old_init()==-EACCES);assert(!socket_live);
#endif
  return 0;
 }
 struct xt_quota_mtinfo2 anon={.quota=77};struct xt_quota_counter *e,*other;
 e=q2_get_counter(&anon);assert(e&&e->quota==77);destroy(e,true,false);cases++;reset();
 fail_alloc=1;assert(!q2_get_counter(&request));assert(counter_list.next==&counter_list);cases++;reset();
 fail_create=1;assert(!q2_get_counter(&request));assert(counter_list.next==&counter_list&&!live_allocs);cases++;reset();
 e=q2_get_counter(&request);assert(e&&e->procfs_entry->live&&e->ref==1);other=q2_get_counter(&request);assert(e==other&&e->ref==2);destroy(other,false,false);assert(e->ref==1&&e->procfs_entry->live);destroy(e,false,false);assert(removals==1&&!missing_removals);cases++;reset();
 fail_create=borrow_on_create=1;assert(!q2_get_counter(&request));assert(borrowed&&borrowed->ref==1&&borrowed->quota==1234&&!borrowed->procfs_entry);destroy(borrowed,false,false);assert(!removals&&!missing_removals);cases++;reset();
 fail_create=borrow_on_create=1;assert(!q2_get_counter(&request));assert(borrowed);fail_create=0;unlock_hook=create_replacement;destroy(borrowed,false,false);assert(replacement->procfs_entry->live&&!removals);destroy(replacement,false,false);assert(removals==1&&!missing_removals);cases++;reset();
#ifdef CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG
 fail_socket=1;assert(quota_mt2_init()==-ENOMEM);assert(!socket_live&&!dir_live&&!registered);cases++;reset();
#endif
 fail_mkdir=1;assert(quota_mt2_init()==-EACCES);assert(!socket_live&&!dir_live&&!registered);cases++;reset();
 fail_register=1;assert(quota_mt2_init()==-EINVAL);assert(!socket_live&&!dir_live&&!registered);cases++;reset();
 assert(!quota_mt2_init());assert(dir_live&&registered);quota_mt2_exit();assert(!socket_live&&!dir_live&&!registered);cases++;reset();
 printf("%u lifecycle cases passed\n",cases);return 0;
}
'''
results={};controls={}
with tempfile.TemporaryDirectory(prefix='quota2-check-') as td:
 c=Path(td)/'test.c';c.write_text(code)
 for enabled in [False,True]:
  out=Path(td)/('logging' if enabled else 'no_logging')
  cmd=['cc','-std=gnu11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-no-pie',str(c),'-o',str(out)]
  if enabled:cmd.insert(1,'-DCONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG=1')
  subprocess.run(cmd,check=True)
  results[out.name]=subprocess.check_output([str(out)],text=True).strip()
  if enabled:
   for mode,diagnostic in [('uaf','heap-use-after-free'),('replacement','replacement->procfs_entry->live'),('socket','!socket_live')]:
    r=subprocess.run([str(out),mode],capture_output=True,text=True);assert r.returncode and diagnostic in r.stderr,(mode,r.returncode,r.stderr);controls[mode]=dict(rejected=True,diagnostic=diagnostic)
report=dict(source_sha256=hashlib.sha256(src.encode()).hexdigest(),pre_change_commit=subprocess.check_output(['git','rev-parse',OLD],cwd=ROOT,text=True).strip(),ack_pre_uaf_commit=subprocess.check_output(['git','rev-parse','550e926637c5^'],cwd=ROOT,text=True).strip(),results=results,negative_controls=controls,sanitizers='AddressSanitizer and UndefinedBehaviorSanitizer',limitations=__doc__,remote_sources_used=[])
(ROOT/'Documentation/android-port/evidence/quota2-lifetime-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
