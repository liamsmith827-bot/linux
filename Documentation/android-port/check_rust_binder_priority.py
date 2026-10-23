#!/usr/bin/env python3
"""Check extracted Rust Binder priority decoding, limits, selection and restoration decisions."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
paths = ['drivers/android/binder/'+p for p in ['prio.rs','node.rs','thread.rs','transaction.rs']]+['rust/kernel/task.rs']

def block(s, marker):
    start=s.index(marker);opening=s.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(s[end]=='{')-(s[end]=='}');end+=1
    return s[start:end]

prefix=r'''
#![allow(dead_code,unused_imports,non_camel_case_types,private_interfaces)]
extern crate self as kernel;
use std::{cell::{Cell,RefCell,RefMut,UnsafeCell},sync::atomic::{AtomicBool,Ordering}};
pub mod ffi{pub type c_uint=u32;pub type c_int=i32;}
pub mod bindings{
 pub const SCHED_NORMAL:u32=0;pub const SCHED_FIFO:u32=1;pub const SCHED_RR:u32=2;pub const SCHED_BATCH:u32=3;
 pub const MIN_NICE:i32=-20;pub const MAX_NICE:i32=19;pub const DEFAULT_PRIO:i32=120;pub const MAX_RT_PRIO:i32=100;
 pub const CAP_SYS_NICE:u32=23;pub const RLIMIT_RTPRIO:u32=14;pub const RLIMIT_NICE:u32=13;
 pub struct task_struct{pub rt:usize,pub nice:usize}
 pub unsafe fn task_rlimit(p:*mut task_struct,r:u32)->usize{if r==RLIMIT_RTPRIO{unsafe{(*p).rt}}else{unsafe{(*p).nice}}}
}
macro_rules! pr_err{($($t:tt)*)=>{{}}}macro_rules! pr_debug{($($t:tt)*)=>{{}}}
pub mod task{pub use crate::Task;}
pub struct Opaque<T>(UnsafeCell<T>);impl<T> Opaque<T>{fn get(&self)->*mut T{self.0.get()}}
pub struct Task(Opaque<bindings::task_struct>,Cell<u32>,Cell<i32>,bool,Cell<bool>);
impl Task{
 fn new(policy:u32,prio:i32,rt:usize,nice:usize,cap:bool)->Self{Self(Opaque(UnsafeCell::new(bindings::task_struct{rt,nice})),Cell::new(policy),Cell::new(prio),cap,Cell::new(false))}
 fn policy(&self)->u32{self.1.get()}fn normal_prio(&self)->i32{self.2.get()}fn pid(&self)->i32{1}fn has_capability_noaudit(&self,_c:i32)->bool{self.3}
 fn sched_setscheduler_nocheck(&self,p:i32,n:i32,reset:bool){if (p==1||p==2)&&(1..=99).contains(&n){self.1.set(p as u32);self.2.set(99-n);self.4.set(reset);}else if (p==0||p==3)&&n==0{self.1.set(p as u32);self.4.set(reset);}}
 fn set_user_nice(&self,n:i32){if (-20..=19).contains(&n){self.2.set(120+n);}}
}
mod prio{
'''
middle=r'''
}
use prio::{BinderPriority,PriorityState};
struct Lock<T>(RefCell<T>);impl<T> Lock<T>{fn lock(&self)->RefMut<'_,T>{self.0.borrow_mut()}}
struct ThreadPrioState{state:PriorityState,next:BinderPriority}
struct Thread{task:Box<Task>,prio_lock:Lock<ThreadPrioState>,selected:Cell<Option<BinderPriority>>}
impl Thread{fn new(policy:u32,p:i32,rt:usize,nice:usize,cap:bool)->Self{Self{task:Box::new(Task::new(policy,p,rt,nice,cap)),prio_lock:Lock(RefCell::new(ThreadPrioState{state:PriorityState::Set,next:BinderPriority::default()})),selected:Cell::new(None)}}fn set_priority(&self,p:&BinderPriority,_t:&Transaction){self.selected.set(Some(*p));}}
const FLAT_BINDER_FLAG_PRIORITY_MASK:u32=255;const FLAT_BINDER_FLAG_SCHED_POLICY_MASK:u32=3<<9;const FLAT_BINDER_FLAG_SCHED_POLICY_SHIFT:u32=9;const FLAT_BINDER_FLAG_INHERIT_RT:u32=1<<11;
struct Node{flags:u32}struct Process{task:Box<Task>}
struct Transaction{target_node:Option<Node>,priority:BinderPriority,saved_priority:Lock<BinderPriority>,set_priority_called:AtomicBool,to:Process}
mod trace{pub fn trace_set_priority(_t:&super::Task,_a:i32,_b:i32){}pub fn trace_transaction_thread_selected(_t:&super::Transaction,_th:&super::Thread){}}
'''
suffix=r'''
fn main(){let mut checks=0;let mut failures=0;let mut check=|v:bool|{checks+=1;if !v{failures+=1;}};
 for policy in [1,2]{for p in [i32::MIN,-128,0,99,127,i32::MAX]{let expected=(99i64-p as i64).clamp(i32::MIN as i64,i32::MAX as i64) as i32;check(prio::to_kernel_prio(policy,p)==expected);}}
 for policy in 0..4u32{for raw in 0..=255u32{let node=Node{flags:raw|(policy<<9)};let p=node.node_prio();let signed=if raw<128{raw as i32}else{raw as i32-256};let expected=if policy==0||policy==3{120+signed}else{99-signed};check(p.sched_policy==policy);check(p.prio==expected);}}
 for rt in [0usize,1,49,50,99,100,i32::MAX as usize,i32::MAX as usize+1,u32::MAX as usize,1usize<<32,usize::MAX]{
  let task=Task::new(0,120,rt,40,false);check(task.rlimit_rtprio()==rt.min(99) as i32);
  for policy in [1,2]{for cap in [false,true]{let th=Thread::new(0,120,rt,40,cap);th.do_set_priority(&BinderPriority{sched_policy:policy,prio:50},true);
   let expected=if !cap&&rt==0{(0,100)}else{(policy,99-if cap{49}else{49.min(rt.min(99) as i32)})};check((th.task.policy(),th.task.normal_prio())==expected);
   if expected.0!=0{check(th.task.4.get());}
  }}
 }
 for nice in [0usize,1,20,40,usize::MAX]{let th=Thread::new(0,120,0,nice,false);th.do_set_priority(&BinderPriority{sched_policy:0,prio:100},true);let expected=if nice==0{120}else{120+(-20).max(20-nice.min(40) as i32)};check(th.task.normal_prio()==expected);}
 for node_policy in 0..4u32{for raw in [0u32,1,19,50,99,236,255]{for caller_policy in 0..4u32{for inherit in [false,true]{for pending in [false,true]{
  let th=Thread::new(3,125,99,40,false);if pending{*th.prio_lock.lock()=ThreadPrioState{state:PriorityState::Pending,next:BinderPriority{sched_policy:0,prio:130}};}
  let caller_prio=if caller_policy==1||caller_policy==2{49}else{120};
  let t=Transaction{target_node:Some(Node{flags:raw|(node_policy<<9)|if inherit{1<<11}else{0}}),priority:BinderPriority{sched_policy:caller_policy,prio:caller_prio},saved_priority:Lock(RefCell::new(BinderPriority::default())),set_priority_called:AtomicBool::new(false),to:Process{task:Box::new(Task::new(0,139,99,40,false))}};
  t.on_thread_selected(&th);let actual=th.selected.get().unwrap();
  let signed=if raw<128{raw as i32}else{raw as i32-256};let node_prio=if node_policy==0||node_policy==3{120+signed}else{99-signed};
  let mut want=if !inherit&&(caller_policy==1||caller_policy==2){(0,120)}else{(caller_policy,caller_prio)};
  if node_prio<want.1 || (node_prio==want.1&&node_policy==1){want=(node_policy,node_prio);}
  check((actual.sched_policy,actual.prio)==want);let saved=t.saved_priority.lock();check((saved.sched_policy,saved.prio)==if pending{(0,130)}else{(3,125)});drop(saved);
  if pending{check(th.prio_lock.lock().state==PriorityState::Abort);}
  th.selected.set(None);t.on_thread_selected(&th);check(th.selected.get().is_none());
 }}}}}
 let th=Thread::new(0,120,99,40,false);th.prio_lock.lock().state=PriorityState::Abort;th.do_set_priority(&BinderPriority{sched_policy:0,prio:130},false);check(th.task.normal_prio()==120);
 println!("{checks} assertions, {failures} failures");if failures!=0{std::process::exit(1);}
}
'''

def extract(sources):
    prio,node,thread,transaction,task=sources
    body='\n'.join(l for l in prio.splitlines() if not l.startswith('//!'))+middle
    body+='impl Node {\n'+block(node,'    pub(crate) fn node_prio(')+'\n'+block(node,'    pub(crate) fn inherit_rt(')+'\n}\n'
    body+='impl Task {\n'+block(task,'    pub fn rlimit_rtprio(')+'\n'+block(task,'    pub fn rlimit_nice(')+'\n}\n'
    body+='impl Thread {\n'+block(thread,'    fn do_set_priority(')+'\n}\n'
    body+='impl Transaction {\n'+block(transaction,'    fn on_thread_selected(')+'\n}\n'
    return body

rustc=ROOT.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results={}
with tempfile.TemporaryDirectory(prefix='rust-binder-prio-') as td:
    td=Path(td)
    for name in ['current','original_ACK']:
        sources=[(ROOT/p).read_text() if name=='current' else subprocess.check_output(['git','show',ACK+':'+p],cwd=ROOT,text=True) for p in paths]
        body=extract(sources);src=td/(name+'.rs');exe=td/name;src.write_text(prefix+body+suffix)
        c=subprocess.run([str(rustc),'--edition=2021',str(src),'-o',str(exe)],capture_output=True,text=True);assert c.returncode==0,c.stderr
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        results[name]={'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr,'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in zip(paths,sources)}}
        assert (r.returncode==0)==(name=='current'),results[name]
report={'scope':__doc__,'results':results,'negative_control_source':ACK,'limitations':'Native task structures, capability/rlimit reads, scheduler changes, spinlocks and trace hooks are host shims. Tests inspect extracted decision paths against the native C signed-byte, priority-selection and resource-limit contracts. No actual scheduling, RT load, Binder IPC, concurrency or vendor callback was executed.'}
(D/'evidence/rust-binder-priority-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({n:{k:v for k,v in r.items() if k in ['returncode','stdout']} for n,r in results.items()},indent=2))
