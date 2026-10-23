#!/usr/bin/env python3
"""Check extracted node-debug enumeration against native strict-greater lookup semantics."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

D=Path(__file__).resolve().parent; ROOT=D.parents[1]
ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
PATH='drivers/android/binder/process.rs'

def block(s,marker):
    start=s.index(marker);opening=s.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(s[end]=='{')-(s[end]=='}');end+=1
    return s[start:end]

prefix=r'''
#![allow(dead_code)]
use std::{cell::{Cell,RefCell,RefMut},rc::Rc};
type Result<T=()> = std::result::Result<T,()>;
#[derive(Clone,Copy,Default,PartialEq,Debug)]struct BinderNodeDebugInfo{ptr:u64,cookie:u64,has_strong_ref:u32,has_weak_ref:u32}
struct Reader(u64);struct Writer(Rc<Cell<BinderNodeDebugInfo>>);struct UserSlice(u64,Rc<Cell<BinderNodeDebugInfo>>);
impl UserSlice{fn reader_writer(self)->(Reader,Writer){(Reader(self.0),Writer(self.1))}}
impl Reader{fn read<T:From<BinderNodeDebugInfo>>(&mut self)->Result<T>{Ok(BinderNodeDebugInfo{ptr:self.0,..Default::default()}.into())}}
impl Writer{fn write(&mut self,x:&BinderNodeDebugInfo)->Result{self.0.set(*x);Ok(())}}
struct Lock<T>(RefCell<T>);impl<T> Lock<T>{fn lock(&self)->RefMut<'_,T>{self.0.borrow_mut()}}
struct Node(BinderNodeDebugInfo);impl Node{fn populate_debug_info(&self,out:&mut BinderNodeDebugInfo,_inner:&Inner){*out=self.0;}}
struct Tree(Vec<(u64,Rc<Node>)>);struct Cursor<'a>(&'a (u64,Rc<Node>));
impl Tree{fn cursor_lower_bound(&mut self,key:&u64)->Option<Cursor<'_>>{self.0.iter().find(|(k,_)|k>=key).map(Cursor)}}
impl Cursor<'_>{fn current(&self)->(&u64,&Rc<Node>){(&self.0.0,&self.0.1)}}
struct Inner{nodes:Tree}struct Process{inner:Lock<Inner>}
impl Process{
'''
suffix=r'''
}
fn main(){std::panic::set_hook(Box::new(|_|{}));let mut checks=0;let mut failures=0;let mut panics=0;
 for seed in 0..32u64{let mut keys=if seed==0{Vec::new()}else{vec![0,1,u64::MAX-1,u64::MAX]};
  if seed>0{for n in 1..=seed{keys.push(seed.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(n as u32));}keys.sort();keys.dedup();}
  let values:Vec<_>=keys.iter().map(|&k|(k,Rc::new(Node(BinderNodeDebugInfo{ptr:k,cookie:k^0xa5a5,has_strong_ref:1,has_weak_ref:1})))).collect();
  let mut queries=vec![0,1,2,u64::MAX/2,u64::MAX-1,u64::MAX];for &k in &keys{queries.extend([k.saturating_sub(1),k,k.saturating_add(1)]);}
  let p=Process{inner:Lock(RefCell::new(Inner{nodes:Tree(values.clone())}))};
  for q in queries{checks+=1;let out=Rc::new(Cell::new(BinderNodeDebugInfo::default()));let expected=values.iter().find(|(k,_)|*k>q).map(|(_,n)|n.0).unwrap_or_default();
   match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||p.get_node_debug_info(UserSlice(q,out.clone())))){
    Ok(Ok(()))=>if out.get()!=expected{failures+=1;},Ok(Err(()))=>failures+=1,Err(_)=>{failures+=1;panics+=1;}
   }
  }
 }
 println!("{checks} cases, {failures} failures, {panics} panics");if failures!=0{std::process::exit(1);}
}
'''
rustc=ROOT.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results={}
with tempfile.TemporaryDirectory(prefix='binder-node-query-') as td:
    td=Path(td)
    for name in ['current','original_ACK']:
        source=(ROOT/PATH).read_text() if name=='current' else subprocess.check_output(['git','show',ACK+':'+PATH],cwd=ROOT,text=True)
        body=block(source,'    fn get_node_debug_info(');src=td/(name+'.rs');exe=td/name;src.write_text(prefix+body+suffix)
        c=subprocess.run([str(rustc),'--edition=2021','-C','overflow-checks=yes',str(src),'-o',str(exe)],capture_output=True,text=True);assert c.returncode==0,c.stderr
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        results[name]={'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'extracted_sha256':hashlib.sha256(body.encode()).hexdigest()}
        assert (r.returncode==0)==(name=='current'),results[name]
report=dict(scope=__doc__,results=results,negative_control_source=ACK,limitations='Native RBTree cursor, locks, refcounts and usercopy are host shims. Expected output is the native C strictly-greater traversal over the same sorted keys. This verifies query boundary/output semantics and detects checked-arithmetic panics; it does not execute a kernel ioctl, native tree traversal or concurrent mutation.')
(D/'evidence/rust-binder-node-query-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({n:{k:v for k,v in r.items() if k in ['returncode','stdout']} for n,r in results.items()},indent=2))
