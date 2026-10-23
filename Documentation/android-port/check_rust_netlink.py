#!/usr/bin/env python3
"""Check extracted Rust netlink size and ownership paths with host FFI shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
path = 'rust/kernel/net/netlink.rs'
current = (ROOT / path).read_text()
original = subprocess.check_output(['git', 'show', ACK + ':' + path], cwd=ROOT, text=True)

def block(s, marker):
    start = s.index(marker)
    opening = s.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (s[end] == '{') - (s[end] == '}')
        end += 1
    return s[start:end]

def extract(s):
    constants = ''
    if 'const MAX_GENL_PAYLOAD' in s:
        constants = s[s.index('const NLMSG_HDRLEN'):s.index('/// A wrapper around')]
    body = constants + '\n'
    for marker in ['pub struct NetlinkSkBuff {', 'impl NetlinkSkBuff {', 'impl Drop for NetlinkSkBuff {',
                   'pub struct GenlMsg {', 'impl GenlMsg {', 'impl Drop for GenlMsg {']:
        body += block(s, marker) + '\n'
    listener = '    pub unsafe fn has_listeners(' if '    pub unsafe fn has_listeners(' in s else '    pub fn has_listeners('
    body += 'impl Family {\n' + block(s, listener) + '\n'
    if '    fn has_group(' in s:
        body += block(s, '    fn has_group(') + '\n'
    return body + '}\n'

prefix = r'''
#![allow(dead_code,non_camel_case_types,non_upper_case_globals,private_interfaces)]
extern crate self as kernel;
use std::{cell::{Cell,UnsafeCell,RefCell},collections::BTreeSet,ffi::{c_int,c_void,CStr},mem::{ManuallyDrop,size_of,size_of_val},ptr::NonNull};
type Result<T=(),E=i32>=std::result::Result<T,E>;
struct Error;impl Error{fn from_errno(e:i32)->i32{e}}
const EMSGSIZE:i32=-90;const EINVAL:i32=-22;
fn to_result(x:i32)->Result{if x<0{Err(x)}else{Ok(())}}
mod alloc {
 #[derive(Debug,PartialEq)] pub struct AllocError;
 #[derive(Clone,Copy)]pub struct Flags(pub u32);
 impl Flags{pub fn as_raw(self)->u32{self.0}}
}
use alloc::AllocError;
trait AsBytes{}impl AsBytes for [u8]{}impl AsBytes for u32{}
trait CStrExt{fn as_bytes_with_nul(&self)->&[u8];}
impl CStrExt for CStr{fn as_bytes_with_nul(&self)->&[u8]{self.to_bytes_with_nul()}}
struct Family{raw:UnsafeCell<bindings::genl_family>}
unsafe impl Sync for Family{}
impl Family{fn as_raw(&self)->*mut bindings::genl_family{self.raw.get()}}
static FAMILIES:[Family;3]=[
 Family{raw:UnsafeCell::new(bindings::genl_family{n_mcgrps:0})},
 Family{raw:UnsafeCell::new(bindings::genl_family{n_mcgrps:1})},
 Family{raw:UnsafeCell::new(bindings::genl_family{n_mcgrps:2})}];
thread_local!{
 static MODE:Cell<u32>=const{Cell::new(0)};static CHECKS:Cell<usize>=const{Cell::new(0)};
 static FAILS:Cell<usize>=const{Cell::new(0)};static CANCEL:Cell<usize>=const{Cell::new(0)};
 static LIVE:RefCell<BTreeSet<usize>>=RefCell::new(BTreeSet::new());
}
fn check(x:bool){CHECKS.with(|v|v.set(v.get()+1));if !x{FAILS.with(|v|v.set(v.get()+1));}}
fn live()->usize{LIVE.with(|v|v.borrow().len())}
fn cleanup(){let ptrs:Vec<_>=LIVE.with(|v|v.borrow().iter().copied().collect());for p in ptrs{unsafe{bindings::nlmsg_free(p as *mut bindings::sk_buff)}}}
mod bindings {
 use super::*;
 pub const NLMSG_ALIGNTO:u32=4;pub const NLA_ALIGNTO:u32=4;pub const EMSGSIZE:u32=90;
 #[repr(C)]pub struct nlmsghdr{len:u32,ty:u16,flags:u16,seq:u32,pid:u32}
 #[repr(C)]pub struct genlmsghdr{cmd:u8,version:u8,reserved:u16}
 #[repr(C)]pub struct nlattr{len:u16,ty:u16}
 pub static mut init_net:u8=0;
 pub struct genl_family{pub n_mcgrps:u8}
 pub struct sk_buff{capacity:usize,used:usize}
 pub unsafe fn genlmsg_new(size:usize,_flags:u32)->*mut sk_buff{
  if MODE.with(|m|m.get())==1{return std::ptr::null_mut();}
  // Model size arithmetic without allocating the requested buffer. Oversize
  // inputs must be rejected by the Rust API before reaching native arithmetic.
  let total=(((size as u128+4+3)&!3)+16+3)&!3;
  check(total<=i32::MAX as u128);
  let p=Box::into_raw(Box::new(sk_buff{capacity:size.saturating_add(20),used:0}));
  LIVE.with(|v|{v.borrow_mut().insert(p as usize);});p
 }
 pub unsafe fn genlmsg_put(s:*mut sk_buff,_p:u32,_seq:u32,_f:*mut genl_family,_fl:i32,_cmd:u8)->*mut c_void{
  check(LIVE.with(|v|v.borrow().contains(&(s as usize))));
  if MODE.with(|m|m.get())==2{return std::ptr::null_mut();}
  unsafe{(*s).used=20;}s.cast()
 }
 pub unsafe fn nlmsg_free(s:*mut sk_buff){let owned=LIVE.with(|v|v.borrow_mut().remove(&(s as usize)));check(owned);if owned{drop(unsafe{Box::from_raw(s)});}}
 pub unsafe fn genlmsg_cancel(s:*mut sk_buff,h:*mut c_void){check(s.cast::<c_void>()==h);CANCEL.with(|v|v.set(v.get()+1));}
 pub unsafe fn genlmsg_end(s:*mut sk_buff,h:*mut c_void){check(s.cast::<c_void>()==h);}
 pub unsafe fn nla_put(s:*mut sk_buff,_t:c_int,len:c_int,_p:*const c_void)->i32{
  check((0..=65531).contains(&len));
  if !(0..=65531).contains(&len){return 0;}
  let total=(len as usize+4+3)&!3;
  if unsafe{(*s).capacity-(*s).used}<total{return -(EMSGSIZE as i32);}
  unsafe{(*s).used+=total;}0
 }
 pub unsafe fn genlmsg_multicast(f:*mut genl_family,s:*mut sk_buff,_p:u32,g:u32,_flags:u32)->i32{
  if g>=unsafe{(*f).n_mcgrps as u32}{return EINVAL;}
  unsafe{nlmsg_free(s)};if MODE.with(|m|m.get())==3{-3}else{0}
 }
 pub unsafe fn genl_has_listeners(f:*mut genl_family,_net:*mut u8,g:u32)->i32{
  if g>=unsafe{(*f).n_mcgrps as u32}{EINVAL}else if MODE.with(|m|m.get())==3{0}else{1}
 }
}
'''
main = r'''
fn main(){unsafe{let mut cases=0;let flags=alloc::Flags(0);
 for size in [0,1,4096,2147483624,2147483625,i32::MAX as usize,usize::MAX]{
  for mode in [0,1]{cases+=1;MODE.with(|v|v.set(mode));let b=NetlinkSkBuff::new(size,flags);
   let total=(((size as u128+4+3)&!3)+16+3)&!3;check(b.is_ok()==(mode==0 && total<=i32::MAX as u128));drop(b);check(live()==0);
  }
 }
 for len in [0,1,4,65530,65531,65532,65535,65536,1048576]{
  cases+=1;MODE.with(|v|v.set(0));let b=NetlinkSkBuff::new(2*1048576,flags).unwrap();let mut msg=b.genlmsg_put(0,0,&FAMILIES[1],1).unwrap();
  let data=vec![0u8;len];let r=msg.put(1,data.as_slice());check(r.is_ok()==(len<=65531));drop(msg);check(live()==0);
 }
 for family in &FAMILIES{for group in [0,1,2,3,u32::MAX]{for mode in [0,3]{
  cases+=1;MODE.with(|v|v.set(mode));let good=group<unsafe{(*family.as_raw()).n_mcgrps as u32};
  check(family.has_listeners(group)==(good && mode==0));
  let msg=NetlinkSkBuff::new(4096,flags).unwrap().genlmsg_put(0,0,family,1).unwrap();
  let cancels=CANCEL.with(|v|v.get());let r=msg.multicast(family,0,group,flags);
  check(r==if !good{Err(EINVAL)}else if mode==3{Err(-3)}else{Ok(())});
  check(live()==0);check(CANCEL.with(|v|v.get())==cancels+usize::from(!good));cleanup();
 }}}
 cases+=1;MODE.with(|v|v.set(2));let r=NetlinkSkBuff::new(4096,flags).unwrap().genlmsg_put(0,0,&FAMILIES[1],1);check(r.is_err());drop(r);check(live()==0);
 cases+=1;MODE.with(|v|v.set(0));let mut msg=NetlinkSkBuff::new(0,flags).unwrap().genlmsg_put(0,0,&FAMILIES[1],1).unwrap();check(msg.put_u32(1,7)==Err(EMSGSIZE));drop(msg);check(live()==0);
 println!("{} cases, {} assertions, {} failures",cases,CHECKS.with(|v|v.get()),FAILS.with(|v|v.get()));
 if FAILS.with(|v|v.get())!=0{std::process::exit(1);}
}}
'''
rustc = ROOT.parent / 'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results = {}
with tempfile.TemporaryDirectory(prefix='rust-netlink-') as td:
    td = Path(td)
    for name, source in [('current', current), ('original_ACK', original)]:
        body = extract(source)
        src, exe = td / (name + '.rs'), td / name
        src.write_text(prefix + body + main)
        r = subprocess.run([str(rustc), '--edition=2021', str(src), '-o', str(exe)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        results[name] = {'returncode': r.returncode, 'stdout': r.stdout.strip(),
                         'extracted_sha256': hashlib.sha256(body.encode()).hexdigest()}
        assert (r.returncode == 0) == (name == 'current'), (name, r.stdout, r.stderr)
report = {'source_sha256': hashlib.sha256(current.encode()).hexdigest(), 'scope': __doc__,
          'results': results, 'negative_control_source': ACK,
          'rustc_version': subprocess.check_output([str(rustc), '--version'], text=True).strip(),
          'limitations': 'Native allocation, SKB storage, attributes, registered families and multicast are host shims. No real netlink traffic, large allocation, registration/unload race, namespace, SELinux or Android userspace execution.'}
(D / 'evidence/rust-netlink-ownership-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(results, indent=2))
