#!/usr/bin/env python3
"""Check extracted WrapFD device get/put ownership and dma-buf reference accounting."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;ROOT=D.parents[1];ACK='23112ce1886ea26b19be03207c0227a06a6ca009';PATH='drivers/android/wrapfd/wrap.rs'
def block(s,m):
 a=s.index(m);o=s.index('{',a);e=o+1;n=1
 while n:n+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[a:e]
prefix=r'''
#![allow(dead_code,unused_mut,private_interfaces,non_camel_case_types)]
use std::{cell::{Cell,RefCell,RefMut},ptr::NonNull,sync::Arc};
#[derive(Clone,Copy,Debug)]struct Error(i32);impl Error{fn to_errno(self)->i32{self.0}}
const ENODEV:Error=Error(-19);const EINVAL:Error=Error(-22);const ENOENT:Error=Error(-2);const EBUSY:Error=Error(-16);const EOVERFLOW:Error=Error(-75);
type Result<T=()> = std::result::Result<T,Error>;type ARef<T>=Arc<T>;
mod ffi{pub type c_int=i32;}
struct Lock<T>(RefCell<T>);impl<T>Lock<T>{fn lock(&self)->RefMut<'_,T>{self.0.borrow_mut()}}
macro_rules! pr_warn{($($a:tt)*)=>{{}}}
struct Task;
mod device{#[derive(PartialEq)]pub struct Device(pub usize);impl Device{pub unsafe fn get_device(p:*mut Self)->super::ARef<Self>{unsafe{super::Arc::increment_strong_count(p);super::Arc::from_raw(p)}}pub unsafe fn from_raw<'a>(p:*mut Self)->&'a Self{unsafe{&*p}}}}
trait AlwaysRefCounted{unsafe fn dec_ref(p:NonNull<Self>);}
struct DmaBuf{refs:Cell<usize>}impl DmaBuf{fn inc_ref(&self){self.refs.set(self.refs.get()+1);}fn as_ptr(&self)->*mut Self{self as *const Self as *mut Self}}
impl AlwaysRefCounted for DmaBuf{unsafe fn dec_ref(p:NonNull<Self>){let b=unsafe{p.as_ref()};b.refs.set(b.refs.get()-1);}}
struct Content{dmabuf:ARef<DmaBuf>}
struct WrapInfo{content:Option<Content>,owner:WrapOwner,mapped:bool}impl WrapInfo{fn is_mapped(&mut self)->bool{self.mapped}}
#[derive(Clone,Copy)]enum WrapState{Available,UsageBlocked,InUse(usize)}
struct Wrap{state:Lock<WrapState>,inner:Lock<WrapInfo>}
mod bindings{pub type device=super::device::Device;pub struct file{pub wrap:super::Wrap,pub valid:bool}pub struct wrapfd_mappable{pub dmabuf:*mut super::DmaBuf}}
fn with_wrap_helper(file:*mut bindings::file,_label:&'static str,f:impl FnOnce(&Wrap)->Result)->Result{if file.is_null()||!unsafe{(*file).valid}{return Err(Error(-9));}f(unsafe{&(*file).wrap})}
'''
suffix=r'''
fn main(){let mut cases=0;let mut failures=0;let mut check=|v:bool|{cases+=1;if !v{failures+=1;}};
 for n in 1..=32usize{let dev=Arc::new(device::Device(1));let other=Arc::new(device::Device(2));let dp=Arc::as_ptr(&dev)as *mut _;let op=Arc::as_ptr(&other)as *mut _;let buf=Arc::new(DmaBuf{refs:Cell::new(1)});
  let mut file=bindings::file{valid:true,wrap:Wrap{state:Lock(RefCell::new(WrapState::Available)),inner:Lock(RefCell::new(WrapInfo{owner:WrapOwner::None,content:Some(Content{dmabuf:buf.clone()}),mapped:false}))}};
  let mut maps:Vec<_>=(0..n).map(|_|bindings::wrapfd_mappable{dmabuf:std::ptr::null_mut()}).collect();
  for m in &mut maps{check(unsafe{wrapfd_get_mappable(&mut file,dp,m)}==0);check(m.dmabuf==buf.as_ptr());}
  check(buf.refs.get()==1+n);let mut wrong=bindings::wrapfd_mappable{dmabuf:std::ptr::null_mut()};check(unsafe{wrapfd_get_mappable(&mut file,op,&mut wrong)}==-16);
  check(unsafe{wrapfd_put_mappable(&mut file,dp,&mut wrong)}==-22);check(buf.refs.get()==1+n);
  for (i,m) in maps.iter_mut().enumerate(){check(unsafe{wrapfd_put_mappable(&mut file,dp,m)}==0);check(buf.refs.get()==n-i);check(file.wrap.inner.lock().owner.has_owner()==(i+1<n));if i+1<n{check(unsafe{wrapfd_get_mappable(&mut file,op,&mut wrong)}==-16);}}
  check(buf.refs.get()==1);check(unsafe{wrapfd_put_mappable(&mut file,dp,&mut maps[0])}==-16);
  check(unsafe{wrapfd_get_mappable(&mut file,op,&mut wrong)}==0);check(unsafe{wrapfd_put_mappable(&mut file,op,&mut wrong)}==0);check(buf.refs.get()==1);
  check(unsafe{wrapfd_get_mappable(&mut file,std::ptr::null_mut(),&mut wrong)}==-19);check(unsafe{wrapfd_get_mappable(&mut file,dp,std::ptr::null_mut())}==-22);
 }
 println!("{cases} assertions, {failures} failures");if failures>0{std::process::exit(1);}
}
'''
rustc=ROOT.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc';results={}
with tempfile.TemporaryDirectory(prefix='wrapfd-device-') as td:
 td=Path(td)
 for name in ['current','original_ACK']:
  s=(ROOT/PATH).read_text() if name=='current' else subprocess.check_output(['git','show',ACK+':'+PATH],cwd=ROOT,text=True)
  body=block(s,'enum WrapOwner {')+'\nimpl WrapOwner{fn has_owner(&mut self)->bool{!matches!(self,Self::None)}\n'+block(s,'    fn owned_by_device(')+'\n}\n'+'\n'.join(block(s,m) for m in ['unsafe extern "C" fn wrapfd_get_mappable(','unsafe extern "C" fn wrapfd_put_mappable(']);src=td/(name+'.rs');exe=td/name;src.write_text(prefix+body+suffix)
  c=subprocess.run([str(rustc),'--edition=2021','-C','overflow-checks=yes',str(src),'-o',str(exe)],capture_output=True,text=True);assert c.returncode==0,c.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True);results[name]={'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'extracted_sha256':hashlib.sha256(body.encode()).hexdigest()};assert (r.returncode==0)==(name=='current'),results[name]
report=dict(scope=__doc__,results=results,negative_control_source=ACK,limitations='Actual get/put bodies and device equality selector run with simulated file checks, device/dma-buf refcounts and locks. Covers 1..32 nested acquisitions, mismatched device/buffer and null arguments, and release ownership until final put. No kernel module caller, concurrent DMA, actual device removal or CFI indirect call executed.')
(D/'evidence/wrapfd-device-ownership-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:{'returncode':v['returncode'],'stdout':v['stdout']} for k,v in results.items()},indent=2))
