#!/usr/bin/env python3
"""Check extracted Rust DMA-buf attachment ownership with host refcount shims."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
root=D.parents[1]
s=(root/'rust/kernel/dma_buf/buf.rs').read_text()
def block(marker):
 start=s.index(marker);opening=s.index('{',start);depth=1;end=opening+1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
attach=block('    pub fn attach(')
body='impl DmaBuf {\n'+attach+'\n}\n'
for marker in ['pub struct DmaBufAttachment {','impl DmaBufAttachment {','impl Drop for DmaBufAttachment {','pub struct DmaBufMapping {','impl Drop for DmaBufMapping {']:
 body+=block(marker)+'\n'
prefix=r'''
#![allow(dead_code,non_camel_case_types)]
use std::{ptr::NonNull,cell::Cell,ops::Deref};
type Result<T> = std::result::Result<T,i32>;
const EINVAL:i32=-22;
#[derive(Clone,Copy)]enum DataDirection {To,From,Both}
impl From<DataDirection> for i32{fn from(d:DataDirection)->i32{match d{DataDirection::To=>1,DataDirection::From=>2,DataDirection::Both=>3}}}
thread_local!{static CHECKS:Cell<u64>=const{Cell::new(0)};static FAILS:Cell<u64>=const{Cell::new(0)};static MODE:Cell<u8>=const{Cell::new(0)};static ATTACH:Cell<u64>=const{Cell::new(0)};static DETACH:Cell<u64>=const{Cell::new(0)};static MAP:Cell<u64>=const{Cell::new(0)};static UNMAP:Cell<u64>=const{Cell::new(0)};}
fn check(v:bool){CHECKS.with(|x|x.set(x.get()+1));if !v{FAILS.with(|x|x.set(x.get()+1));}}
trait Counted {fn refs(&self)->&Cell<usize>;}
struct ARef<T:Counted>(NonNull<T>);
impl<T:Counted> From<&T> for ARef<T>{fn from(p:&T)->Self{check(p.refs().get()>0);p.refs().set(p.refs().get()+1);Self(NonNull::from(p))}}
impl<T:Counted>Deref for ARef<T>{type Target=T;fn deref(&self)->&T{unsafe{self.0.as_ref()}}}
impl<T:Counted>Drop for ARef<T>{fn drop(&mut self){let p=unsafe{self.0.as_ref()};check(p.refs().get()>0);p.refs().set(p.refs().get()-1);}}
struct Device{refs:Cell<usize>}
impl Counted for Device{fn refs(&self)->&Cell<usize>{&self.refs}}
impl Device{fn as_raw(&self)->*mut Self{self as *const Self as *mut Self}}
struct DmaBuf{refs:Cell<usize>}
impl Counted for DmaBuf{fn refs(&self)->&Cell<usize>{&self.refs}}
impl DmaBuf{fn as_ptr(&self)->*mut Self{self as *const Self as *mut Self}}
fn from_err_ptr<T>(p:*mut T)->Result<*mut T>{if p as usize>=usize::MAX-4094{Err(p as isize as i32)}else{Ok(p)}}
mod bindings{
 use super::*;
 pub struct dma_buf_attachment{buf:*mut DmaBuf,dev:*mut Device}
 pub struct sg_table{attachment:*mut dma_buf_attachment,dir:i32}
 unsafe fn live(a:*mut dma_buf_attachment){let a=unsafe{&*a};check(unsafe{(*a.buf).refs.get()>0 && (*a.dev).refs.get()>0});}
 pub unsafe fn dma_buf_attach(buf:*mut DmaBuf,dev:*mut Device)->*mut dma_buf_attachment{
  check(unsafe{(*buf).refs.get()>0 && (*dev).refs.get()>0});
  if MODE.with(|x|x.get())==1{return (-12isize) as *mut _;}
  ATTACH.with(|x|x.set(x.get()+1));Box::into_raw(Box::new(dma_buf_attachment{buf,dev}))
 }
 pub unsafe fn dma_buf_detach(buf:*mut DmaBuf,a:*mut dma_buf_attachment){
  unsafe{live(a)};check(unsafe{(*a).buf==buf});DETACH.with(|x|x.set(x.get()+1));drop(unsafe{Box::from_raw(a)});
 }
 pub unsafe fn dma_buf_map_attachment_unlocked(a:*mut dma_buf_attachment,dir:i32)->*mut sg_table{
  unsafe{live(a)};if MODE.with(|x|x.get())==2{return (-5isize) as *mut _;}
  MAP.with(|x|x.set(x.get()+1));Box::into_raw(Box::new(sg_table{attachment:a,dir}))
 }
 pub unsafe fn dma_buf_unmap_attachment_unlocked(a:*mut dma_buf_attachment,sg:*mut sg_table,dir:i32){
  unsafe{live(a)};check(unsafe{(*sg).attachment==a && (*sg).dir==dir});UNMAP.with(|x|x.set(x.get()+1));drop(unsafe{Box::from_raw(sg)});
 }
}
'''
main=r'''
fn main(){let mut cases=0;
 for mode in 0..3{for early_buf in [false,true]{for early_dev in [false,true]{for dir in [DataDirection::To,DataDirection::From,DataDirection::Both]{
  cases+=1;MODE.with(|x|x.set(mode));
  let b=Box::new(DmaBuf{refs:Cell::new(1)});let d=Box::new(Device{refs:Cell::new(1)});
  let result=b.attach(&d);
  if mode==1{check(matches!(result,Err(-12)));check(b.refs.get()==1 && d.refs.get()==1);continue;}
  check(result.is_ok());let a=result.unwrap();check(b.refs.get()==2 && d.refs.get()==2);
  // Model release of the caller's last device/buffer ownership. Storage is
  // retained by the harness to observe invalid dereferences without host UB.
  if early_buf{b.refs.set(b.refs.get()-1);}if early_dev{d.refs.set(d.refs.get()-1);}
  let mapped=a.map(dir);
  if mode==2{check(matches!(mapped,Err(-5)));}else{check(mapped.is_ok());drop(mapped);}
  check(b.refs.get()==usize::from(!early_buf) && d.refs.get()==usize::from(!early_dev));
 }}}}
 check(ATTACH.with(|x|x.get())==DETACH.with(|x|x.get()));
 check(MAP.with(|x|x.get())==UNMAP.with(|x|x.get()));
 println!("{} cases, {} assertions, {} failures",cases,CHECKS.with(|x|x.get()),FAILS.with(|x|x.get()));
 if FAILS.with(|x|x.get())!=0{std::process::exit(1);}
}
'''
old=body.replace('            _dev: ARef::from(dev),\n','').replace('    _dev: ARef<Device>,\n','')
assert old!=body
rustc=root.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results={}
with tempfile.TemporaryDirectory(prefix='rust-dmabuf-') as td:
 td=Path(td)
 for name,impl in [('current',body),('missing_device_reference',old)]:
  src=td/(name+'.rs');src.write_text(prefix+impl+main);exe=td/name
  subprocess.run([str(rustc),'--edition=2021',str(src),'-o',str(exe)],check=True,capture_output=True)
  r=subprocess.run([str(exe)],capture_output=True,text=True)
  results[name]={'returncode':r.returncode,'stdout':r.stdout.strip()}
  assert (r.returncode==0)==(name=='current'),(name,r.stdout,r.stderr)
report={'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'extracted_body_sha256':hashlib.sha256(body.encode()).hexdigest(),'scope':__doc__,'results':results,'rustc':str(rustc),'rustc_version':subprocess.check_output([str(rustc),'--version'],text=True).strip(),'limitations':'Refcount, device, buffer and attach/map FFI are host shims. Checks destruction ordering and fallible ownership transfer; no real DMA, device unbind, concurrency, SDK boot or C exporter executed.'}
(D/'evidence/rust-dmabuf-attachment-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(results,indent=2))
