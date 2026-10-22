#!/usr/bin/env python3
"""Exercise extracted anon-inode creation/release with host ownership/FFI shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
path = 'rust/kernel/anon_inodes.rs'
current = (ROOT / path).read_text()
original = subprocess.check_output(['git', 'show', ACK + ':' + path], cwd=ROOT, text=True)

def block(source, marker):
    start = source.index(marker)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

def extract(source):
    return ('trait AnonInodeFileInterface: Sized { type Ptr: ForeignOwnable + Send + Sync;\n' +
            block(source, '    fn release(device:') + '\n}\n' +
            'impl<T: AnonInodeFileInterface> AnonInodeFileVTable<T> {\n' +
            block(source, '    unsafe extern "C" fn release(') + '\n}\n' +
            block(source, 'pub fn anon_inode_create_getfile<') + '\n')

prefix = r'''
#![allow(dead_code,non_camel_case_types,private_bounds,private_interfaces)]
use std::{cell::Cell,ffi::{CStr,c_void},marker::PhantomData,ptr::NonNull};
mod ffi {pub type c_int=i32;}
type Error=i32;
type Result<T,E=Error>=std::result::Result<T,E>;
thread_local!{
 static MODE:Cell<i32>=const{Cell::new(0)};
 static DROPS:Cell<usize>=const{Cell::new(0)};
 static FILE_FREES:Cell<usize>=const{Cell::new(0)};
 static INVALID_FILE_REFS:Cell<usize>=const{Cell::new(0)};
 static ASSERTS:Cell<usize>=const{Cell::new(0)};
 static FAILS:Cell<usize>=const{Cell::new(0)};
}
fn check(v:bool){ASSERTS.with(|x|x.set(x.get()+1));if !v{FAILS.with(|x|x.set(x.get()+1));}}
trait ForeignOwnable:Sized {
 fn into_foreign(self)->*mut c_void;
 unsafe fn from_foreign(p:*mut c_void)->Self;
}
struct Owned(u32);
impl Drop for Owned {fn drop(&mut self){DROPS.with(|x|x.set(x.get()+1));}}
impl ForeignOwnable for Box<Owned>{
 fn into_foreign(self)->*mut c_void{Box::into_raw(self).cast()}
 unsafe fn from_foreign(p:*mut c_void)->Self{unsafe{Box::from_raw(p.cast())}}
}
struct Driver;
impl AnonInodeFileInterface for Driver {type Ptr=Box<Owned>;}
struct AnonInodeFileVTable<T:AnonInodeFileInterface>{fops:bindings::file_operations,marker:PhantomData<T>}
unsafe impl<T:AnonInodeFileInterface> Sync for AnonInodeFileVTable<T>{}
static VTABLE:AnonInodeFileVTable<Driver>=AnonInodeFileVTable{
 fops:bindings::file_operations{release:AnonInodeFileVTable::<Driver>::release},marker:PhantomData};
#[repr(transparent)]struct File(bindings::file);
impl File {
 unsafe fn from_raw_file<'a>(p:*mut bindings::file)->&'a File{
  if unsafe{(*p).refs}==0 {INVALID_FILE_REFS.with(|x|x.set(x.get()+1));}
  unsafe{&*p.cast()}
 }
}
struct ARef<T>(NonNull<T>);
impl ARef<File>{unsafe fn from_raw(p:NonNull<File>)->Self{Self(p)}}
impl<T> Drop for ARef<T>{fn drop(&mut self){unsafe{
 let p=self.0.as_ptr().cast::<bindings::file>();
 check((*p).refs==1);(*p).refs=0;
 ((*(*p).fops).release)(std::ptr::null_mut(),p);
 FILE_FREES.with(|x|x.set(x.get()+1));drop(Box::from_raw(p));
}}}
fn from_err_ptr<T>(p:*mut T)->Result<*mut T>{
 if p as usize>=usize::MAX-4094{Err(p as isize as i32)}else{Ok(p)}
}
mod bindings {
 use super::*;
 pub struct inode;
 pub struct file_operations{pub release:unsafe extern "C" fn(*mut inode,*mut file)->i32}
 pub struct file{pub private_data:*mut c_void,pub fops:*const file_operations,pub refs:usize}
 pub unsafe fn anon_inode_create_getfile(name:*const i8,ops:*const file_operations,priv_data:*mut c_void,flags:i32,context:*const inode)->*mut file{
  check(!name.is_null() && !ops.is_null() && !priv_data.is_null());check(context.is_null());check(flags==2);
  let mode=MODE.with(|x|x.get());if mode!=0{return (mode as isize) as *mut file;}
  Box::into_raw(Box::new(file{private_data:priv_data,fops:ops,refs:1}))
 }
}
'''
main = r'''
fn main(){let mut cases=0;
 for mode in [0,-12,-13,-2]{for value in [0,1,7,u32::MAX]{
  cases+=1;MODE.with(|x|x.set(mode));let d=DROPS.with(|x|x.get());let n=FILE_FREES.with(|x|x.get());
  let owned=Box::new(Owned(value));let original_ptr=(&*owned) as *const Owned;
  let result=anon_inode_create_getfile::<Driver>(c"check",owned,2,&VTABLE);
  check(DROPS.with(|x|x.get())==d);
  match result{
   Ok(file)=>{check(mode==0);drop(file);check(FILE_FREES.with(|x|x.get())==n+1);}
   Err((err,owned))=>{
    check(err==mode);check(owned.0==value);check(std::ptr::eq(original_ptr,&*owned));
    check(FILE_FREES.with(|x|x.get())==n);
    MODE.with(|x|x.set(0));let retry=anon_inode_create_getfile::<Driver>(c"retry",owned,2,&VTABLE);
    check(retry.is_ok());drop(retry);check(FILE_FREES.with(|x|x.get())==n+1);
   }
  }
  check(DROPS.with(|x|x.get())==d+1);
 }}
 check(INVALID_FILE_REFS.with(|x|x.get())==0);
 println!("{} cases, {} assertions, {} failures, {} invalid File references",cases,ASSERTS.with(|x|x.get()),FAILS.with(|x|x.get()),INVALID_FILE_REFS.with(|x|x.get()));
 if FAILS.with(|x|x.get())!=0{std::process::exit(1);}
}
'''
rustc = ROOT.parent / 'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results = {}
with tempfile.TemporaryDirectory(prefix='rust-anon-inode-') as td:
    td = Path(td)
    for name, source in [('current', current), ('original_ACK_release', original)]:
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
          'limitations': 'FFI, file refs and ownership are host shims. Checks extracted creation, error ownership return, retry and final release; no native LSM, file syscall, real refcount race, mmap, ioctl or SDK execution.'}
(D / 'evidence/rust-anon-inode-ownership-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(results, indent=2))
