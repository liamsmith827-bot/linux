#!/usr/bin/env python3
"""Exercise extracted ashmem ioctl dispatch and toggle reads with Rust host shims.

Compile ioctl numbers and payload size from the actual C UAPI. Check the legacy
GET_PIN_STATUS zero-size encoding still receives its eight-byte input payload,
toggle reads report copied bytes and advance positions across short reads, and
global toggle writes require privilege before consuming input or changing state.
Old-source controls reproduce all three mismatches. Usercopy and range operations
are simulated; no kernel ioctl, Rust in-kernel test or device is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[2];baseline='b1ae0b82acce45f4dd5c1d76afb08bcd060c2672'
rustc=root.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
def function(t,name):
    start=t.index(name);end=t.index('{',start)+1;depth=1
    while depth:
        depth+=(t[end]=='{')-(t[end]=='}');end+=1
    return t[start:end]+'\n'
excerpts=[]
for prefix in ['', 'old_']:
    for path,name in [('drivers/staging/android/ashmem.rs','fn ioctl('),
                      ('drivers/staging/android/ashmem_toggle.rs','fn read_iter('),
                      ('drivers/staging/android/ashmem_toggle.rs','fn write_iter(')]:
        t=(root/path).read_text() if not prefix else subprocess.check_output(['git','show',baseline+':'+path],cwd=root,text=True)
        f=function(t,name).replace(name,'fn '+prefix+name[3:],1).replace('Self::Ptr','()')
        excerpts.append(f)
simple=function((root/'rust/kernel/iov.rs').read_text(),'pub fn simple_read_from_buffer(')
shim=r'''
#![allow(dead_code,non_camel_case_types,non_snake_case,unused_mut)]
use std::{pin::Pin,marker::PhantomData,cell::Cell,sync::atomic::{AtomicBool,Ordering}};
type Result<T> = std::result::Result<T,i32>;
const EINVAL:i32=22;const EFAULT:i32=14;const ENOTTY:i32=25;const EPERM:i32=1;
static ADMIN:AtomicBool=AtomicBool::new(false);
static TOGGLE:AtomicBool=AtomicBool::new(false);
fn has_cap_sys_admin()->bool {ADMIN.load(Ordering::Relaxed)}
#[repr(transparent)] struct CStr([u8]);
impl CStr {
 fn from_bytes_with_nul(data:&[u8])->Result<&Self> {
  if data.last()!=Some(&0) || data[..data.len()-1].contains(&0) {return Err(EINVAL)}
  Ok(unsafe {&*(data as *const [u8] as *const Self)})
 }
}
fn kstrtobool(data:&CStr)->Result<bool> {
 match &data.0 {b"1\0"=>Ok(true),b"0\0"=>Ok(false),_=>Err(EINVAL)}
}
fn _IOC_SIZE(cmd:u32)->usize {((cmd>>16)&0x3fff) as usize}
struct UserPtr(usize);
impl UserPtr { fn from_addr(a:usize)->Self {Self(a)} }
struct UserSlice {ptr:UserPtr,len:usize}
impl UserSlice {
 fn new(ptr:UserPtr,len:usize)->Self {Self{ptr,len}}
 fn reader(self)->Self {self}
 fn writer(self)->Self {self}
}
struct File;
struct Ashmem { calls:Cell<usize> }
impl Ashmem {
 fn set_name(&self,_s:UserSlice)->Result<isize>{Ok(0)}
 fn get_name(&self,_s:UserSlice)->Result<isize>{Ok(0)}
 fn set_size(&self,_s:usize)->Result<isize>{Ok(0)}
 fn get_size(&self)->Result<isize>{Ok(0)}
 fn set_prot_mask(&self,_s:usize)->Result<isize>{Ok(0)}
 fn get_prot_mask(&self)->Result<isize>{Ok(0)}
 fn get_file_id(&self,_s:UserSlice)->Result<isize>{Ok(0)}
 fn purge_all_caches(&self)->Result<isize>{Ok(0)}
 fn pin_unpin(&self,cmd:u32,s:UserSlice)->Result<isize>{
   if s.len<core::mem::size_of::<bindings::ashmem_pin>() || s.ptr.0==0 {return Err(EFAULT)}
   assert_eq!(s.len,8);self.calls.set(self.calls.get()+1);
   Ok(if cmd==bindings::ASHMEM_GET_PIN_STATUS {1}else{0})
 }
}
struct Kiocb<'a,T> {pos:&'a mut i64,_p:PhantomData<T>}
impl<T> Kiocb<'_,T> {
 fn ki_pos(&self)->i64{*self.pos}
 fn ki_pos_mut(&mut self)->&mut i64{self.pos}
}
struct IovIterDest<'a>{buf:&'a mut Vec<u8>,capacity:usize}
impl IovIterDest<'_> {
 fn copy_to_iter(&mut self,data:&[u8])->usize {
  let n=self.capacity.min(data.len());self.buf.extend_from_slice(&data[..n]);self.capacity-=n;n
 }
SIMPLE_READ
}
struct T;
impl T {
 fn get()->bool {true}
 fn set(value:bool)->Result<()> {TOGGLE.store(value,Ordering::Relaxed);Ok(())}
}
struct IovIterSource<'a>{buf:&'a [u8],copied:usize}
impl IovIterSource<'_> {
 fn copy_from_iter(&mut self,out:&mut [u8])->usize {
  let n=out.len().min(self.buf.len());out[..n].copy_from_slice(&self.buf[..n]);self.copied+=n;n
 }
}
'''.replace('SIMPLE_READ',simple)
checks=r'''
fn main() {
 assert_eq!(core::mem::size_of::<bindings::ashmem_pin>(),8);
 assert_eq!(_IOC_SIZE(ASHMEM_GET_PIN_STATUS),0);
 let me=Ashmem{calls:Cell::new(0)};let file=File;
 for cmd in [ASHMEM_PIN,ASHMEM_UNPIN,ASHMEM_GET_PIN_STATUS] {
  assert_eq!(ioctl(Pin::new(&me),&file,cmd,1),Ok(if cmd==ASHMEM_GET_PIN_STATUS{1}else{0}));
  assert_eq!(ioctl(Pin::new(&me),&file,cmd,0),Err(EFAULT));
 }
 assert_eq!(me.calls.get(),3);
 assert_eq!(old_ioctl(Pin::new(&me),&file,ASHMEM_GET_PIN_STATUS,1),Err(EFAULT));
 assert_eq!(old_ioctl(Pin::new(&me),&file,ASHMEM_PIN,1),Ok(0));
 assert_eq!(ioctl(Pin::new(&me),&file,0xffff,1),Err(ENOTTY));
 for cap in 0..4 {
  let mut pos=0;let mut out=Vec::new();
  let mut io=IovIterDest{buf:&mut out,capacity:cap};
  let n=read_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut io).unwrap();
  assert_eq!(n,cap.min(2));assert_eq!(pos,n as i64);assert_eq!(out.len(),n);
 }
 let mut pos=0;let mut out=Vec::new();
 for expected in [1,1,0] {
  let mut io=IovIterDest{buf:&mut out,capacity:1};
  assert_eq!(read_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut io),Ok(expected));
 }
 assert_eq!(&out,b"1\n");assert_eq!(pos,2);
 pos=-1;let mut io=IovIterDest{buf:&mut out,capacity:2};
 assert_eq!(read_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut io),Err(EINVAL));
 pos=0;out.clear();let mut io=IovIterDest{buf:&mut out,capacity:1};
 assert_eq!(old_read_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut io),Ok(2));
 assert_eq!(out.len(),1);assert_eq!(pos,2);
 let mut input=IovIterSource{buf:b"1",copied:0};pos=0;
 assert_eq!(write_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut input),Err(EPERM));
 assert_eq!(input.copied,0);assert!(!TOGGLE.load(Ordering::Relaxed));
 assert_eq!(old_write_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut input),Ok(1));
 assert!(TOGGLE.load(Ordering::Relaxed));
 ADMIN.store(true,Ordering::Relaxed);input=IovIterSource{buf:b"0",copied:0};
 assert_eq!(write_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut input),Ok(1));
 assert!(!TOGGLE.load(Ordering::Relaxed));
 input=IovIterSource{buf:b"bad",copied:0};
 assert_eq!(write_iter(Kiocb{pos:&mut pos,_p:PhantomData},&mut input),Err(EINVAL));
 println!("Ashmem legacy ioctl sizing, toggle short-read and privilege checks passed; old controls reproduced");
}
'''
names=['ASHMEM_SET_NAME','ASHMEM_GET_NAME','ASHMEM_SET_SIZE','ASHMEM_GET_SIZE',
       'ASHMEM_SET_PROT_MASK','ASHMEM_GET_PROT_MASK','ASHMEM_GET_FILE_ID',
       'ASHMEM_PIN','ASHMEM_UNPIN','ASHMEM_GET_PIN_STATUS','ASHMEM_PURGE_ALL_CACHES']
with tempfile.TemporaryDirectory(prefix='ashmem-io-check-') as tmp:
    tmp=Path(tmp);c=tmp/'constants.c';exe=tmp/'constants'
    c.write_text('#include <stddef.h>\n#include <stdio.h>\n#include "drivers/staging/android/uapi/ashmem.h"\nint main(void){\n'+''.join('printf("'+n+' %u\\n", '+n+');\n' for n in names)+'printf("payload %zu\\n",sizeof(struct ashmem_pin));\n}\n')
    subprocess.run(['cc','-I',str(root),str(c),'-o',str(exe)],check=True)
    constants=dict(line.split() for line in subprocess.check_output([str(exe)],text=True).splitlines())
    assert constants.pop('payload')=='8'
    bindings='mod bindings {\n#[repr(C)] pub struct ashmem_pin {pub offset:u32,pub len:u32}\n'+''.join(f'pub const {n}:u32={v};\n' for n,v in constants.items())+'}\nuse bindings::{ASHMEM_PIN,ASHMEM_UNPIN,ASHMEM_GET_PIN_STATUS};\n'
    src=tmp/'check.rs';binary=tmp/'check';src.write_text(shim+bindings+''.join(excerpts)+checks)
    flags=['--edition=2021','-C','overflow-checks=yes']
    subprocess.run([str(rustc),*flags,str(src),'-o',str(binary)],check=True)
    r=subprocess.run([str(binary)],text=True,capture_output=True,timeout=15)
    if r.returncode:raise SystemExit(r.stderr or r.stdout)
record={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'negative_control_commit':baseline,'excerpts_sha256':hashlib.sha256((''.join(excerpts)+simple).encode()).hexdigest(),
        'rustc':str(rustc),'rustc_version':subprocess.check_output([str(rustc),'--version'],text=True).strip(),
        'compiler_flags':flags,'uapi_constants':constants,'result':r.stdout.strip(),'scope':__doc__.strip()}
a.output.write_text(json.dumps(record,indent=2)+'\n');print(record['result'])
