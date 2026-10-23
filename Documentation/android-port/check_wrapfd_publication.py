#!/usr/bin/env python3
"""Exercise extracted WrapFD publication/unwind, permission rollback and empty-load handling."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;ROOT=D.parents[1];ACK='23112ce1886ea26b19be03207c0227a06a6ca009'
def block(s,marker):
 start=s.index(marker);op=s.index('{',start);end=op+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
prefix=r'''
#![allow(dead_code,unused_variables,private_interfaces,non_camel_case_types,unused_mut)]
use std::{cell::{Cell,RefCell,RefMut,UnsafeCell},pin::Pin,sync::Arc,ops::{Deref,DerefMut}};
#[derive(Clone,Copy,Debug,PartialEq)]struct Error(i32);const EINVAL:Error=Error(-22);const EACCES:Error=Error(-13);const ENOENT:Error=Error(-2);const ENOMEM:Error=Error(-12);const EBUSY:Error=Error(-16);
impl From<std::num::TryFromIntError> for Error{fn from(_:std::num::TryFromIntError)->Self{EINVAL}}
type Result<T=(),E=Error>=std::result::Result<T,E>;type Offset=i64;type ARef<T>=Arc<T>;const GFP_KERNEL:u32=0;
macro_rules! c_str{($s:expr)=>{$s}}
struct Lock<T>(RefCell<T>);impl<T>Lock<T>{fn lock(&self)->RefMut<'_,T>{self.0.borrow_mut()}}
struct KBox<T>(Box<T>);impl<T>KBox<T>{fn pin_init(t:T,_f:u32)->Result<Pin<Self>>{if fail(1){return Err(ENOMEM);}Ok(unsafe{Pin::new_unchecked(Self(Box::new(t)))})}}
impl<T>Deref for KBox<T>{type Target=T;fn deref(&self)->&T{&self.0}}impl<T>DerefMut for KBox<T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
thread_local!{static FAIL:Cell<u8>=const{Cell::new(0)};static RESERVED:Cell<i32>=const{Cell::new(0)};static DROPS:Cell<usize>=const{Cell::new(0)};static INSTALLED:RefCell<Vec<Arc<File>>>=const{RefCell::new(Vec::new())};}
fn fail(n:u8)->bool{FAIL.with(|f|f.get()==n)}
mod bindings{pub const PROT_READ:u32=1;pub const PROT_WRITE:u32=2;pub const O_CLOEXEC:u32=0x80000;pub const O_RDWR:u32=2;pub const O_RDONLY:u32=0;
 pub struct inode{pub size:i64}pub unsafe fn file_inode(f:*mut super::File)->*mut inode{unsafe{(*f).inode.get()}}pub unsafe fn i_size_write(p:*mut inode,n:i64){unsafe{(*p).size=n;}}
}
struct DmaBuf{size:usize,writable:bool}impl DmaBuf{fn size(&self)->usize{self.size}}
struct LocalFile;
struct File{inode:UnsafeCell<bindings::inode>,context:Pin<KBox<Wrap>>}impl File{fn as_ptr(&self)->*mut Self{self as *const Self as *mut Self}}
struct FileDescriptorReservation{live:bool}impl FileDescriptorReservation{
 fn get_unused_fd_flags(_f:u32)->Result<Self>{if fail(2){return Err(ENOMEM);}RESERVED.with(|n|n.set(n.get()+1));Ok(Self{live:true})}
 fn reserved_fd(&self)->u32{12}fn fd_install(mut self,f:Arc<File>){self.live=false;RESERVED.with(|n|n.set(n.get()-1));INSTALLED.with(|v|v.borrow_mut().push(f));}
}impl Drop for FileDescriptorReservation{fn drop(&mut self){if self.live{RESERVED.with(|n|n.set(n.get()-1));}}}
struct DmaBufContent{dmabuf:Arc<DmaBuf>,writable:bool}
struct WrapInfo{content:Option<DmaBufContent>,owner:bool,mapped:bool}impl WrapInfo{fn check_modifiable(&mut self)->Result{if !self.owner{Err(EBUSY)}else if self.mapped{Err(EINVAL)}else{Ok(())}}}
struct Wrap{inner:Arc<Lock<WrapInfo>>,close_on_exec:bool,blocked:Cell<bool>}
impl Wrap{fn new(close_on_exec:bool)->Self{Self{inner:Arc::new(Lock(RefCell::new(WrapInfo{content:None,owner:true,mapped:false}))),close_on_exec,blocked:Cell::new(false)}}fn begin_block_usage(&self)->Option<UseGuard<'_>>{if self.blocked.replace(true){None}else{Some(UseGuard(self))}}}
struct UseGuard<'a>(&'a Wrap);impl Drop for UseGuard<'_>{fn drop(&mut self){self.0.blocked.set(false);}}
impl Drop for Wrap{fn drop(&mut self){let _guard=self.inner.lock();DROPS.with(|n|n.set(n.get()+1));}}
fn create_wrap_file(_n:&str,context:Pin<KBox<Wrap>>,_f:u32)->Result<Arc<File>,(Error,Pin<KBox<Wrap>>)>{if fail(3){Err((ENOMEM,context))}else{Ok(Arc::new(File{inode:UnsafeCell::new(bindings::inode{size:0}),context}))}}
struct WrapFdDevice;impl WrapFdDevice{fn publish_wrap(w:Pin<KBox<Wrap>>,c:DmaBufContent,x:bool)->Result<u32,(Error,DmaBufContent)>{DmaBufContent::create_wrap(w,c,x)}}
mod uapi{#[derive(Clone,Copy)]pub struct wrapfd_rewrap{pub prot:u32,pub pad:u32,pub reserved:u64}}
struct UserSlice(uapi::wrapfd_rewrap);struct Reader(uapi::wrapfd_rewrap);impl UserSlice{fn reader(self)->Reader{Reader(self.0)}}impl Reader{fn read<T:From<uapi::wrapfd_rewrap>>(&mut self)->Result<T>{Ok(self.0.into())}}
impl DmaBufContent{fn is_dmabuf_writable(b:&DmaBuf)->bool{b.writable}}
'''
suffix=r'''
fn main(){std::panic::set_hook(Box::new(|_|{}));let mut cases=0;let mut failures=0;
 let mut run=|f:&mut dyn FnMut()|{cases+=1;FAIL.with(|v|v.set(0));INSTALLED.with(|v|v.borrow_mut().clear());RESERVED.with(|v|v.set(0));if std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err(){failures+=1;}FAIL.with(|v|v.set(0));INSTALLED.with(|v|v.borrow_mut().clear());};
 for site in [0,2,3]{for writable in [false,true]{run(&mut ||{
  let c=DmaBufContent{dmabuf:Arc::new(DmaBuf{size:8192,writable:true}),writable};let ctx=KBox::pin_init(Wrap::new(true),0).unwrap();let inner=ctx.inner.clone();FAIL.with(|v|v.set(site));
  match DmaBufContent::create_wrap(ctx,c,true){Ok(fd)=>{assert_eq!(site,0);assert_eq!(fd,12);INSTALLED.with(|v|{let v=v.borrow();assert_eq!(v.len(),1);assert_eq!(unsafe{(*v[0].inode.get()).size},8192);});},Err((e,c))=>{assert_ne!(site,0);assert_eq!(e,ENOMEM);assert_eq!(c.is_writable(),writable);assert!(inner.lock().content.is_none());}}
  assert_eq!(RESERVED.with(|v|v.get()),0);
 });}}
 for site in 0..=3{for writable in [false,true]{for prot in [0,1,2,3,4]{for backing_write in [false,true]{if writable&&!backing_write{continue;}run(&mut ||{
  let w=Wrap::new(true);w.inner.lock().content=Some(DmaBufContent{dmabuf:Arc::new(DmaBuf{size:4096,writable:backing_write}),writable});FAIL.with(|v|v.set(site));
  let r=w.rewrap(UserSlice(uapi::wrapfd_rewrap{prot,pad:0,reserved:0}));let valid=prot<4&&(prot&2==0||backing_write);
  if valid&&site==0{assert_eq!(r,Ok(12));assert!(w.inner.lock().content.is_none());INSTALLED.with(|v|assert_eq!(v.borrow()[0].context.inner.lock().content.as_ref().unwrap().is_writable(),prot&2!=0));}
  else{assert!(r.is_err());assert_eq!(w.inner.lock().content.as_ref().unwrap().is_writable(),writable);}
  assert!(!w.blocked.get());assert_eq!(RESERVED.with(|v|v.get()),0);
 });}}}}
 for bo in [0,1,4095,4096,4097,-1]{run(&mut ||{let b=DmaBuf{size:4096,writable:true};assert_eq!(DmaBufContent::empty_load(&b,Arc::new(LocalFile),0,bo,0),if (0..=4096).contains(&bo){Ok(0)}else{Err(EINVAL)});});}
 println!("{cases} cases, {failures} failed cases");if failures!=0{std::process::exit(1);}
}
'''
def extract(content,wrap):
 body='impl DmaBufContent{\n'+'\n'.join(block(content,m) for m in ['    pub(crate) fn make_writable(','    pub(crate) fn is_writable(','    pub(crate) fn create_wrap('])+'\n'
 # Exercise the real conversion/bounds/empty-load prefix without invoking a backend.
 load=content[content.index('    pub(crate) fn load('):content.index('        let (map, mut io_context) = Self::load_prepare')]
 body+=load.replace('fn load(','fn empty_load(')+'panic!("empty load reached the I/O backend");\n}\n}\n'
 body+='impl Wrap{'+block(wrap,'    fn rewrap(')+'}\n';return body
rustc=ROOT.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc';results={};paths=['drivers/android/wrapfd/content.rs','drivers/android/wrapfd/wrap.rs']
with tempfile.TemporaryDirectory(prefix='wrapfd-publish-') as td:
 td=Path(td)
 for name in ['current','original_ACK']:
  ss=[(ROOT/p).read_text() if name=='current' else subprocess.check_output(['git','show',ACK+':'+p],cwd=ROOT,text=True) for p in paths];body=extract(*ss);src=td/(name+'.rs');exe=td/name;src.write_text(prefix+body+suffix)
  c=subprocess.run([str(rustc),'--edition=2021','-C','overflow-checks=yes',str(src),'-o',str(exe)],capture_output=True,text=True)
  if c.returncode:Path('/tmp/wrapfd-publish-failed.rs').write_text(src.read_text())
  assert c.returncode==0,c.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True);results[name]={'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr,'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in zip(paths,ss)}};assert (r.returncode==0)==(name=='current'),results[name]
report=dict(scope=__doc__,results=results,negative_control_source=ACK,limitations='Extracted create_wrap/rewrap/protection methods and the empty-load prefix run with allocator, fd reservation, file/inode, DMA-buffer and usercopy shims. RefCell detects destructor relocking as a caught panic instead of hanging on a native mutex. Does not execute native LSM, task/mm reads, VFS mmap, actual fault injection or syscalls.')
(D/'evidence/wrapfd-publication-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:{'returncode':v['returncode'],'stdout':v['stdout']} for k,v in results.items()},indent=2))
