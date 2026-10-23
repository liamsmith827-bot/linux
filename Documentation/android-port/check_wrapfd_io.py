#!/usr/bin/env python3
"""Exercise extracted WrapFD buffer geometry, request splitting and completion bounds."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;ROOT=D.parents[1];ACK='23112ce1886ea26b19be03207c0227a06a6ca009';PATH='drivers/android/wrapfd/io_context.rs'
def block(s,marker):
 start=s.index(marker);op=s.index('{',start);end=op+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
prefix=r'''
#![allow(dead_code,unused_variables,unused_imports,private_interfaces,non_camel_case_types)]
use std::{ops::{Deref,DerefMut},ptr::NonNull,pin::Pin,sync::Arc,marker::PhantomData,cell::{RefCell,UnsafeCell}};
extern crate self as kernel;
mod ffi{pub use std::ffi::c_void;pub type c_long=isize;}
#[derive(Clone,Copy,Debug,PartialEq)]struct Error(i32);impl Error{fn to_errno(self)->i32{self.0}}
const EINVAL:Error=Error(-22);type Result<T=(),E=Error>=std::result::Result<T,E>;type Flags=u32;const GFP_KERNEL:Flags=0;
const PAGE_SIZE:usize=4096;const PAGE_MASK:usize=!(PAGE_SIZE-1);const MAX_NR_KVECS:usize=4;
fn page_align(x:usize)->usize{(x+PAGE_SIZE-1)&PAGE_MASK}fn page_align_down(x:usize)->usize{x&PAGE_MASK}fn offset_in_page(x:usize)->usize{x&!PAGE_MASK}fn is_page_aligned(x:usize)->bool{offset_in_page(x)==0}
macro_rules! pr_warn{($($a:tt)*)=>{{}}}
#[macro_export]macro_rules! container_of{($p:expr,$t:ty,$f:ident)=>{unsafe{($p as *const u8).sub(std::mem::offset_of!($t,$f)).cast::<$t>()}}}
struct KVec<T>(Vec<T>);impl<T>KVec<T>{fn new()->Self{Self(Vec::new())}fn push(&mut self,t:T,_f:Flags)->Result{self.0.push(t);Ok(())}}
impl<T>Deref for KVec<T>{type Target=Vec<T>;fn deref(&self)->&Vec<T>{&self.0}}impl<T>DerefMut for KVec<T>{fn deref_mut(&mut self)->&mut Vec<T>{&mut self.0}}
type InitializedPage=Box<[u8;PAGE_SIZE]>;fn get_free_page()->Result<InitializedPage>{Ok(Box::new([0;PAGE_SIZE]))}
struct KBox<T>(Box<T>);impl<T>KBox<T>{fn pin_init(t:T,_f:Flags)->Result<Pin<Self>>{Ok(unsafe{Pin::new_unchecked(Self(Box::new(t)))})}}
impl<T>Deref for KBox<T>{type Target=T;fn deref(&self)->&T{&self.0}}impl<T>DerefMut for KBox<T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
mod bindings{
 #[derive(Clone,Copy,Default)]pub struct kvec{pub iov_base:*mut super::ffi::c_void,pub iov_len:usize}
 pub struct kiocb{pub dummy:usize}pub struct completion{pub count:usize}
 pub unsafe fn memmove(d:*mut super::ffi::c_void,s:*const super::ffi::c_void,n:usize){unsafe{std::ptr::copy(s.cast::<u8>(),d.cast::<u8>(),n)}}
 pub unsafe fn complete(p:*mut completion){unsafe{(*p).count+=1;}}
}
#[repr(transparent)]struct Opaque<T>(UnsafeCell<T>);impl<T>Opaque<T>{fn get(&self)->*mut T{self.0.get()}}
struct Lock<T>(RefCell<T>);impl<T>Lock<T>{fn lock_irq<R>(&self,f:impl FnOnce(std::cell::RefMut<'_,T>)->R)->R{f(self.0.borrow_mut())}}
struct IoResults{io_ret:isize,bytes_read:usize,nr_reqs:usize}
struct SharedContext{inner:Lock<IoResults>,io_done:Opaque<bindings::completion>}
impl SharedContext{fn new(n:usize)->Self{Self{inner:Lock(RefCell::new(IoResults{io_ret:0,bytes_read:0,nr_reqs:n})),io_done:Opaque(UnsafeCell::new(bindings::completion{count:0}))}}}
struct LocalFile;
struct DataSegment{offs:usize,len:usize}impl DataSegment{fn new(offs:usize,len:usize)->Self{Self{offs,len}}}
enum State{Idle,ReadDone(usize)}
struct IoContext{bounce_bufs:KVec<InitializedPage>,dst_buf:NonNull<ffi::c_void>,start_bounce_len:usize,end_bounce_len:usize,buf_offs:usize,file_seg:DataSegment,dio_buf_seg:DataSegment,state:State}
struct IoRequest{shared_context:Arc<SharedContext>,kiocb:Opaque<bindings::kiocb>,iov:[bindings::kvec;4],file_seg:DataSegment,min_read:usize,nr_segs:usize}
struct DmaBufVmap{ptr:NonNull<ffi::c_void>,size:usize}impl DmaBufVmap{fn vaddr(&self)->Option<NonNull<ffi::c_void>>{Some(self.ptr)}}
struct CpuAccess<'a,const R:bool,const W:bool>{map:&'a DmaBufVmap}impl<const R:bool>CpuAccess<'_,R,true>{fn memcpy_to(&mut self,off:usize,src:&[u8]){assert!(off+src.len()<=self.map.size);unsafe{std::ptr::copy_nonoverlapping(src.as_ptr(),self.map.ptr.as_ptr().cast::<u8>().add(off),src.len());}}}
'''
suffix=r'''
fn pattern(p:usize)->u8{(p%251+1)as u8}
fn main(){std::panic::set_hook(Box::new(|_|{}));let mut checks=0usize;let mut failures=0usize;let mut panics=0usize;
 let mut run=|f:&mut dyn FnMut()|{checks+=1;if std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err(){failures+=1;panics+=1;}};
 for max in [0,1,2,32,4096,usize::MAX]{for min in [0,1,4095,4096,1<<20,(1usize<<31)-1,usize::MAX]{for len in [4096,8192,1<<20,1usize<<32,(i64::MAX as usize)&PAGE_MASK]{run(&mut ||{let n=request_len(len,max,min);assert!(n>=4096&&n<=((i32::MAX as usize)&PAGE_MASK)&&n%4096==0);});}}}
 for fo in [0,1,4095,4096,i64::MAX as usize,usize::MAX]{for bo in [0,1,4096,usize::MAX]{run(&mut ||{let out=unsafe{IoContext::new(fo,NonNull::dangling(),bo,0)};assert!(out.is_err());});}}
 for (fo,bo,len) in [(usize::MAX,0,1),(i64::MAX as usize-1,0,1),(0,usize::MAX,1),(0,isize::MAX as usize,1)]{run(&mut ||{assert!(unsafe{IoContext::new(fo,NonNull::dangling(),bo,len)}.is_err());});}
 for fo in [0,1,7,511,4094,4095,4096,4097,8191]{for bo in [0,1,7,511,4094,4095,4096,4097,8191]{for len in [1,7,511,4095,4096,4097,8191,8192,8193,16389,65537]{for split in [4096,8192,16384,1<<20]{run(&mut ||{
  // Extra host allocation room permits a negative-control pointer calculation
  // to be inspected before rejecting its out-of-range logical segment.
  let logical=bo+len;let mut dst=vec![0xdd;logical+8*PAGE_SIZE];let base=NonNull::new(dst.as_mut_ptr().cast::<ffi::c_void>()).unwrap();
  let mut io=unsafe{IoContext::new(fo,base,bo,len)}.unwrap();assert!(io.bounce_bufs.len()<=3);
  let start=fo&!4095;let end=(fo+len+4095)&!4095;let mut cur=start;let mut total=0;let shared=Arc::new(SharedContext::new(1));
  while cur<end{let n=split.min(end-cur);let req=io.init_io_request(shared.clone(),&LocalFile,cur,n).unwrap();assert!(req.nr_segs<=4);let mut pos=cur;
   for seg in &req.iov[..req.nr_segs]{let ptr=seg.iov_base.cast::<u8>();let a=ptr as usize;let b=a.checked_add(seg.iov_len).unwrap();
    let direct=a>=base.as_ptr() as usize&&b<=base.as_ptr() as usize+logical;
    let bounce=io.bounce_bufs.iter().any(|p|a>=p.as_ptr() as usize&&b<=p.as_ptr() as usize+PAGE_SIZE);
    assert!(seg.iov_len>0&&(direct||bounce));if direct{assert!(a>=base.as_ptr()as usize+bo);}
    for i in 0..seg.iov_len{unsafe{ptr.add(i).write(pattern(pos+i));}}pos+=seg.iov_len;
   }assert_eq!(pos,cur+n);total+=n;cur+=n;
  }
  io.state=State::ReadDone(total);let map=DmaBufVmap{ptr:base,size:logical};io.complete(&map,CpuAccess::<true,true>{map:&map}).unwrap();
  for i in 0..dst.len(){assert_eq!(dst[i],if (bo..logical).contains(&i){pattern(fo+i-bo)}else{0xdd});}
 });}}}}
 // The final request may stop at the requested end, but an earlier short
 // request must never be offset by a later request's alignment padding.
 for first_ret in [0,1,2048,4095,4096,4097,-5]{for last_ret in [0,1,4095,4096,4097,-5]{for reverse in [false,true]{run(&mut ||{
  let shared=Arc::new(SharedContext::new(2));let mut a=IoRequest{shared_context:shared.clone(),kiocb:Opaque(UnsafeCell::new(bindings::kiocb{dummy:0})),iov:[bindings::kvec::default();4],file_seg:DataSegment::new(0,4096),min_read:4096,nr_segs:0};
  let mut b=IoRequest{shared_context:shared.clone(),kiocb:Opaque(UnsafeCell::new(bindings::kiocb{dummy:0})),iov:[bindings::kvec::default();4],file_seg:DataSegment::new(4096,4096),min_read:1,nr_segs:0};
  let order=if reverse{[(&mut b,last_ret),(&mut a,first_ret)]}else{[(&mut a,first_ret),(&mut b,last_ret)]};
  for (req,ret) in order{unsafe{IoRequest::async_io_complete(req.kiocb.get(),ret);}}
  let r=shared.inner.0.borrow();let expect=first_ret==4096&&(1..=4096).contains(&last_ret);assert_eq!(r.io_ret==0,expect);assert_eq!(r.nr_reqs,0);assert_eq!(unsafe{(*shared.io_done.get()).count},1);
 });}}}
 println!("{checks} cases, {failures} failed cases (including {panics} caught assertions/panics)");if failures!=0{std::process::exit(1);}
}
'''
def extract(s,current):
 helper=block(s,'fn dio_aligned_len(')
 if current:helper+='\n'+block(s,'fn request_len(')
 else:
  frag=s[s.index('        const MAX_RW_COUNT:'):s.index('        let nr_reqs = remaining_len.div_ceil')]
  frag=frag.replace('*module_parameters::max_nr_load_reqs.value()','max_nr_reqs').replace('*module_parameters::min_bytes_per_req.value()','min_bytes')
  helper+='\nfn request_len(remaining_len:usize,max_nr_reqs:usize,min_bytes:usize)->usize{\n'+frag+'\nlen_per_req\n}\n'
 newarg='min_read:usize,' if current else ''
 ctor='impl IoRequest{fn new(shared_context:Arc<SharedContext>,_file:&LocalFile,offs:usize,len:usize,'+newarg+'nr_segs:usize,iov:[bindings::kvec;4])->Self{Self{shared_context,kiocb:Opaque(UnsafeCell::new(bindings::kiocb{dummy:0})),iov,file_seg:DataSegment::new(offs,len),min_read:'+('min_read' if current else '0')+',nr_segs}}\n'+block(s,'    unsafe extern "C" fn async_io_complete(')+'\n}\n'
 body='impl IoContext{\n'+'\n'.join(block(s,m) for m in ['    pub(crate) unsafe fn new(','    fn init_io_request(','    pub(crate) fn complete<'])+'\n}\n'
 return helper+ctor+body
rustc=ROOT.parent/'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc';results={}
with tempfile.TemporaryDirectory(prefix='wrapfd-io-') as td:
 td=Path(td)
 for name in ['current','original_ACK']:
  s=(ROOT/PATH).read_text() if name=='current' else subprocess.check_output(['git','show',ACK+':'+PATH],cwd=ROOT,text=True);body=extract(s,name=='current');src=td/(name+'.rs');exe=td/name;src.write_text(prefix+body+suffix)
  c=subprocess.run([str(rustc),'--edition=2021','-C','overflow-checks=yes','-O',str(src),'-o',str(exe)],capture_output=True,text=True)
  if c.returncode:Path('/tmp/wrapfd-io-failed.rs').write_text(src.read_text())
  assert c.returncode==0,c.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=120);results[name]={'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'extracted_sha256':hashlib.sha256(body.encode()).hexdigest()};assert (r.returncode==0)==(name=='current'),results[name]
report=dict(scope=__doc__,results=results,negative_control_source=ACK,limitations='Actual new/init_io_request/complete/async_io_complete bodies and splitting arithmetic run with host page allocation, DMA map, file, lock and completion shims. Geometry cases simulate full reads and compare every destination byte plus surrounding sentinels. Completion cases model short/error returns in both orders. No real DMA, VFS direct I/O, asynchronous callback race, zero-length ioctl syscall or mmap executed.')
(D/'evidence/wrapfd-io-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:{'returncode':v['returncode'],'stdout':v['stdout']} for k,v in results.items()},indent=2))
