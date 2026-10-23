#!/usr/bin/env python3
"""Check extracted parameter parsing, container access and bounded formatting with host shims."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
paths = ['rust/kernel/module_param.rs', 'rust/kernel/str/parse_int.rs',
         'rust/kernel/str.rs', 'rust/kernel/sync/set_once.rs']

def block(s, marker):
    start = s.index(marker)
    opening = s.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (s[end] == '{') - (s[end] == '}')
        end += 1
    return s[start:end]

prefix = r'''
#![allow(dead_code,unused_imports,non_camel_case_types,private_interfaces)]
extern crate self as kernel;
use std::{cell::UnsafeCell,mem::MaybeUninit,marker::PhantomData,ffi::{c_int,c_void},fmt::{self,Write},ops::Deref};
use std::sync::atomic::Ordering::{Acquire,Relaxed,Release};
type c_char=u8;
type Result<T=()> = std::result::Result<T, Error>;
#[derive(Copy,Clone,Debug,PartialEq)]pub struct Error(i32);impl Error{fn to_errno(self)->i32{self.0}}
const EINVAL:Error=Error(-22);const PAGE_SIZE:usize=4096;
pub mod error{pub mod code{pub const EEXIST:crate::Error=crate::Error(-17);}pub fn from_result(f:impl FnOnce()->crate::Result<i32>)->i32{f().unwrap_or_else(|e|e.0)}}
#[macro_export]macro_rules! pr_warn{($($t:tt)*)=>{{}}}
struct Atomic<T>{inner:std::sync::atomic::AtomicU32,_t:PhantomData<T>}
impl Atomic<u32>{const fn new(v:u32)->Self{Self{inner:std::sync::atomic::AtomicU32::new(v),_t:PhantomData}}fn load(&self,o:std::sync::atomic::Ordering)->u32{self.inner.load(o)}fn store(&self,v:u32,o:std::sync::atomic::Ordering){self.inner.store(v,o)}fn cmpxchg(&self,a:u32,b:u32,o:std::sync::atomic::Ordering)->std::result::Result<u32,u32>{self.inner.compare_exchange(a,b,o,o)}fn get_mut(&mut self)->&mut u32{self.inner.get_mut()}}
#[repr(transparent)]pub struct BStr([u8]);impl Deref for BStr{type Target=[u8];fn deref(&self)->&[u8]{&self.0}}
impl AsRef<BStr> for [u8]{fn as_ref(&self)->&BStr{unsafe{&*(self as *const [u8] as *const BStr)}}}
#[repr(transparent)]struct CStr([u8]);impl CStr{unsafe fn from_char_ptr<'a>(p:*const c_char)->&'a Self{let b=unsafe{std::ffi::CStr::from_ptr(p.cast())}.to_bytes_with_nul();unsafe{&*(b as *const [u8] as *const CStr)}}}impl Deref for CStr{type Target=BStr;fn deref(&self)->&BStr{self.0[..self.0.len()-1].as_ref()}}
pub mod prelude{pub(crate) use crate::{Result,EINVAL};}
pub mod str{pub use crate::BStr;pub mod parse_int{
'''

def extract(sources):
    param, parse, formatter, once = sources
    # Copy the actual parser without inner documentation (its module is already open).
    body = '\n'.join(l for l in parse.splitlines() if not l.startswith('//!')) + '\n}}\n'
    for marker in ['pub struct SetOnce<T>', 'impl<T> SetOnce<T>', 'impl<T> Drop for SetOnce<T>',
                   'pub struct RawFormatter', 'impl RawFormatter', 'impl fmt::Write for RawFormatter']:
        body += block(once if 'SetOnce' in marker else formatter, marker) + '\n'
    body += "pub struct Formatter<'a>(RawFormatter, PhantomData<&'a mut ()>);\n"
    for marker in ["impl Formatter<'_>", "impl Deref for Formatter<'_>", "impl fmt::Write for Formatter<'_>"]:
        body += block(formatter, marker) + '\n'
    body += 'mod bindings {pub struct kernel_param{pub __bindgen_anon_1:Arg}pub struct Arg{pub arg:*mut core::ffi::c_void}}\n'
    for marker in ['pub trait ModuleParam:', 'unsafe extern "C" fn set_param<T>',
                   'macro_rules! impl_int_module_param', 'unsafe extern "C" fn get_param<T>',
                   'pub struct ModuleParamAccess<T>', 'impl<T> ModuleParamAccess<T>']:
        body += block(param, marker) + '\n'
    body += '\n'.join('impl_int_module_param!(' + ty + ');' for ty in ['i8','u8','i16','u16','i32','u32','i64','u64','isize','usize'])
    return body

suffix = r'''
use crate::str::parse_int::ParseInt;
struct Long;impl fmt::Display for Long{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{for _ in 0..6000{f.write_str("x")?;}Ok(())}}
fn main(){let mut checks=0;let mut failures=0;let mut nonzero_offsets=0;let mut check=|v:bool|{checks+=1;if !v{failures+=1;}};
 macro_rules! case{($ty:ty)=>{{
  for value in [0i128,1,7,8,15,16,127,128,255,256,32767,32768,65535,65536,2147483647,2147483648,4294967295,4294967296,9223372036854775807,9223372036854775808,18446744073709551615]{
   for sign in ["","+","-"]{for radix in [2,8,10,16]{for newline in ["","\n"]{
    let digits=match radix{2=>format!("0b{value:b}"),8=>format!("0{value:o}"),16=>format!("0x{value:x}"),_=>value.to_string()};
    let input=format!("{sign}{digits}{newline}");let expected=if sign=="-"{-value}else{value};
    let good=expected>=<$ty>::MIN as i128 && expected<=<$ty>::MAX as i128;
    let result=<$ty as ParseInt>::from_str(input.as_bytes().as_ref());
    check(result.map(|v|v as i128)==if good{Ok(expected)}else{Err(EINVAL)});
   }}}}
  for bad in ["","+","-","++1","+-1","-+1","--1","0x+1","0x-1","0b+1","0o-1"," 1","1 ","1\n\n","0x","0b2","08","0x10000000000000000","1\0","\n"]{check(<$ty as ParseInt>::from_str(bad.as_bytes().as_ref()).is_err());}
  for default in [0 as $ty,<$ty>::MAX,<$ty>::MIN]{
   let container=ModuleParamAccess::new(default);let old=container.value();let arg=container.as_void_ptr();let p=bindings::kernel_param{__bindgen_anon_1:bindings::Arg{arg}};
   let offset=(&container.value as *const _ as usize)-(arg as usize);if offset!=0{nonzero_offsets+=1;}
   // Do not execute the original invalid cast under a layout where it is wrong.
   // Record it as a failed precondition instead of invoking undefined behavior.
   if ORIGINAL && offset!=0{check(false);continue;}
   check(unsafe{set_param::<$ty>(std::ptr::null(),&p)}==-22);
   let malformed=c"bad";check(unsafe{set_param::<$ty>(malformed.as_ptr().cast(),&p)}==-22);check(*container.value()==default);
   let input=c"7";check(unsafe{set_param::<$ty>(input.as_ptr().cast(),&p)}==0);check(*container.value()==7 as $ty);check(*old==default);
   let second=c"8";check(unsafe{set_param::<$ty>(second.as_ptr().cast(),&p)}==-17);check(*container.value()==7 as $ty);
   let mut buf=vec![0xabu8;PAGE_SIZE+16];let n=unsafe{get_param::<$ty>(buf.as_mut_ptr().cast(),&p)};check(n==2);check(&buf[..3]==b"7\n\0");check(buf[PAGE_SIZE..].iter().all(|b|*b==0xab));
   check(unsafe{get_param::<$ty>(std::ptr::null_mut(),&p)}==-22);
  }
 }}}
 case!(i8);case!(u8);case!(i16);case!(u16);case!(i32);case!(u32);case!(i64);case!(u64);case!(isize);case!(usize);
 // Extra allocated guard space makes the ACK overflow control observable without
 // writing beyond the real host allocation. Native sysfs guarantees one page only.
 let c=ModuleParamAccess::new(Long);let p=bindings::kernel_param{__bindgen_anon_1:bindings::Arg{arg:c.as_void_ptr()}};let mut buf=vec![0xabu8;2*PAGE_SIZE];
 let n=unsafe{get_param::<Long>(buf.as_mut_ptr().cast(),&p)};check(n==-22);check(buf[PAGE_SIZE..].iter().all(|b|*b==0xab));
 println!("{checks} assertions, {failures} failures, {nonzero_offsets} nonzero field offsets");if failures!=0{std::process::exit(1);}
}
'''
rustc = ROOT.parent / 'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results = {}
with tempfile.TemporaryDirectory(prefix='rust-module-params-') as td:
    td = Path(td)
    for name in ['current', 'original_ACK']:
        sources = [(ROOT / p).read_text() if name == 'current' else
                   subprocess.check_output(['git', 'show', ACK + ':' + p], cwd=ROOT, text=True) for p in paths]
        body = extract(sources)
        src = td / (name + '.rs')
        src.write_text(prefix + body + '\nconst ORIGINAL:bool=' + ('true' if name=='original_ACK' else 'false') + ';\n' + suffix)
        results[name] = {'extracted_sha256': hashlib.sha256(body.encode()).hexdigest(),
                         'source_sha256': {p:hashlib.sha256(s.encode()).hexdigest() for p,s in zip(paths,sources)}, 'runs': []}
        for seed in [None, 1, 7, 19]:
            exe = td / (name + str(seed))
            flags = [] if seed is None else ['-Zrandomize-layout', '-Zlayout-seed='+str(seed)]
            c = subprocess.run([str(rustc), '--edition=2021', *flags, str(src), '-o', str(exe)], capture_output=True, text=True, env=dict(os.environ,RUSTC_BOOTSTRAP='1'))
            assert c.returncode == 0, c.stderr
            r = subprocess.run([str(exe)], capture_output=True, text=True)
            result = {'layout_seed':seed,'returncode':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr}
            results[name]['runs'].append(result)
            assert (r.returncode == 0) == (name == 'current'), result
report = {'scope': __doc__, 'results': results, 'negative_control_source':ACK,
          'limitations':'Native parser ingress, sysfs and kernel atomics are not executed. Rust BStr/CStr and native parameter structs are host shims; copied SetOnce uses host atomic operations. Actual parser, formatter, callbacks and container definitions are extracted. Randomized layout tests skip the ACK invalid pointer cast when its offset is wrong. The long Display case is a generic callback boundary test; generated operations currently support only bounded primitive integers, so no existing large-display sysfs exploit is claimed.'}
(D/'evidence/rust-module-parameter-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({n:r['runs'] for n,r in results.items()},indent=2))
