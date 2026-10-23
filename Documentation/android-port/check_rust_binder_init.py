#!/usr/bin/env python3
"""Exercise extracted Binder init/shrinker paths with allocation and registration shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
paths = ['drivers/android/binder/' + p for p in
         ['rust_binder_main.rs', 'page_range.rs', 'transaction.rs']]

def block(s, marker):
    start = s.index(marker)
    opening = s.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (s[end] == '{') - (s[end] == '}')
        end += 1
    return s[start:end]

prefix = r'''
#![allow(dead_code,non_camel_case_types,static_mut_refs,private_interfaces,unused_variables)]
extern crate self as kernel;
use std::{cell::{Cell,UnsafeCell},ffi::CStr,ptr};
type Result<T=()> = std::result::Result<T, Error>;
#[derive(Clone,Copy,PartialEq,Debug)]pub struct Error(i32);
impl Error{fn from_errno(e:i32)->Self{Self(if e==0{-22}else{e})}}
const ENOMEM:Error=Error(-12);const EPERM:Error=Error(-1);const GFP_KERNEL:u32=0;
#[derive(Default)]struct State{mode:u32,alloc_calls:usize,live_logs:usize,net:usize,lru:usize,shrinker:usize,fs:usize,refs:usize,trace_removed:usize,published:usize}
thread_local!{static S:std::cell::RefCell<State>=Default::default();}
fn state<T>(f:impl FnOnce(&mut State)->T)->T{S.with(|s|f(&mut s.borrow_mut()))}
fn mode()->u32{state(|s|s.mode)}
macro_rules! pr_warn{($($t:tt)*)=>{{}}}macro_rules! pr_err{($($t:tt)*)=>{{}}}
#[macro_export]macro_rules! c_str{($s:literal)=>{CStr::from_bytes_with_nul(concat!($s,"\0").as_bytes()).unwrap()}}
#[macro_export]macro_rules! new_spinlock{($e:expr,$s:literal $(,)?)=>{$e}}
macro_rules! pin_init{(TransactionLogSlot { entry <- $e:expr, })=>{TransactionLogSlot{entry:$e}}}
pub mod error{pub type Result<T=()> = crate::Result<T>;pub fn to_result(e:i32)->Result{if e<0{Err(crate::Error(e))}else{Ok(())}}}
pub struct ThisModule;impl ThisModule{fn as_ptr(&self)->*mut u8{ptr::null_mut()}}
pub trait Module:Sized{fn init(m:&'static ThisModule)->Result<Self>;}
mod context{pub struct Contexts;pub static CONTEXTS:Contexts=Contexts;impl Contexts{pub unsafe fn init(&self){}}}
static RUST_BINDER_LAYOUT:u32=0;
struct Opaque<T>(UnsafeCell<T>);impl<T> Opaque<T>{fn get(&self)->*mut T{self.0.get()}}
unsafe impl<T> Sync for Opaque<T>{}
struct Shrinker{inner:Opaque<*mut bindings::shrinker>,list_lru:Opaque<bindings::list_lru>}
static BINDER_SHRINKER:Shrinker=Shrinker{inner:Opaque(UnsafeCell::new(ptr::null_mut())),list_lru:Opaque(UnsafeCell::new(0))};
unsafe extern "C" fn rust_shrink_count(){}unsafe extern "C" fn rust_shrink_scan(){}
mod bindings{
 use super::*;
 pub static mut RUST_BINDER_LAYOUT:u32=0;pub type list_lru=u32;
 pub struct shrinker{pub count_objects:Option<unsafe extern "C" fn()>,pub scan_objects:Option<unsafe extern "C" fn()>,pub private_data:*mut u8}
 pub unsafe fn binder_try_unload_builtin()->i32{match mode(){1=>-1,2=>-22,_=>0}}
 pub unsafe fn binder_remove_trace_events(_m:*mut u8){state(|s|s.trace_removed+=1);}
 pub unsafe fn __list_lru_init(_l:*mut list_lru,_m:bool,_k:*mut u8)->i32{if mode()==6{-12}else{state(|s|s.lru+=1);0}}
 pub unsafe fn list_lru_destroy(_l:*mut list_lru){state(|s|{assert_eq!(s.lru,1);assert_eq!(s.shrinker,0);s.lru-=1;});}
 pub unsafe fn shrinker_alloc(_f:u32,_n:*const i8)->*mut shrinker{if mode()==7{return ptr::null_mut();}Box::into_raw(Box::new(shrinker{count_objects:None,scan_objects:None,private_data:ptr::null_mut()}))}
 pub unsafe fn shrinker_register(_p:*mut shrinker){state(|s|s.shrinker+=1);}
 pub unsafe fn shrinker_free(p:*mut shrinker){state(|s|{assert_eq!(s.shrinker,1);s.shrinker-=1;});drop(unsafe{Box::from_raw(p)});}
 pub unsafe fn __module_get(_m:*mut u8){state(|s|s.refs+=1);}
}
trait CStrExt{fn as_char_ptr(&self)->*const i8;}impl CStrExt for CStr{fn as_char_ptr(&self)->*const i8{self.as_ptr()}}
mod binderfs{pub unsafe fn init_rust_binderfs()->i32{if super::mode()==8{-12}else{super::state(|s|s.fs=1);0}}}
pub mod net{pub mod netlink{
 pub struct Registration;impl Drop for Registration{fn drop(&mut self){crate::state(|s|{assert_eq!(s.net,1);s.net-=1;});}}
}}
mod netlink{pub struct Family;pub static BINDER_NL_FAMILY:Family=Family;impl Family{
 pub fn register(&self)->super::Result<super::net::netlink::Registration>{if super::mode()==5{return Err(super::ENOMEM);}super::state(|s|s.net+=1);Ok(super::net::netlink::Registration)}
}}
struct BinderModule{_netlink:Option<net::netlink::Registration>}
const LOG_SIZE:usize=32;struct TransactionLogEntry;impl TransactionLogEntry{fn empty()->Self{Self}}
struct TransactionLogSlot{entry:TransactionLogEntry}
mod pin_init{pub fn pin_init_array_from_fn<T,F:FnMut(usize)->T>(f:F)->[T;32]{std::array::from_fn(f)}}
struct KBox;struct OwnedEntries([TransactionLogSlot;32]);
impl Drop for OwnedEntries{fn drop(&mut self){state(|s|s.live_logs-=1);}}
impl KBox{fn pin_init(e:[TransactionLogSlot;32],_f:u32)->Result<OwnedEntries>{let n=state(|s|{s.alloc_calls+=1;s.alloc_calls});if mode()==2+n as u32{return Err(ENOMEM);}state(|s|s.live_logs+=1);Ok(OwnedEntries(e))}}
struct Entries;impl Entries{fn populate(&self,e:OwnedEntries){state(|s|s.published+=1);std::mem::forget(e);}}
mod transaction{use super::*;pub struct TransactionLog{entries:Entries}pub static TRANSACTION_LOG:TransactionLog=TransactionLog{entries:Entries};pub static FAILED_TRANSACTION_LOG:TransactionLog=TransactionLog{entries:Entries};
'''
suffix = r'''
fn main(){let mut failures=0;let mut checks=0;let mut check=|x:bool|{checks+=1;if !x{failures+=1;}};
 for m in 0..=8{state(|s|*s=State{mode:m,..Default::default()});let result=BinderModule::init(&ThisModule);
  if m==0{check(result.is_ok());state(|s|{check(s.refs==1);check(s.fs==1);check(s.shrinker==1);check(s.lru==1);check(s.net==1);check(s.published==2);check(s.live_logs==2);});std::mem::forget(result);}
  else if m<=2{check(result.is_ok());drop(result);state(|s|{check(s.refs==0);check(s.fs==0);check(s.shrinker==0);check(s.lru==0);check(s.net==0);check(s.live_logs==0);check(s.trace_removed==1);});}
  else{check(result.is_err());if m==7{check(matches!(&result,Err(e) if *e==ENOMEM));}drop(result);state(|s|{check(s.refs==0);check(s.fs==0);check(s.shrinker==0);check(s.lru==0);check(s.net==0);check(s.live_logs==0);check(s.published==0);});}
 }
 println!("9 cases, {checks} assertions, {failures} failures");if failures!=0{std::process::exit(1);}
}
'''

def extract(sources):
    main, shrinker, trans = sources
    prep = '    pub(crate) fn prepare(' if '    pub(crate) fn prepare(' in trans else '    pub(crate) fn init('
    body = 'impl TransactionLog {\n' + block(trans, prep) + '\n}}\n'
    body += 'impl Shrinker {\n' + block(shrinker, '    pub(crate) fn register(') + '\n'
    if '    pub(crate) unsafe fn unregister_unused(' in shrinker:
        body += block(shrinker, '    pub(crate) unsafe fn unregister_unused(') + '\n'
    body += '}\n' + block(main, 'impl kernel::Module for BinderModule {')
    return body

rustc = ROOT.parent / 'kernel_manifest-6.18/prebuilts/rust-toolchain/linux-x86/1.91.1.p3/bin/rustc'
results = {}
with tempfile.TemporaryDirectory(prefix='rust-binder-init-') as td:
    td = Path(td)
    for name in ['current', 'original_ACK']:
        sources = [(ROOT / p).read_text() if name == 'current' else
                   subprocess.check_output(['git', 'show', ACK + ':' + p], cwd=ROOT, text=True) for p in paths]
        body = extract(sources)
        src, exe = td / (name + '.rs'), td / name
        src.write_text(prefix + body + suffix)
        c = subprocess.run([str(rustc), '--edition=2021', '--cfg', 'CONFIG_ANDROID_BINDER_IPC', str(src), '-o', str(exe)], capture_output=True, text=True)
        assert c.returncode == 0, c.stderr
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        results[name] = {'returncode': r.returncode, 'stdout': r.stdout.strip(), 'stderr': r.stderr,
                         'extracted_sha256': hashlib.sha256(body.encode()).hexdigest(),
                         'source_sha256': {p: hashlib.sha256(s.encode()).hexdigest() for p, s in zip(paths, sources)}}
        assert (r.returncode == 0) == (name == 'current'), results[name]
report = {'scope': __doc__, 'results': results, 'negative_control_source': ACK,
          'limitations': 'Native module loader, filesystem publication, concurrent shrinker callbacks, locks, allocations, and netlink registration are shims. No actual module load, unload, allocation-failure injection or Binder transactions executed.'}
(D / 'evidence/rust-binder-init-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({n: {k: v for k, v in r.items() if k in ['returncode', 'stdout']} for n, r in results.items()}, indent=2))
