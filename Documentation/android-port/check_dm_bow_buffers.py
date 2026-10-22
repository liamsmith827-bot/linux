#!/usr/bin/env python3
"""Check extracted dm-bow buffer copying/logging and state transitions with storage fault shims."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent;s=(D.parents[1]/'drivers/md/dm-bow.c').read_text()
def f(n):
 m=re.search(r'^static .*\b'+n+r'\([^;{}]*\)\n\{',s,re.M);assert m,n
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
body=f('copy_data')+f('add_log_entry')+f('state_store')
prefix=r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
typedef uint64_t sector_t;typedef uint32_t u32;typedef uint8_t u8;
static unsigned checks,cases,failures;
#define CHECK(x) (++checks,(x)?0:(++failures,0))
#define WARN_ON(x) ((void)(x))
#define DMERR(...) ((void)0)
#define DMINFO(...) ((void)0)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
enum {BLK_STS_OK,BLK_STS_IOERR,BLK_STS_NOSPC,BLK_STS_RESOURCE};
static int errno_to_blk_status(int n){return !n?0:n==-ENOMEM?BLK_STS_RESOURCE:n==-ENOSPC?BLK_STS_NOSPC:BLK_STS_IOERR;}
static int blk_status_to_errno(int n){return !n?0:n==BLK_STS_RESOURCE?-ENOMEM:n==BLK_STS_NOSPC?-ENOSPC:-EIO;}
struct rb_node {int unused;};struct bow_range {struct rb_node node;sector_t sector;unsigned size;};
struct rb_root {struct rb_node *node;};
static struct rb_node *rb_first(struct rb_root *r){return r->node;}
struct log_entry {uint64_t source,dest;u32 size,checksum;} __attribute__((packed));
struct log_sector {u32 magic;uint16_t header_version,header_size;u32 block_size,count,sequence;sector_t sector0;struct log_entry entries[];} __attribute__((packed));
struct kobject {int unused;};struct kobj_attribute {int unused;};
struct mutex {int held;};
static void mutex_lock(struct mutex *m){CHECK(!m->held);m->held=1;}
static void mutex_unlock(struct mutex *m){CHECK(m->held);m->held=0;}
enum state {TRIM,CHECKPOINT,COMMITTED};
struct bow_context {unsigned block_size,block_shift;void *bufio,*workqueue;struct {struct kobject kobj;} kobj_holder;struct mutex state_lock,ranges_lock;bool failed;int state;struct rb_root ranges;struct bow_range *current;struct log_sector *log_sector;};
#define atomic_read(p) (*(p))
#define atomic_inc(p) (++*(p))
static unsigned long long range_size(struct bow_range *r){return r->size;}
static sector_t sector_to_page(struct bow_context const *c,sector_t s){return s;}
static struct bow_range *find_sector0_current(struct bow_context *c){return c->current;}
static int prepare_error,backup_error,read_error,new_error,flush_error,flushes,drains;
static void flush_workqueue(void *p){struct bow_context *c=p;CHECK(c->state_lock.held && !c->ranges_lock.held);drains++;}
static int prepare_log(struct bow_context *c){CHECK(drains && c->ranges_lock.held);return prepare_error;}
static int backup_log_sector(struct bow_context *c){if(!backup_error)c->log_sector->count=0;return backup_error;}
struct dm_buffer {unsigned char data[512];int refs,valid,dirty;};
static struct dm_buffer cache[8];static unsigned char disk[8][512];
static void dm_bufio_forget(void *c,sector_t p){CHECK(p<8);if(!cache[p].refs && !cache[p].dirty)cache[p].valid=0;}
static void *dm_bufio_read(void *c,sector_t p,struct dm_buffer **out){CHECK(p<8);if(read_error)return ERR_PTR(read_error);struct dm_buffer *b=&cache[p];if(!b->valid)memcpy(b->data,disk[p],512);b->valid=1;b->refs++;*out=b;return b->data;}
static void *dm_bufio_new(void *c,sector_t p,struct dm_buffer **out){CHECK(p<8);if(new_error)return ERR_PTR(new_error);struct dm_buffer *b=&cache[p];b->valid=1;b->refs++;*out=b;return b->data;}
static void dm_bufio_release(struct dm_buffer *b){CHECK(b>=cache && b<cache+8 && b->refs>0);b->refs--;}
static void dm_bufio_mark_buffer_dirty(struct dm_buffer *b){CHECK(b->refs>0);b->dirty=1;}
static int dm_bufio_write_dirty_buffers(void *c){flushes++;if(flush_error)return flush_error;for(int i=0;i<8;i++)if(cache[i].dirty){memcpy(disk[i],cache[i].data,512);cache[i].dirty=0;}return 0;}
static u32 crc32(u32 n,const void *p,unsigned count){return n+((const u8 *)p)[0]+count;}
'''
main=r'''
static unsigned char log_bytes[512];
static void reset(void){memset(cache,0,sizeof(cache));memset(disk,9,sizeof(disk));memset(log_bytes,0,sizeof(log_bytes));read_error=new_error=flush_error=prepare_error=backup_error=flushes=drains=0;}
static void check_refs(void){for(int i=0;i<8;i++)CHECK(!cache[i].refs);}
int main(void){
 for(int stage=0;stage<4;stage++)for(int err=0;err<3;err++)for(int blocks=1;blocks<4;blocks++)for(int checksum=0;checksum<2;checksum++){
  reset();int e=err==0?-EIO:err==1?-ENOMEM:-ENOSPC;if(stage==1)read_error=e;if(stage==2)new_error=e;if(stage==3)flush_error=e;
  struct bow_context c={.block_size=512,.block_shift=9};struct bow_range src={.sector=0,.size=blocks*512},dest={.sector=4,.size=blocks*512};
  for(int i=0;i<blocks;i++){cache[i].valid=1;memset(cache[i].data,3,512);}
  u32 sum=0;int ret=copy_data(&c,&src,&dest,checksum?&sum:NULL);
  CHECK(ret==(stage?errno_to_blk_status(e):0) && c.failed==!!stage);
  if(!stage){for(int i=0;i<blocks;i++)CHECK(!memcmp(disk[i],disk[i+4],512));if(checksum)CHECK(sum==(unsigned)blocks*(512+9));}
  check_refs();cases++;
 }
 for(int stage=0;stage<3;stage++)for(int full=0;full<2;full++){
  reset();if(stage==1)new_error=-ENOMEM;if(stage==2)flush_error=-EIO;
  struct bow_context c={.block_size=512,.log_sector=(void *)log_bytes};c.log_sector->count=full?20:0;
  int ret=add_log_entry(&c,2,5,512,123);CHECK(ret==(stage==1?BLK_STS_RESOURCE:stage==2?BLK_STS_IOERR:0));CHECK(c.failed==!!stage);
  if(!stage){struct log_sector *stored=(void *)disk[0];CHECK(stored->count==1 && stored->entries[0].source==2 && stored->entries[0].dest==5 && stored->entries[0].checksum==123);}
  check_refs();cases++;
 }
 for(int old=TRIM;old<=COMMITTED;old++)for(int next=-1;next<4;next++)for(int error=0;error<4;error++)for(int broken=0;broken<2;broken++){
  reset();struct bow_range first={.sector=0,.size=512},current={.sector=1,.size=512};struct bow_context c={.block_size=512,.block_shift=9,.state=old,.failed=broken,.ranges={.node=&first.node},.current=&current};c.workqueue=&c;
  prepare_error=error;flush_error=blk_status_to_errno(error);char input=(char)('0'+next);
  int ret=state_store(&c.kobj_holder.kobj,NULL,&input,1);
  int want=(next<TRIM || next>COMMITTED)?-EINVAL:broken?-EIO:next!=old+1?-EINVAL:blk_status_to_errno(error);
  CHECK(ret==(want?want:1));CHECK(c.state==(want?old:next));CHECK(!c.state_lock.held && !c.ranges_lock.held);
  if(old<CHECKPOINT+1 && next==old+1 && error)CHECK(c.failed);
  check_refs();cases++;
 }
 printf("%u %u %u\n",cases,checks,failures);return !!failures;
}
'''
controls={
 'stale_source_buffer':body.replace('dm_bufio_forget(bc->bufio, page);',''),
 'swallow_dirty_write_error':body.replace('ret = dm_bufio_write_dirty_buffers(bc->bufio);','dm_bufio_write_dirty_buffers(bc->bufio); ret = 0;'),
 'positive_sysfs_error':body.replace('blk_status_to_errno(prepare_log(bc))','prepare_log(bc)'),
 'retry_failed_checkpoint':body.replace('if (bc->failed) {','if (false) {'),
}
with tempfile.TemporaryDirectory(prefix='dm-bow-buffer-check-') as tmp:
 t=Path(tmp)
 def run(n,b,expected):
  p=t/(n+'.c');exe=t/n;p.write_text(prefix+b+main)
  r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True);assert (r.returncode==0)==expected,(n,r.stdout,r.stderr);return r.stdout
 output=run('current',body,True)
 for n,b in controls.items():assert b!=body,n;run(n,b,False)
counts=list(map(int,output.split()));report={'cases':counts[0],'assertions':counts[1],'failures':counts[2],'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'negative_controls_rejected':list(controls),'scope':__doc__+' Buffer storage, CRC arithmetic and queue draining are shims; range-tree/log-rollover implementation, real media durability and concurrency are not tested.'};(D/'evidence/dm-bow-buffers-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
