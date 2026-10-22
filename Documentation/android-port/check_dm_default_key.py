#!/usr/bin/env python3
"""Exercise extracted dm-default-key construction, teardown and mapping with host shims."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
s=(D.parents[1]/'drivers/md/dm-default-key.c').read_text()
# This contiguous section includes the actual constructor, optional parser,
# destructor, map function and target-private declarations, without rewrites.
body=s[s.index('static const struct dm_default_key_cipher {'):s.index('static void default_key_status(')]
prefix=r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
typedef unsigned long long u64,sector_t;typedef unsigned char u8;
enum blk_crypto_mode_num {BLK_ENCRYPTION_MODE_AES_256_XTS,BLK_ENCRYPTION_MODE_ADIANTUM};
enum blk_crypto_key_type {BLK_CRYPTO_KEY_TYPE_RAW=1,BLK_CRYPTO_KEY_TYPE_HW_WRAPPED=2};
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define SECTOR_SHIFT 9
#define SECTOR_SIZE 512
#define BLK_CRYPTO_MAX_ANY_KEY_SIZE 128
#define BLK_CRYPTO_DUN_ARRAY_SIZE 4
#define GFP_KERNEL 0
#define GFP_NOIO 0
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define WARN_ON_ONCE(x) (!!(x))
#define DMDEBUG(...) ((void)0)
enum {DM_MAPIO_REMAPPED=1,DM_MAPIO_KILL=4};
static unsigned cases,checks,failures;
#define CHECK(x) (++checks,(x)?0:(++failures,0))
static unsigned allocations,frees,device_gets,device_puts,evicts,wipes,key_inits,key_starts,fail_stage;
struct block_device {int unused;};struct dm_dev {struct block_device *bdev;};
static struct block_device dev;static struct dm_dev dmdev={&dev};
struct blk_crypto_key {unsigned size,dun_bytes;};
struct dm_target {void *private,*table;const char *error;sector_t begin,len;unsigned num_flush_bios,num_discard_bios;bool emulate_zone_append,flush_bypasses_map;};
struct dm_arg {unsigned min,max;const char *error;};struct dm_arg_set {unsigned argc;char **argv;};
static void *kzalloc(size_t n,int f){if(fail_stage==1)return NULL;allocations++;return calloc(1,n);}
static char *kstrdup(const char *s,int f){if(fail_stage==2)return NULL;allocations++;return strdup(s);}
static void kfree_sensitive(const void *p){if(p){frees++;free((void *)p);}}
static unsigned ilog2(u64 n){return 63-__builtin_clzll(n);}
static unsigned fls64(u64 n){return n?64-__builtin_clzll(n):0;}
static bool is_power_of_2(u64 n){return n && !(n&(n-1));}
static int hex2bin(u8 *dst,const char *src,size_t n){for(size_t i=0;i<n;i++){unsigned v;char tmp[3]={src[i*2],src[i*2+1],0};if(sscanf(tmp,"%2x",&v)!=1)return -1;dst[i]=v;}return 0;}
static void memzero_explicit(void *p,size_t n){memset(p,0,n);wipes++;}
static unsigned dm_table_get_mode(void *p){return 0;}
static int dm_get_device(struct dm_target *t,const char *name,unsigned m,struct dm_dev **p){if(fail_stage==3)return -ENODEV;device_gets++;*p=&dmdev;return 0;}
static void dm_put_device(struct dm_target *t,struct dm_dev *p){CHECK(p==&dmdev);device_puts++;}
static bool bdev_is_zoned(struct block_device *p){return false;}
static const char *dm_shift_arg(struct dm_arg_set *a){if(!a->argc)return NULL;a->argc--;return *a->argv++;}
static int dm_read_arg_group(const struct dm_arg *a,struct dm_arg_set *s,unsigned *n,const char **err){const char *p=dm_shift_arg(s);char x;if(!p || sscanf(p,"%u%c",n,&x)!=1 || *n>a->max || *n>s->argc)return -EINVAL;return 0;}
static int blk_crypto_init_key(struct blk_crypto_key *k,const u8 *bytes,unsigned size,enum blk_crypto_key_type type,enum blk_crypto_mode_num mode,unsigned dun_bytes,unsigned unit){key_inits++;if(fail_stage==4)return -EINVAL;if(!dun_bytes || dun_bytes>8 || size!=(mode==BLK_ENCRYPTION_MODE_AES_256_XTS?64:32))return -EINVAL;k->size=size;k->dun_bytes=dun_bytes;return 0;}
static int blk_crypto_start_using_key(struct block_device *d,struct blk_crypto_key *k){key_starts++;return fail_stage==5?-EOPNOTSUPP:0;}
static void blk_crypto_evict_key(struct block_device *d,struct blk_crypto_key *k){CHECK(k->size>0);evicts++;}
struct bio {struct block_device *bdev;struct {sector_t bi_sector;unsigned bi_size;} bi_iter;bool skip,data,crypt;u64 dun;};
static void bio_set_dev(struct bio *b,struct block_device *d){b->bdev=d;}
static unsigned bio_sectors(struct bio *b){return b->bi_iter.bi_size>>9;}
static sector_t dm_target_offset(struct dm_target *t,sector_t s){return s-t->begin;}
static bool bio_should_skip_dm_default_key(struct bio *b){return b->skip;}
static bool bio_has_data(struct bio *b){return b->data;}
static bool bio_has_crypt_ctx(struct bio *b){return b->crypt;}
static void bio_crypt_set_ctx(struct bio *b,const struct blk_crypto_key *k,u64 *d,int f){CHECK(!b->crypt);b->crypt=true;b->dun=d[0];}
'''
main=r'''
static void reset(void){allocations=frees=device_gets=device_puts=evicts=wipes=key_inits=key_starts=0;}
int main(void){
 char key[129];memset(key,'1',128);key[128]=0;
 const u64 offsets[]={0,1,7,8,255,256,65535,65536,0x100000000ULL,~0ULL-4095,~0ULL-255,~0ULL-7,~0ULL};
 const u64 lens[]={1,2,7,8,9,16,255,256,257,4096,65536};
 for(unsigned bits=9;bits<=12;bits++)for(unsigned i=0;i<ARRAY_SIZE(offsets);i++)for(unsigned j=0;j<ARRAY_SIZE(lens);j++)for(fail_stage=0;fail_stage<6;fail_stage++){
  reset();u64 iv=offsets[i],len=lens[j],units=1ULL<<(bits-9);unsigned unit=1U<<bits;
  char ivstr[32],sizeopt[32];snprintf(ivstr,sizeof(ivstr),"%llu",iv);snprintf(sizeopt,sizeof(sizeopt),"sector_size:%u",unit);
  char *argv[]={"aes-xts-plain64",key,ivstr,"device","3","3","allow_discards",sizeopt,"iv_large_sectors"};
  struct dm_target ti={.begin=64,.len=len};int ret=default_key_ctr(&ti,9,argv);
  /* Independent 128-bit oracle for the mathematical inclusive IV range. */
  __uint128_t last=(__uint128_t)iv+len-1;
  bool valid=!(iv%units) && !(len%units) && last<=~0ULL;
  bool success=valid && !fail_stage;
  CHECK((ret==0)==success);
  if(!fail_stage && !valid)CHECK(key_inits==0 && key_starts==0);
  if(success){
   struct default_key_c *c=ti.private;u64 want_last=(u64)(last/units);unsigned width=1;while(width<8 && (want_last>>(width*8)))width++;
   CHECK(c->max_dun==want_last && c->key.dun_bytes==width);CHECK(ti.flush_bypasses_map && ti.num_flush_bios==1);
   u64 pos[]={0,len-units};
   for(int p=0;p<2;p++){
    struct bio bio={.bi_iter={.bi_sector=ti.begin+pos[p],.bi_size=unit},.data=true};
    CHECK(default_key_map(&ti,&bio)==DM_MAPIO_REMAPPED);CHECK(bio.bdev==&dev && bio.bi_iter.bi_sector==3+pos[p]);
    CHECK(bio.crypt && bio.dun==(u64)(((__uint128_t)iv+pos[p])/units));
   }
   struct bio flush={0};CHECK(default_key_map(&ti,&flush)==DM_MAPIO_REMAPPED && !flush.crypt);
   struct bio skip={.bi_iter={.bi_sector=ti.begin,.bi_size=unit},.data=true,.skip=true,.crypt=true};CHECK(default_key_map(&ti,&skip)==DM_MAPIO_REMAPPED && skip.crypt);
   struct bio nodata={.bi_iter={.bi_sector=ti.begin,.bi_size=unit}};CHECK(default_key_map(&ti,&nodata)==DM_MAPIO_REMAPPED && !nodata.crypt);
   struct bio doublekey={.bi_iter={.bi_sector=ti.begin,.bi_size=unit},.data=true,.crypt=true};CHECK(default_key_map(&ti,&doublekey)==DM_MAPIO_KILL);
   default_key_dtr(&ti);CHECK(evicts==1);
  }
  CHECK(allocations==frees && device_gets==device_puts);CHECK(wipes==(fail_stage==1?0:1));
  if(fail_stage==5 && valid)CHECK(evicts==1);
  if(fail_stage>=2 && fail_stage<=4)CHECK(evicts==0);
  cases++;
 }
 printf("%u %u %u\n",cases,checks,failures);return !!failures;
}
'''
controls={
 'zero_dun_width':body.replace('max_t(unsigned int, 1,\n\t\t\t  DIV_ROUND_UP(fls64(dkc->max_dun), 8))','DIV_ROUND_UP(fls64(dkc->max_dun), 8)'),
 'unchecked_iv_wrap':body.replace('check_add_overflow(dkc->iv_offset, (u64)ti->len - 1,\n\t\t\t       &dkc->max_dun)','(dkc->max_dun = dkc->iv_offset + ti->len - 1, false)'),
 'unaligned_iv_accepted':body.replace('if (dkc->iv_offset & ((dkc->sector_size >> SECTOR_SHIFT) - 1))','if (false)'),
 'evict_uninitialized_key':body.replace('if (blk_key->size > 0)','if (true)'),
}
with tempfile.TemporaryDirectory(prefix='dm-default-key-check-') as tmp:
 t=Path(tmp)
 def run(n,b,expected):
  p=t/(n+'.c');exe=t/n;p.write_text(prefix+b+main)
  r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True);assert (r.returncode==0)==expected,(n,r.stdout,r.stderr);return r.stdout
 output=run('current',body,True)
 for n,b in controls.items():assert b!=body,n;run(n,b,False)
counts=list(map(int,output.split()));report={'cases':counts[0],'assertions':counts[1],'failures':counts[2],'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'negative_controls_rejected':list(controls),'scope':__doc__+' Geometry oracle uses 128-bit arithmetic; allocator, DM, crypto and bio APIs are shims. Checks do not execute encryption, actual device I/O, concurrency or wrapped-key hardware.'};(D/'evidence/dm-default-key-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
