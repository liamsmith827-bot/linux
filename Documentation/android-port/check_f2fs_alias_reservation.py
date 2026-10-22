#!/usr/bin/env python3
"""Check extracted alias reservation accounting, ioctl unwind and geometry."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
paths=['fs/f2fs/f2fs.h','fs/f2fs/file.c','fs/f2fs/segment.c','fs/f2fs/gc.c']
sources={p:(ROOT/p).read_text() for p in paths}
def function(src,name):
    m=re.search(r'^.*\b'+name+r'\([^;{]*\)\n\{',src,re.M);assert m,name
    i,d=m.end(),1
    while d:d+=(src[i]=='{')-(src[i]=='}');i+=1
    return src[m.start():i]+'\n'
baseline='334f9060783c42bd9d9e274d39ec4e84b9eb9ed9'
identical={}
for p,names in {'fs/f2fs/segment.c':['update_sit_entry_for_alloc','update_sit_entry'],
                'fs/f2fs/gc.c':['free_segment_range','f2fs_gc_range']}.items():
    native=subprocess.check_output(['git','-C',str(ROOT),'show',baseline+':'+p],text=True)
    for n in names:
        f=function(sources[p],n);assert f==function(native,n),(p,n)
        identical[n]=hashlib.sha256(f.encode()).hexdigest()
body='\n'.join(function(sources['fs/f2fs/f2fs.h'],n) for n in ['get_available_block_count','inc_valid_block_count'])
body+='\n'+'\n'.join(function(sources['fs/f2fs/file.c'],n) for n in ['f2fs_get_dev_alias_extent','f2fs_ioc_reserve_dev_alias','f2fs_ioc_release_dev_alias'])
prefix=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef EFSCORRUPTED
#define EFSCORRUPTED 117
#endif
typedef uint32_t block_t;
typedef uint64_t u64;
#define U32_MAX UINT32_MAX
#define unlikely(x) (x)
#define CP_SYNC 1
#define CAP_SYS_ADMIN 1
#define SBI_CP_DISABLED 1
#define SBI_NEED_FSCK 2
#define ERROR_CORRUPTED_INODE 1
#define RESERVE_ROOT 1
#define FAULT_BLOCK 1
#define FI_NO_EXTENT 1
#define EX_READ 0
#define CURSEG_HOT_DATA 0
#define NR_CURSEG_PERSIST_TYPE 6
#define NR_CURSEG_TYPE 8
#define F2FS_I_SB(i) ((i)->sbi)
#define F2FS_I(i) (i)
#define F2FS_OPTION(s) ((s)->options)
#define FREE_I(s) (s)
#define FDEV(i) (sbi->devs[i])
#define F2FS_HAS_BLOCKS(i) ((i)->blocks!=0)
#define IS_DEVICE_ALIASING(i) ((i)->alias)
#define GET_SEGNO(s,b) ((b)>>(s)->log_blocks_per_seg)
#define GET_SEGOFF_FROM_SEG0(s,b) (b)
#define BLKS_PER_SEC(s) (1U<<(s)->log_blocks_per_seg)
#define WRITE_ONCE(x,v) ((x)=(v))
#define f2fs_warn(...) ((void)0)
struct extent_info { unsigned blk,len,fofs; };
struct extent_tree { int lock;struct extent_info largest; };
struct bdev { bool zoned; };
struct dev { char *path;unsigned start_blk,end_blk,total_segments,alias_ino;bool is_reserving;struct bdev *bdev; };
struct f2fs_sb_info { unsigned user_block_count,current_reserved_blocks,alias_reserved_blocks,unusable_block_count,total_valid_block_count;
    struct { unsigned root_reserved_blocks; } options;
    bool reserve_root,cp_disabled;int stat_lock,gc_lock,segmap_lock,log_blocksize,log_blocks_per_seg,s_ndevs;
    long long alloc_valid_block_count;struct dev devs[2]; };
struct inode { struct f2fs_sb_info *sbi;struct extent_tree *extent_tree[1];void *i_mapping;
    unsigned long i_ino;unsigned i_nlink,i_mode;bool alias;long long blocks;loff_t size; };
struct dentry { struct inode *inode;struct { const char *name; } d_name; };
struct file { struct inode *inode;struct { struct dentry *dentry; } f_path; };
struct cp_control { int reason,a,b,c; };
struct f2fs_lock_context { int unused; };
static unsigned cases,assertions,failures;
#define CHECK(x) do { assertions++;if(!(x)){failures++;if(failures<8)fprintf(stderr,"line %d: %s\n",__LINE__,#x);} } while(0)
static int stage,mount_writes,inode_locks,op_locks,invalidate_locks,moved,checkpoints;
static long long quota;
static bool allowed=true,root_allowed=true;
static struct inode *file_inode(struct file *f){return f->inode;}
static struct inode *d_inode(struct dentry *d){return d->inode;}
static bool capable(int c){return allowed;}
static bool bdev_is_zoned(struct bdev *b){return b->zoned;}
static bool is_sbi_flag_set(struct f2fs_sb_info *s,int f){return f==SBI_CP_DISABLED && (s->cp_disabled || (stage==17 && op_locks));}
static bool test_opt(struct f2fs_sb_info *s,int f){return s->reserve_root;}
static bool __allow_reserved_root(struct f2fs_sb_info *s,struct inode *i,bool cap){return root_allowed;}
static int dquot_reserve_block(struct inode *i,blkcnt_t c){if(stage==19)return -EDQUOT;quota+=c;return 0;}
static void dquot_release_reservation_block(struct inode *i,blkcnt_t c){quota-=c;}
static bool time_to_inject(struct f2fs_sb_info *s,int f){return stage==24;}
static void percpu_counter_add(long long *p,blkcnt_t c){*p+=c;}
static void percpu_counter_sub(long long *p,blkcnt_t c){*p-=c;}
static void spin_lock(int *p){CHECK(!(*p)++);}
static void spin_unlock(int *p){CHECK(--(*p)==0);}
static void write_lock(int *p){CHECK(!(*p)++);}
static void write_unlock(int *p){CHECK(--(*p)==0);}
static void read_lock(int *p){CHECK(!(*p)++);}
static void read_unlock(int *p){CHECK(--(*p)==0);}
static void f2fs_i_blocks_write(struct inode *i,block_t c,bool a,bool b){CHECK(a&&b);i->blocks+=c;}
static int mnt_want_write_file(struct file *f){if(stage==3)return -EROFS;mount_writes++;return 0;}
static void mnt_drop_write_file(struct file *f){CHECK(--mount_writes==0);}
static void inode_lock(struct inode *i){CHECK(!inode_locks++);}
static void inode_unlock(struct inode *i){CHECK(--inode_locks==0);}
static void f2fs_down_write_trace(int *p,struct f2fs_lock_context *lc){CHECK(inode_locks==1);CHECK(!(*p)++);}
static void f2fs_up_write_trace(int *p,struct f2fs_lock_context *lc){CHECK(--(*p)==0);}
static void f2fs_lock_op(struct f2fs_sb_info *s,struct f2fs_lock_context *lc){CHECK(s->gc_lock==1);CHECK(!op_locks++);}
static void f2fs_unlock_op(struct f2fs_sb_info *s,struct f2fs_lock_context *lc){CHECK(--op_locks==0);}
static void set_sbi_flag(struct f2fs_sb_info *s,int f){}
static void f2fs_handle_error(struct f2fs_sb_info *s,int e){}
static int f2fs_target_device_index(struct f2fs_sb_info *s,unsigned b){CHECK(b==64);return 1;}
static void f2fs_reset_gc_victim_resource(struct f2fs_sb_info *s,unsigned a,unsigned b){CHECK(s->gc_lock && s->devs[1].is_reserving);}
static int f2fs_allocate_segment_for_resize(struct f2fs_sb_info *s,int type,unsigned a,unsigned b){
    CHECK(s->gc_lock && s->devs[1].is_reserving);if(stage==9+type)return -EAGAIN;moved|=1<<type;return 0;
}
static int f2fs_gc_range(struct f2fs_sb_info *s,unsigned a,unsigned b,bool dry,unsigned secs,bool lock){
    CHECK(s->gc_lock==1 && op_locks==1 && !lock && !dry && !secs && moved==255);
    if(stage==20)s->current_reserved_blocks=s->user_block_count;
    return stage==18?-EAGAIN:0;
}
static void clear_inode_flag(struct inode *i,int f){}
static void f2fs_reserve_device_alias(struct f2fs_sb_info *s,unsigned b,unsigned n){CHECK(s->gc_lock && op_locks && s->devs[1].is_reserving);}
static void i_size_write(struct inode *i,loff_t v){i->size=v;}
static void f2fs_update_inode_page(struct inode *i){CHECK(op_locks && inode_locks);}
static int f2fs_write_checkpoint(struct f2fs_sb_info *s,struct cp_control *c){
    CHECK(mount_writes==1 && !s->gc_lock && !op_locks && !inode_locks);checkpoints++;return stage==21?-EIO:0;
}
static int filemap_write_and_wait(void *m){return stage==22?-EIO:0;}
static void filemap_invalidate_lock(void *m){CHECK(!invalidate_locks++);}
static void filemap_invalidate_unlock(void *m){CHECK(--invalidate_locks==0);}
static void truncate_setsize(struct inode *i,loff_t v){CHECK(invalidate_locks);i->size=v;}
static int f2fs_truncate_blocks(struct inode *i,int from,bool lock){
    CHECK(invalidate_locks && op_locks && !from && !lock);
    if(stage==23)return -EIO;
    i->sbi->total_valid_block_count-=i->blocks;i->blocks=0;i->extent_tree[0]->largest.len=0;return 0;
}
static void reset(void){mount_writes=inode_locks=op_locks=invalidate_locks=moved=checkpoints=0;quota=0;}
'''
suffix=r'''
int main(void){
    for(stage=0;stage<=24;stage++)for(int release=0;release<2;release++){
        reset();allowed=stage!=1;root_allowed=true;
        struct bdev b={0};struct f2fs_sb_info s={.user_block_count=1024,.total_valid_block_count=100,
            .current_reserved_blocks=16,.s_ndevs=2,.log_blocks_per_seg=2,.log_blocksize=12,.cp_disabled=stage==2};
        s.devs[1]=(struct dev){.path="/dev/vdb",.start_blk=64,.end_blk=95,.total_segments=8,.alias_ino=99,.bdev=&b};
        struct extent_tree t={0};struct inode i={.sbi=&s,.extent_tree={&t},.i_ino=99,.i_nlink=stage!=5,.i_mode=S_IFREG,.alias=stage!=4};
        struct dentry d={.inode=&i,.d_name={.name="vdb"}};struct file f={.inode=&i,.f_path={.dentry=&d}};
        if(release){i.blocks=32;i.size=32LL<<12;t.largest=(struct extent_info){64,32,0};s.total_valid_block_count+=32;}
        if(stage==6){i.blocks=release?0:32;i.size=i.blocks<<12;}
        if(stage==7)s.devs[1].alias_ino=0;
        if(stage==8)s.total_valid_block_count=1010;
        unsigned initial_valid=s.total_valid_block_count;long long initial_blocks=i.blocks;loff_t initial_size=i.size;
        int r=release?f2fs_ioc_release_dev_alias(&f):f2fs_ioc_reserve_dev_alias(&f);
        int expected=0;bool changed=false;
        if(stage==1)expected=-EPERM;
        else if(stage==2)expected=-EINVAL;
        else if(stage==3)expected=-EROFS;
        else if(stage==4)expected=-EINVAL;
        else if(!release && stage==5)expected=-ENOENT;
        else if(stage==6)expected=0;
        else if(!release && stage==7)expected=-EFSCORRUPTED;
        else if(!release && stage==8)expected=-ENOSPC;
        else if(!release && stage>=9 && stage<=16)expected=-EAGAIN;
        else if(stage==17)expected=-EINVAL;
        else if(!release && stage==18)expected=-EAGAIN;
        else if(!release && stage==19)expected=-EDQUOT;
        else if(!release && (stage==20 || stage==24))expected=-ENOSPC;
        else if(release && (stage==22 || stage==23))expected=-EIO;
        else {changed=true;if(stage==21)expected=-EIO;}
        CHECK(r==expected);CHECK(!mount_writes && !inode_locks && !op_locks && !invalidate_locks && !s.gc_lock && !s.stat_lock && !s.segmap_lock && !t.lock);
        CHECK(!s.alias_reserved_blocks && !s.devs[1].is_reserving);
        CHECK(checkpoints==changed);
        if(changed){CHECK(i.blocks==(release?0:32));CHECK(i.size==(release?0:32LL<<12));CHECK(s.total_valid_block_count==initial_valid+(release?-32:32));}
        else {CHECK(i.blocks==initial_blocks && i.size==initial_size);CHECK(s.total_valid_block_count==initial_valid);}
        if(!release)CHECK(quota==(changed?32:0) && s.alloc_valid_block_count==(changed?32:0));
        cases++;
    }
    /* Mathematical capacity reference includes wrap boundaries and oversized reserves. */
    unsigned values[]={0,1,31,32,1024,0x7fffffffU,0xfffffffeU,0xffffffffU};
    stage=0;allowed=true;
    for(unsigned a=0;a<8;a++)for(unsigned b=0;b<8;b++)for(unsigned c=0;c<8;c++)for(unsigned d=0;d<8;d++)
    for(int cp=0;cp<2;cp++)for(int root=0;root<2;root++){
        struct f2fs_sb_info s={.user_block_count=values[a],.current_reserved_blocks=values[b],.alias_reserved_blocks=values[c],
            .unusable_block_count=31,.reserve_root=true,.cp_disabled=cp,.options={.root_reserved_blocks=values[d]}};
        struct inode i={.sbi=&s};root_allowed=root;
        uint64_t reserved=(uint64_t)values[b]+values[c]+(root?0:values[d]);
        uint64_t avail=values[a]>reserved?values[a]-reserved:0;
        if(cp)avail=avail>31?avail-31:0;
        CHECK(get_available_block_count(&s,&i,true)==avail);cases++;
    }
    /* A reservation that wraps unsigned addition must fail before moving data. */
    reset();root_allowed=true;
    struct bdev b={0};struct f2fs_sb_info s={.user_block_count=UINT32_MAX,.total_valid_block_count=UINT32_MAX-8,
        .s_ndevs=2,.log_blocks_per_seg=2,.log_blocksize=12};
    s.devs[1]=(struct dev){.path="/dev/vdb",.start_blk=64,.end_blk=95,.total_segments=8,.alias_ino=99,.bdev=&b};
    struct extent_tree t={0};struct inode i={.sbi=&s,.extent_tree={&t},.i_ino=99,.i_nlink=1,.i_mode=S_IFREG,.alias=true};
    struct dentry d={.inode=&i,.d_name={.name="vdb"}};struct file f={.inode=&i,.f_path={.dentry=&d}};
    CHECK(f2fs_ioc_reserve_dev_alias(&f)==-ENOSPC);CHECK(!moved && !s.alias_reserved_blocks && !s.devs[1].is_reserving);cases++;
    for(int mode=0;mode<7;mode++){
        s.devs[1]=(struct dev){.path="/dev/vdb",.start_blk=64,.end_blk=95,.total_segments=8,.alias_ino=99,.bdev=&b};b.zoned=false;
        if(mode==1)s.devs[1].start_blk++;
        if(mode==2)s.devs[1].total_segments=0;
        if(mode==3)s.devs[1].total_segments=0x40000008U;
        if(mode==4)s.devs[1].alias_ino=98;
        if(mode==5)b.zoned=true;
        if(mode==6)s.devs[1].end_blk--;
        struct extent_info ei;CHECK(f2fs_get_dev_alias_extent(&s,&d,&ei)==(mode==0));cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);return !!failures;
}
'''
variants={'port':body,
          'unsigned_capacity_wrap_control':body.replace('(u64)sbi->total_valid_block_count + ei.len','sbi->total_valid_block_count + ei.len'),
          'persistent_curseg_only_control':body.replace('type < NR_CURSEG_TYPE','type < NR_CURSEG_PERSIST_TYPE'),
          'checkpoint_without_write_hold_control':body.replace('err = f2fs_write_checkpoint(sbi, &cpc);\n\tmnt_drop_write_file(filp);','mnt_drop_write_file(filp);\n\terr = f2fs_write_checkpoint(sbi, &cpc);')}
results={}
with tempfile.TemporaryDirectory(prefix='f2fs-alias-') as tmp:
    for name,code in variants.items():
        c,exe=Path(tmp)/(name+'.c'),Path(tmp)/name;c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (r.returncode==0)==(name=='port'),(name,r.stdout,r.stderr)
        results[name]={'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
report={'scope':__doc__+' Lock/allocation/GC/bitmap/storage shims, no actual filesystem, quota, concurrency, IO or crash recovery. Native per-block SIT and resize/GC function identity checked separately.',
        'native_baseline':baseline,'identical_native_functions_sha256':identical,
        'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'results':results}
(D/'evidence/f2fs-alias-reservation-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip());print('All three negative controls rejected; native SIT/resize/GC functions identical')
