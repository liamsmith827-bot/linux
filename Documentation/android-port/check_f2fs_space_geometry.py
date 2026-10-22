#!/usr/bin/env python3
"""Exercise extracted free-section and multi-device trim calculations."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
def function(src,name):
    m=re.search(r'^.*\b'+name+r'\([^;{]*\)\n\{',src,re.M)
    assert m,name
    i,depth=m.end(),1
    while depth:
        depth+=(src[i]=='{')-(src[i]=='}');i+=1
    return src[m.start():i]+'\n'
sources={p:(ROOT/p).read_text() for p in ['fs/f2fs/segment.h','fs/f2fs/f2fs.h']}
body='\n'.join(function(sources[p],n) for p,n in [
    ('fs/f2fs/segment.h','get_additional_blocks_required'),
    ('fs/f2fs/segment.h','__get_secs_required'),
    ('fs/f2fs/f2fs.h','f2fs_hw_discard_granularity')])
prefix=r'''
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
enum { CURSEG_HOT_DATA, CURSEG_WARM_DATA, CURSEG_COLD_DATA, NR_PERSISTENT_LOG=6 };
enum { F2FS_DIRTY_NODES, F2FS_DIRTY_DENTS, F2FS_DIRTY_IMETA, F2FS_DIRTY_DATA };
#define NULL_SEGNO UINT_MAX
#define unlikely(x) (x)
#define min(a,b) ((a)<(b)?(a):(b))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define DIV_ROUND_UP(a,b) (((a)+(b)-1)/(b))
struct block_device { bool zoned; unsigned gran; };
struct super_block { struct block_device *s_bdev; };
struct f2fs_sb_info {
    unsigned cap, counts[4], left[6]; bool lfs;
    struct { unsigned segno; } curseg[6];
    struct { int active_logs; } opt;
    int s_ndevs; struct super_block *sb;
    struct { struct block_device *bdev; } devs[8];
};
#define CAP_BLKS_PER_SEC(s) ((s)->cap)
#define CURSEG_I(s,i) (&(s)->curseg[i])
#define F2FS_OPTION(s) ((s)->opt)
#define get_pages(s,t) ((s)->counts[t])
#define FDEV(i) sbi->devs[i]
static unsigned assertions,failures,cases;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
    if(failures<8) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
static unsigned get_left_section_blocks(struct f2fs_sb_info *s,int i,unsigned seg) { return s->left[i]; }
static bool f2fs_lfs_mode(struct f2fs_sb_info *s) { return s->lfs; }
static bool f2fs_is_multi_device(struct f2fs_sb_info *s) { return s->s_ndevs>1; }
static bool bdev_is_zoned(struct block_device *b) { return b->zoned; }
static unsigned bdev_discard_granularity(struct block_device *b) { return b->gran; }
'''
suffix=r'''
int main(void) {
    unsigned values[]={0,1,15,16,17,31,32};
    for(int logs=2;logs<=6;logs+=2) for(int lfs=0;lfs<2;lfs++)
    for(int mask=0;mask<64;mask++) for(int missing=0;missing<2;missing++)
    for(int a=0;a<7;a++) for(int b=0;b<7;b++) for(int c=0;c<7;c++) {
        struct f2fs_sb_info s={.cap=16,.lfs=lfs,.opt.active_logs=logs,
            .counts={values[a],values[b],1,values[c]}};
        unsigned avail[3]={16,16,16};
        for(int i=0;i<6;i++) {
            s.curseg[i].segno=missing && i==4 ? NULL_SEGNO:i;
            s.left[i]=mask&(1<<i) ? 16:0;
            int cls=i>=3 ? 0:logs==4 && i==0 ? 1:2;
            if(s.left[i]<avail[cls]) avail[cls]=s.left[i];
        }
        if(missing) for(int i=0;i<3;i++) avail[i]=0;
        unsigned demand[3]={values[a]+values[b]+1,logs==4 ? values[b]:0,
                            (lfs ? values[c]:0)+(logs!=4 ? values[b]:0)};
        unsigned expected=0;
        for(int i=0;i<3;i++) if(demand[i]>avail[i]) expected+=(demand[i]-avail[i]+15)/16;
        CHECK(__get_secs_required(&s)==expected);cases++;
    }
    struct block_device dev[8]; struct super_block sb={.s_bdev=dev};
    struct f2fs_sb_info s={.sb=&sb};
    for(int n=1;n<=8;n++) for(int mask=0;mask<(1<<n);mask++) {
        s.s_ndevs=n;
        for(int i=0;i<n;i++) {
            dev[i]=(struct block_device){.zoned=!!(mask&(1<<i)),.gran=512U<<i};
            s.devs[i].bdev=&dev[i];
        }
        unsigned expected=dev[0].gran;
        for(int i=1;i<n;i++) if(!dev[i].zoned && dev[i].gran>expected) expected=dev[i].gran;
        CHECK(f2fs_hw_discard_granularity(&s)==expected);cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
with tempfile.TemporaryDirectory(prefix='f2fs-space-geometry-') as tmp:
    variants={'port':body,
        'ack_swapped_arguments_control':body.replace('&total_node_blocks, &total_data_blocks,\n\t\t\t&total_dent_blocks', '&total_node_blocks, &total_dent_blocks,\n\t\t\t&total_data_blocks'),
        'ack_stop_at_zoned_device_control':body.replace('i < sbi->s_ndevs; i++', 'i < sbi->s_ndevs && !bdev_is_zoned(FDEV(i).bdev); i++')}
    results={}
    for name,code in variants.items():
        c,exe=Path(tmp)/(name+'.c'),Path(tmp)/name;c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (r.returncode==0)==(name=='port'),(name,r.stdout,r.stderr)
        results[name]={'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
report={'scope':__doc__+' Host arithmetic with shims, not a filesystem or allocator test.',
        'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'results':results}
(D/'evidence/f2fs-space-geometry-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip());print('Both original-ACK controls rejected')
