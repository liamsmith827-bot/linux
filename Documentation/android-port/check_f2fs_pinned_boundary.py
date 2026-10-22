#!/usr/bin/env python3
"""Exercise pinned-area calculation, zero-area GC avoidance and cached-section reuse."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
sources={p:(ROOT/p).read_text() for p in ['fs/f2fs/segment.h','fs/f2fs/segment.c','fs/f2fs/gc.c','fs/f2fs/super.c']}
def function(src,name):
    m=re.search(r'^.*\b'+name+r'\([^;{]*\)\n\{',src,re.M);assert m,name
    i,d=m.end(),1
    while d:d+=(src[i]=='{')-(src[i]=='}');i+=1
    return src[m.start():i]+'\n'
body='\n'.join(function(sources['fs/f2fs/segment.h'],n) for n in ['f2fs_pinned_area_limit','adjust_pinned_area_boundary'])
body+='\n'+'\n'.join(function(sources['fs/f2fs/segment.c'],n) for n in ['__allocate_new_segment','f2fs_allocate_pinning_section'])
# Actual publishing call sites are examined separately from the modeled calls.
resize=function(sources['fs/f2fs/gc.c'],'update_fs_metadata')
assert resize.rstrip().endswith('adjust_pinned_area_boundary(sbi);\n}')
remount=function(sources['fs/f2fs/super.c'],'__f2fs_remount')
assert '\tf2fs_down_write(&sbi->pin_sem);\n\tadjust_pinned_area_boundary(sbi);\n\tf2fs_up_write(&sbi->pin_sem);' in remount
prefix=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#define min(a,b) ((a)<(b)?(a):(b))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define MAIN_SECS(s) ((s)->total)
#define F2FS_OPTION(s) ((s)->options)
#define GET_SEC_FROM_SEG(s,n) ((n)/(s)->segs_per_sec)
#define SEGS_PER_SEC(s) ((s)->segs_per_sec)
#define NULL_SEGNO UINT32_MAX
#define CURSEG_COLD_DATA_PINNED 1
#define CURSEG_I(s,t) (&(s)->curseg)
#define ZONED_PIN_SEC_REQUIRED_COUNT 1
struct curseg_info { unsigned segno,next_blkoff;bool inited; };
struct f2fs_sb_info { unsigned total,segs_per_sec,first_seq_zone_segno,pinned_area_max_secno;
    bool zoned;struct { unsigned resizable_tail_secno; } options;struct curseg_info curseg;void *sb; };
struct f2fs_lock_context { int unused; };
static unsigned cases,assertions,failures,gc_calls,alloc_calls,new_calls;
static int locked,gc_error,sync_error;
static unsigned expect_max;
#define CHECK(x) do{assertions++;if(!(x)){failures++;if(failures<8)fprintf(stderr,"line %d: %s\n",__LINE__,#x);}}while(0)
static bool f2fs_sb_has_blkzoned(struct f2fs_sb_info *s){return s->zoned;}
static unsigned get_valid_blocks(struct f2fs_sb_info *s,unsigned seg,bool sec){return 0;}
static unsigned get_ckpt_valid_blocks(struct f2fs_sb_info *s,unsigned seg,bool sec){return 0;}
static int new_curseg(struct f2fs_sb_info *s,int t,bool sec){new_calls++;return 0;}
static void stat_inc_seg_type(struct f2fs_sb_info *s,struct curseg_info *c){}
static void locate_dirty_segment(struct f2fs_sb_info *s,unsigned seg){}
static void f2fs_lock_op(struct f2fs_sb_info *s,struct f2fs_lock_context *c){CHECK(!locked++);}
static void f2fs_unlock_op(struct f2fs_sb_info *s,struct f2fs_lock_context *c){CHECK(--locked==0);}
static int f2fs_allocate_new_section(struct f2fs_sb_info *s,int t,bool force){CHECK(locked==1);alloc_calls++;return -EAGAIN;}
static int f2fs_gc_range(struct f2fs_sb_info *s,unsigned start,unsigned end,bool dry,unsigned count,bool lock){
    CHECK(!locked && expect_max && start==0 && end==expect_max*s->segs_per_sec-1 && end<s->total*s->segs_per_sec);
    CHECK(dry && count==ZONED_PIN_SEC_REQUIRED_COUNT && lock);gc_calls++;return gc_error;
}
static int f2fs_sync_fs(void *sb,int wait){CHECK(!locked && wait==1);return sync_error;}
'''
suffix=r'''
int main(void){
    unsigned values[]={0,1,2,4,8,16,31,32,0xfffffffeU,0xffffffffU};
    for(unsigned a=0;a<10;a++)for(unsigned b=0;b<10;b++)for(unsigned c=0;c<10;c++)for(int zone=0;zone<2;zone++){
        struct f2fs_sb_info s={.total=values[a],.segs_per_sec=1,.first_seq_zone_segno=values[c],.zoned=zone,.options={values[b]}};
        uint64_t expected=values[a]>values[b]?(uint64_t)values[a]-values[b]:0;
        if(zone && values[c]!=UINT32_MAX && values[c]<expected)expected=values[c];
        adjust_pinned_area_boundary(&s);CHECK(s.pinned_area_max_secno==expected);cases++;
    }
    /* Includes stale published bounds larger than transient/current geometry. */
    for(unsigned total=0;total<=16;total++)for(unsigned bound=0;bound<=20;bound++)for(unsigned segs=1;segs<=4;segs++)
    for(int error=0;error<3;error++){
        struct f2fs_sb_info s={.total=total,.segs_per_sec=segs,.pinned_area_max_secno=bound};
        gc_calls=alloc_calls=0;locked=0;gc_error=error==1?-EIO:0;sync_error=error==2?-EIO:0;
        expect_max=min(total,bound);
        int r=f2fs_allocate_pinning_section(&s);
        CHECK(!locked);
        if(!expect_max){CHECK(r==-ENOSPC && !gc_calls && !alloc_calls);}
        else if(expect_max==total){CHECK(r==-EAGAIN && !gc_calls && alloc_calls==1);}
        else {CHECK(gc_calls==1);CHECK(r==(error?-EIO:-EAGAIN));CHECK(alloc_calls==(error?1:2));}
        cases++;
    }
    for(unsigned limit=0;limit<=8;limit++)for(unsigned section=0;section<8;section++)for(int type=0;type<2;type++){
        struct f2fs_sb_info s={.total=8,.segs_per_sec=2,.pinned_area_max_secno=limit,.curseg={.segno=section*2,.inited=true}};
        new_calls=0;CHECK(!__allocate_new_segment(&s,type,true,false));
        CHECK(new_calls==(type==CURSEG_COLD_DATA_PINNED && section>=limit));cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);return !!failures;
}
'''
variants={'port':body,
          'tail_underflow_control':body.replace('total > tail ? total - tail : 0','total - tail'),
          'zero_area_gc_control':body.replace('if (!max_secno) {','if (false) {'),
          'out_of_area_reuse_control':body.replace('(type != CURSEG_COLD_DATA_PINNED ||\n\t     GET_SEC_FROM_SEG(sbi, curseg->segno) < f2fs_pinned_area_limit(sbi))','true')}
results={}
with tempfile.TemporaryDirectory(prefix='f2fs-pinned-boundary-') as tmp:
    for name,code in variants.items():
        c,exe=Path(tmp)/(name+'.c'),Path(tmp)/name;c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (r.returncode==0)==(name=='port'),(name,r.stdout,r.stderr)
        results[name]={'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
report={'scope':__doc__+' Modeled geometry, GC, locks and section allocation. Publication call placement checked in source; actual remount/resize, concurrency and storage not executed.',
        'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'results':results}
(D/'evidence/f2fs-pinned-boundary-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip());print('All three negative controls rejected')
