#!/usr/bin/env python3
"""Exercise extracted segment selection against independent allowed-section masks."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D=Path(__file__).resolve().parent
ROOT=D.parents[1]
sources={p:(ROOT/p).read_text() for p in ['fs/f2fs/segment.c','fs/f2fs/segment.h']}
def function(src,name):
    m=re.search(r'^.*\b'+name+r'\([^;{]*\)\n\{',src,re.M);assert m,name
    i,d=m.end(),1
    while d:d+=(src[i]=='{')-(src[i]=='}');i+=1
    return src[m.start():i]+'\n'
body='\n'.join(function(sources['fs/f2fs/segment.h'],n) for n in ['f2fs_dev_is_reserving','f2fs_dev_is_alloc_blocked','sec_usage_check'])
body+=function(sources['fs/f2fs/segment.c'],'get_new_segment')
baseline='334f9060783c42bd9d9e274d39ec4e84b9eb9ed9'
native=subprocess.check_output(['git','-C',str(ROOT),'show',baseline+':fs/f2fs/segment.c'],text=True)
body+=function(native,'get_new_segment').replace('get_new_segment(', 'native_get_new_segment(',1)
prefix=r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifndef EFSCORRUPTED
#define EFSCORRUPTED 117
#endif
#define CONFIG_BLK_DEV_ZONED 1
#define READ_ONCE(x) (x)
#define FDEV(i) (sbi->devs[i])
#define FREE_I(s) (&(s)->free)
#define MAIN_SECS(s) 8
#define MAIN_SEGS(s) (8*(s)->segs_per_sec)
#define GET_SEC_FROM_SEG(s,n) ((n)/(s)->segs_per_sec)
#define GET_SEG_FROM_SEC(s,n) ((n)*(s)->segs_per_sec)
#define GET_ZONE_FROM_SEC(s,n) ((n)/(s)->secs_per_zone)
#define GET_ZONE_FROM_SEG(s,n) GET_ZONE_FROM_SEC(s,GET_SEC_FROM_SEG(s,n))
#define SEGS_PER_SEC(s) ((s)->segs_per_sec)
#define START_BLOCK(s,n) ((n)*4)
#define GET_SEGNO(s,n) ((n)/4)
#define CURSEG_I(s,n) (&(s)->curseg[n])
#define NR_CURSEG_TYPE 8
#define FAULT_NO_SEGMENT 1
#define ALLOCATE_FORWARD_NOHINT 0
#define ALLOCATE_FORWARD_FROM_HINT 1
#define ALLOCATE_FORWARD_WITHIN_HINT 2
#define BLKZONE_ALLOC_PRIOR_CONV 0
#define BLKZONE_ALLOC_ONLY_SEQ 1
#define STOP_CP_REASON_CORRUPTED_FREE_BITMAP 1
#define STOP_CP_REASON_NO_SEGMENT 2
#define max(a,b) ((a)>(b)?(a):(b))
typedef unsigned block_t;
struct free_segmap_info { int segmap_lock;unsigned long free_segmap[1],free_secmap[1]; };
struct f2fs_sb_info { struct free_segmap_info free;unsigned segs_per_sec,secs_per_zone,allocate_section_policy,allocate_section_hint;
    unsigned cur_victim_sec,used_sec_mask,first_seq_zone_segno,blkzone_alloc_policy;bool zoned,alias;
    unsigned s_ndevs;struct { unsigned end_blk,alias_ino;bool is_reserving; } devs[2];struct { unsigned zone; } curseg[8]; };
static unsigned cases,assertions,failures,searches;
#define CHECK(x) do{assertions++;if(!(x)){failures++;if(failures<8)fprintf(stderr,"line %d: %s\n",__LINE__,#x);}}while(0)
static bool f2fs_sb_has_device_alias(struct f2fs_sb_info *s){return s->alias;}
static bool f2fs_sb_has_blkzoned(struct f2fs_sb_info *s){return s->zoned;}
static bool is_cursec(struct f2fs_sb_info *s,unsigned sec){return s->used_sec_mask&(1U<<sec);}
static int f2fs_target_device_index(struct f2fs_sb_info *s,unsigned b){CHECK(b<8*s->segs_per_sec*4);return b>=s->devs[1].end_blk/2+1;}
static bool time_to_inject(struct f2fs_sb_info *s,int fault){return false;}
static bool test_bit(unsigned bit,unsigned long *bits){return bits[0]&(1UL<<bit);}
static unsigned find_next_zero_bit(unsigned long *bits,unsigned maxbit,unsigned start){
    if(++searches>64)abort();for(unsigned i=start;i<maxbit;i++)if(!test_bit(i,bits))return i;return maxbit;
}
static unsigned find_first_zero_bit(unsigned long *bits,unsigned maxbit){return find_next_zero_bit(bits,maxbit,0);}
static void spin_lock(int *l){CHECK(!(*l)++);}
static void spin_unlock(int *l){CHECK(--(*l)==0);}
static void f2fs_bug_on(struct f2fs_sb_info *s,bool bug){}
static void f2fs_stop_checkpoint(struct f2fs_sb_info *s,bool b,int reason){}
static bool f2fs_is_sequential_zone_area(struct f2fs_sb_info *s,unsigned b){return s->zoned && b>=s->first_seq_zone_segno*4;}
static void __set_inuse(struct f2fs_sb_info *s,unsigned seg){CHECK(!test_bit(seg,s->free.free_segmap));s->free.free_segmap[0]|=1UL<<seg;}
'''
suffix=r'''
int main(void){
    for(unsigned occupied=0;occupied<256;occupied++)for(unsigned flags=0;flags<16;flags++)
    for(unsigned geometry=0;geometry<4;geometry++)for(int pin=0;pin<2;pin++)for(int zone=0;zone<3;zone++){
        struct f2fs_sb_info s={.alias=true,.s_ndevs=2,.segs_per_sec=1+(geometry&1),.secs_per_zone=1+!!(geometry&2),
            .used_sec_mask=1,.cur_victim_sec=1,.zoned=zone!=0,.blkzone_alloc_policy=zone==2?1:0};
        s.first_seq_zone_segno=4*s.segs_per_sec;
        s.devs[0].end_blk=16*s.segs_per_sec-1;s.devs[1].end_blk=32*s.segs_per_sec-1;
        s.devs[0].alias_ino=flags&1;s.devs[0].is_reserving=flags&2;
        s.devs[1].alias_ino=flags&4;s.devs[1].is_reserving=flags&8;
        s.allocate_section_policy=occupied%3;s.allocate_section_hint=occupied%10;
        for(int j=0;j<8;j++)s.curseg[j].zone=j%s.secs_per_zone;
        s.free.free_secmap[0]=occupied;
        for(int sec=0;sec<8;sec++)if(occupied&(1U<<sec))
            for(unsigned seg=sec*s.segs_per_sec;seg<(sec+1)*s.segs_per_sec;seg++)s.free.free_segmap[0]|=1UL<<seg;
        unsigned allowed=0;
        for(int sec=2;sec<8;sec++){
            int dev=sec>=4;
            bool blocked=(dev?(flags&8):(flags&2)) || (pin && (dev?(flags&4):(flags&1)));
            bool wrong_zone=zone && pin && sec>=4;
            if(!(occupied&(1U<<sec)) && !blocked && !wrong_zone)allowed|=1U<<sec;
        }
        unsigned selected=(occupied%8)*s.segs_per_sec;searches=0;
        int r=get_new_segment(&s,&selected,true,pin);
        CHECK(!s.free.segmap_lock);
        if(!r){CHECK(selected<8*s.segs_per_sec && (allowed&(1U<<(selected/s.segs_per_sec))));}
        else {
            CHECK(r==-ENOSPC || r==-EAGAIN);
            /* Native zone/hint preferences can retry or bypass otherwise free zones. */
            if(!zone){if(allowed && failures<7)fprintf(stderr,"occupied=%u flags=%u geometry=%u pin=%d hint=%u policy=%u selected=%u allowed=%u r=%d\n",occupied,flags,geometry,pin,s.allocate_section_hint,s.allocate_section_policy,selected,allowed,r);CHECK(!allowed);}
        }
        cases++;
    }
    /* Confirm two non-guarantees against the unchanged pre-alias selector. */
    for(int pin=0;pin<2;pin++){
        struct f2fs_sb_info s={.segs_per_sec=1,.secs_per_zone=pin?2:1,.s_ndevs=2,.zoned=true,
            .first_seq_zone_segno=4,.blkzone_alloc_policy=BLKZONE_ALLOC_ONLY_SEQ,
            .allocate_section_policy=pin?0:2,.allocate_section_hint=2,.cur_victim_sec=99};
        s.devs[0].end_blk=15;s.devs[1].end_blk=31;
        s.free.free_secmap[0]=3;s.free.free_segmap[0]=3;
        for(int j=0;j<8;j++)s.curseg[j].zone=j%2;
        struct f2fs_sb_info old=s;unsigned a=pin?0:6,b=a;searches=0;
        int r=get_new_segment(&s,&a,true,pin);searches=0;
        int nr=native_get_new_segment(&old,&b,true,pin);
        CHECK(r==nr && a==b);CHECK(pin?r==-EAGAIN:(!r && a==2));cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);return !!failures;
}
'''
variants={'port':body,'premature_zone_exhaustion_control':body.replace('		/* The fallback pass must not skip the last usable zone. */\n		init = false;',''),
          'ignore_device_reservation_control':body.replace('return READ_ONCE(FDEV(devi).is_reserving);','return false;').replace('return (pinning && READ_ONCE(FDEV(devi).alias_ino)) ||\n\t\tREAD_ONCE(FDEV(devi).is_reserving);','return false;')}
results={}
with tempfile.TemporaryDirectory(prefix='f2fs-alias-placement-') as tmp:
    for name,code in variants.items():
        c,exe=Path(tmp)/(name+'.c'),Path(tmp)/name;c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter','-Wno-misleading-indentation',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        assert (r.returncode==0)==(name=='port'),(name,r.stdout,r.stderr)
        results[name]={'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
report={'scope':__doc__+' Two-device, eight-section modeled maps; new-section selection, aliases/pinning, zoned policies, one/two segments and sections per zone, hints and occupied maps. Not actual allocator concurrency, hardware, mount, storage or runtime testing.',
        'native_baseline':baseline,'native_policy_limits':'Existing allocation hints can override ONLY_SEQ preference; zone separation can return EAGAIN for pinned allocations despite available conventional sections. Both cases executed against the native selector. No full availability guarantee asserted for zoned policies.',
        'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'results':results}
(D/'evidence/f2fs-alias-placement-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip());print('Ignoring device reservation and premature exhaustion controls rejected')
