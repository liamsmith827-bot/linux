#!/usr/bin/env python3
"""Host checks of extracted notification functions and inotify canonical tail.

Kernel allocation, path references and event delivery are instrumented shims.
This does not test actual FUSE transport, LSM, inotify queues or concurrency.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
root=D.parent.parent

def function(source,signature):
    start=source.index(signature);op=source.index('{',start);depth=1;i=op+1
    while depth:
        depth+=(source[i]=='{')-(source[i]=='}');i+=1
    return source[start:i]

header=(root/'include/linux/fsnotify.h').read_text()
old=subprocess.check_output(['git','show','9bd964ac839f:include/linux/fsnotify.h'],cwd=root,text=True)
watch_source=(root/'fs/notify/inotify/inotify_user.c').read_text()
watch_start=watch_source.index('\t/* support stacked filesystems */')
watch_end=watch_source.index('\n}\n',watch_start)
watch_tail=watch_source[watch_start:watch_end]
preamble=r'''
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
typedef unsigned __u32;
#define FS_OPEN 0x20
#define FS_OPEN_EXEC 0x1000
#define FS_MODIFY 0x2
#define FS_ACCESS 0x1
#define FS_CLOSE_WRITE 0x8
#define FS_OPEN_PERM 0x10000
#define ALL_FSNOTIFY_PERM_EVENTS FS_OPEN_PERM
#define FSNOTIFY_PRIO_CONTENT 1
#define __FMODE_EXEC 4
#define FMODE_FSNOTIFY_NONE(mode) ((mode) & 3)
struct path;
struct super_block { int unused; };
struct inode { int id; };
struct dentry_operations { int (*d_canonical_path)(const struct path *,struct path *); };
struct dentry { struct dentry_operations *d_op; struct super_block *d_sb; struct inode *d_inode; };
struct path { struct dentry *dentry; void *mnt; };
struct file { struct path f_path; unsigned f_mode,f_flags; void *private_data; };
struct fsnotify_group { int unused; };
static struct inode src_inode={1},dst_inode={2};
static struct dentry src,dst;
static struct path original;
static struct file global_file;
static int scenario,orig_refs,lower_refs,callbacks,upper_events,lower_events;
static int upper_error,lower_error,watch_calls,watch_inode,watch_error,fd_refs=1;
static int errors,cases,priority,hook_calls,hook_mode;
static bool path_equal(const struct path *a,const struct path *b) {
 return a->dentry==b->dentry && a->mnt==b->mnt;
}
static void check(bool ok) { if(!ok) errors++; }
static void path_get(struct path *p) {
 if(path_equal(p,&original))orig_refs++;else lower_refs++;
}
static void path_put(const struct path *p) {
 if(path_equal(p,&original)){check(orig_refs>0);orig_refs--;}
 else{check(lower_refs>0);lower_refs--;}
}
static int canonical(const struct path *p,struct path *out) {
 callbacks++;
 if(scenario==5)return -ENOSYS;
 if(scenario==6)return -ENOENT;
 if(scenario==7)return -ENOMEM;
 if(scenario==8)return -EIO;
 *out=*p;
 if(scenario==2)out->dentry=&dst;
 if(scenario==4)out->mnt=(void *)2;
 path_get(out);return 0;
}
static int fsnotify_path(const struct path *p,__u32 mask) {
 (void)mask;check(orig_refs>0 || lower_refs>0);
 if(path_equal(p,&original)){upper_events++;return upper_error;}
 lower_events++;return lower_error;
}
static bool fsnotify_sb_has_priority_watchers(struct super_block *s,int p) {
 (void)s;(void)p;return priority;
}
static void trace_android_vh_fsnotify_open(struct file *f,__u32 *mask) {
 (void)f;hook_calls++;if(hook_mode==1)*mask=FS_MODIFY;
}
static int inotify_update_watch(struct fsnotify_group *g,struct inode *inode,unsigned mask) {
 (void)g;(void)mask;check(fd_refs==1);watch_calls++;watch_inode=inode->id;
 check(orig_refs>0 || lower_refs>0);return watch_error;
}
#define fd_file(f) (f)
static struct dentry_operations ops={canonical},no_callback={0};
static void setup(int sc,unsigned mode) {
 scenario=sc;src.d_op=sc==0?NULL:sc==1?&no_callback:&ops;
 src.d_inode=&src_inode;dst.d_inode=&dst_inode;
 original=(struct path){&src,(void *)1};
 global_file=(struct file){.f_path=original,.f_mode=mode};
 orig_refs=1;lower_refs=callbacks=upper_events=lower_events=watch_calls=watch_inode=hook_calls=0;
}
'''
watch='''
static int watch(void) {
 struct path path=original,alteredpath,*canonical_path=&path;
 struct file *f=&global_file;
 struct inode *inode;struct fsnotify_group *group;
 unsigned mask=FS_OPEN;int ret;
'''+watch_tail+'\n}\n'
main=r'''
int main(void) {
 unsigned masks[]={FS_OPEN,FS_OPEN|FS_OPEN_EXEC,FS_MODIFY,FS_ACCESS,FS_CLOSE_WRITE,FS_OPEN_PERM};
 for(int sc=0;sc<9;sc++)for(int mode=0;mode<4;mode++)
 for(unsigned mi=0;mi<sizeof(masks)/sizeof(*masks);mi++)
 for(int le=0;le<2;le++)for(int ue=0;ue<2;ue++)for(priority=0;priority<2;priority++) {
  setup(sc,mode);lower_error=le?-ENOMEM:0;upper_error=ue?-EPERM:0;
  int ret=fsnotify_file(&global_file,masks[mi]);
  bool active=mode==0,open=!!(masks[mi]&FS_OPEN),distinct=sc==2||sc==4;
  check(upper_events==active);check(lower_events==(active&&open&&distinct));
  check(callbacks==(active&&open&&sc>=2));check(orig_refs==1&&lower_refs==0);
  check(ret==(active?upper_error:0));cases++;
 }
 for(int sc=0;sc<9;sc++)for(int mode=0;mode<4;mode++)
 for(int ex=0;ex<2;ex++)for(hook_mode=0;hook_mode<2;hook_mode++) {
  setup(sc,mode);global_file.f_flags=ex?__FMODE_EXEC:0;lower_error=-ENOMEM;upper_error=0;
  fsnotify_open(&global_file);
  check(hook_calls==1);check(upper_events==(mode==0));
  check(lower_events==(mode==0&&hook_mode==0&&(sc==2||sc==4)));
  check(orig_refs==1&&lower_refs==0);cases++;
 }
 for(int sc=0;sc<9;sc++)for(int we=0;we<2;we++) {
  setup(sc,0);watch_error=we?-ENOSPC:42;int ret=watch();
  int ce=sc==6?-ENOENT:sc==7?-ENOMEM:sc==8?-EIO:0;
  check(ret==(ce?ce:watch_error));check(watch_calls==!ce);
  check(orig_refs==0&&lower_refs==0);check(watch_inode==(ce?0:sc==2?2:1));cases++;
 }
 printf("%d cases, %d failed assertions\n",cases,errors);return errors?1:0;
}
'''
report={'scope':__doc__.strip(),'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'header_sha256':hashlib.sha256(header.encode()).hexdigest(),'inotify_tail_sha256':hashlib.sha256(watch_tail.encode()).hexdigest(),'runs':[]}
with tempfile.TemporaryDirectory(prefix='fsnotify-host-') as tmp:
    tmp=Path(tmp)
    for label,src in [('port-worktree',header),('negative-control-9bd964ac839f',old)]:
        code=preamble+'\n'+function(src,'static inline int fsnotify_file(')+'\n'+function(src,'static inline void fsnotify_open(')+'\n'+watch+main
        c=tmp/'test.c';binary=tmp/'test';c.write_text(code)
        subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Wno-unused-function',str(c),'-o',str(binary)],check=True)
        result=subprocess.run([str(binary)],capture_output=True,text=True)
        report['runs'].append({'source':label,'exit_code':result.returncode,'output':result.stdout.strip()})
        assert (result.returncode==0)==(label=='port-worktree'),report['runs'][-1]
(D/'evidence/fsnotify-canonical-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
