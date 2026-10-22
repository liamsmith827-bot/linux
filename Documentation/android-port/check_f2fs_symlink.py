#!/usr/bin/env python3
"""Exercise extracted F2FS symlink rollback, unlink and failed-inode control flow."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

D = Path(__file__).resolve().parent
ROOT = D.parents[1]
sources = {p: (ROOT / p).read_text() for p in ['fs/f2fs/namei.c', 'fs/f2fs/inode.c']}

def function(src, name):
    m = re.search(r'^.*\b' + name + r'\([^;{]*\)\n\{', src, re.M)
    assert m, name
    i, depth = m.end(), 1
    while depth:
        depth += (src[i] == '{') - (src[i] == '}')
        i += 1
    return src[m.start():i] + '\n'

body = function(sources['fs/f2fs/inode.c'], 'f2fs_handle_failed_inode')
body += '\n'.join(function(sources['fs/f2fs/namei.c'], n)
                  for n in ['__do_unlink', 'f2fs_unlink', 'f2fs_symlink'])
prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#ifndef EFSCORRUPTED
#define EFSCORRUPTED 117
#endif
#define S_IRWXUGO 0777
#define unlikely(x) (x)
#define IS_ERR(x) ((uintptr_t)(x) > (uintptr_t)-4096)
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define F2FS_I_SB(i) ((i)->i_sb->sbi)
#define IS_ENCRYPTED(i) encrypted
#define IS_DIRSYNC(i) dirsync
#define IS_CASEFOLDED(i) casefold
#define CONFIG_UNICODE 1
#define IS_ENABLED(x) (x)
#define SBI_NEED_FSCK 1
#define FI_FREE_NID 2
#define NULL_ADDR 0
#define f2fs_warn(...) ((void)0)
#define trace_f2fs_unlink_enter(...) ((void)0)
#define trace_f2fs_unlink_exit(...) ((void)0)
struct mnt_idmap { int unused; };
struct f2fs_lock_context { int unused; };
struct f2fs_sb_info { struct super_block *sb; };
struct super_block { struct f2fs_sb_info *sbi; unsigned s_blocksize; };
struct mapping { void *a_ops; };
struct inode { struct super_block *i_sb; struct mapping *i_mapping; void *i_op;
    unsigned long i_ino; unsigned i_mode, i_nlink; bool fresh; };
struct qstr { const char *name; };
struct dentry { struct qstr d_name; struct inode *inode; };
struct fscrypt_str { unsigned char *name; size_t len; };
struct f2fs_dir_entry { int unused; };
struct folio { int unused; };
struct node_info { unsigned blk_addr; };
static int f2fs_encrypted_symlink_inode_operations, f2fs_symlink_inode_operations, f2fs_dblock_aops;
static unsigned assertions, failures, cases;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; \
    if (failures<8) fprintf(stderr,"line %d: %s\n", __LINE__, #x); } } while(0)
static int stage, rollback_error, locked, orphan_count, acquires, instantiated, iputs;
static int deletes, allocations, frees, folio_refs, quota_calls, sync_calls;
static bool encrypted, dirsync, casefold, rolling_back, entry;
static struct mapping mapping;
static struct inode child;
static struct folio folio;
static struct f2fs_dir_entry de;
static struct inode *d_inode(struct dentry *d) { return d->inode; }
static bool f2fs_cp_error(struct f2fs_sb_info *s) { return stage==1 || (rolling_back && rollback_error==1); }
static bool f2fs_is_checkpoint_ready(struct f2fs_sb_info *s) { return stage!=2; }
static int fscrypt_prepare_symlink(struct inode *d,const char *n,size_t l,unsigned b,struct fscrypt_str *out) {
    out->name=encrypted?NULL:(unsigned char *)n;out->len=l+1;return stage==3?-ENOKEY:0;
}
static int f2fs_dquot_initialize(struct inode *i) {
    quota_calls++;
    if (!rolling_back) return stage==4?-EDQUOT:0;
    return ((rollback_error==2 && i!=&child) || (rollback_error==3 && i==&child))?-EDQUOT:0;
}
static struct inode *f2fs_new_inode(struct mnt_idmap *m,struct inode *d,unsigned mode,void *n) {
    if(stage==5)return ERR_PTR(-ENOMEM);
    child=(struct inode){.i_sb=d->i_sb,.i_mapping=&mapping,.i_ino=99,.i_mode=mode,.i_nlink=1,.fresh=true};
    return &child;
}
static void inode_nohighmem(struct inode *i) {}
static void f2fs_lock_op(struct f2fs_sb_info *s,struct f2fs_lock_context *c) { CHECK(!locked++); }
static void f2fs_unlock_op(struct f2fs_sb_info *s,struct f2fs_lock_context *c) { CHECK(--locked==0); }
static int f2fs_add_link(struct dentry *d,struct inode *i) { CHECK(locked==1);entry=stage!=6;return entry?0:-ENOSPC; }
static void f2fs_alloc_nid_done(struct f2fs_sb_info *s,unsigned long ino) {}
static int fscrypt_encrypt_symlink(struct inode *i,const char *n,size_t l,struct fscrypt_str *out) {
    if(stage==7){rolling_back=true;return -ENOKEY;}
    if(encrypted){out->name=calloc(1,out->len);allocations++;}
    return 0;
}
static int page_symlink(struct inode *i,unsigned char *n,size_t l) {
    if(stage==8){rolling_back=true;return -ENOSPC;}return 0;
}
static void unlock_new_inode(struct inode *i) { CHECK(i->fresh);i->fresh=false; }
static void d_instantiate_new(struct dentry *d,struct inode *i) { CHECK(!d->inode);unlock_new_inode(i);d->inode=i;instantiated++; }
static int filemap_write_and_wait_range(struct mapping *m,unsigned a,size_t b) { CHECK(instantiated==1);return stage==9?-EIO:0; }
static int f2fs_sync_fs(struct super_block *s,int wait) { sync_calls++;return stage==10?-EIO:0; }
static void f2fs_balance_fs(struct f2fs_sb_info *s,bool need) { CHECK(!locked); }
static void kfree(void *p) { if(p){frees++;free(p);} }
static struct f2fs_dir_entry *f2fs_find_entry(struct inode *d,const struct qstr *n,struct folio **f) {
    if(rollback_error==4){*f=ERR_PTR(-EIO);return NULL;}
    if(rollback_error==5){*f=NULL;return NULL;}
    CHECK(entry);*f=&folio;folio_refs++;return &de;
}
static int f2fs_acquire_orphan_inode(struct f2fs_sb_info *s) {
    CHECK(locked==1);acquires++;if(rolling_back && rollback_error==6)return -ENOSPC;
    orphan_count++;return 0;
}
static void f2fs_folio_put(struct folio *f,bool lock) { CHECK(f==&folio);CHECK(--folio_refs==0); }
static void f2fs_delete_entry(struct f2fs_dir_entry *e,struct folio *f,struct inode *d,struct inode *i) {
    CHECK(locked==1 && orphan_count==1 && entry);entry=false;i->i_nlink=0;deletes++;f2fs_folio_put(f,false);
}
static void set_sbi_flag(struct f2fs_sb_info *s,int flag) {}
static void d_invalidate(struct dentry *d) { CHECK(!locked && deletes); }
static void clear_nlink(struct inode *i) { i->i_nlink=0; }
static void f2fs_update_inode_page(struct inode *i) { CHECK(locked==1); }
static void f2fs_inode_synced(struct inode *i) {}
static int f2fs_get_node_info(struct f2fs_sb_info *s,unsigned long n,struct node_info *ni,bool c) { ni->blk_addr=1;return 0; }
static void set_inode_flag(struct inode *i,int flag) {}
static void f2fs_add_orphan_inode(struct inode *i) { CHECK(orphan_count==1); }
static void iput(struct inode *i) { CHECK(!locked && !i->fresh && !i->i_nlink);CHECK(orphan_count==1);orphan_count--;iputs++; }
static void reset(void) {
    locked=orphan_count=acquires=instantiated=iputs=deletes=allocations=frees=folio_refs=quota_calls=sync_calls=0;
    rolling_back=entry=false;memset(&child,0,sizeof(child));
}
'''
suffix = r'''
int main(void) {
    struct f2fs_sb_info s={0};struct super_block sb={.sbi=&s,.s_blocksize=4096};s.sb=&sb;
    struct inode dir={.i_sb=&sb,.i_mode=S_IFDIR,.i_nlink=2};
    for(stage=0;stage<=10;stage++) for(rollback_error=0;rollback_error<=6;rollback_error++)
    for(int flags=0;flags<8;flags++) {
        reset();encrypted=flags&1;dirsync=flags&2;casefold=flags&4;
        struct dentry d={.d_name={.name="link"}};
        int r=f2fs_symlink(NULL,&dir,&d,"target");
        int expected[]={0,-EIO,-ENOSPC,-ENOKEY,-EDQUOT,-ENOMEM,-ENOSPC,-ENOKEY,-ENOSPC,-EIO,dirsync?-EIO:0};
        CHECK(r==expected[stage]);CHECK(!locked && !folio_refs && allocations==frees);
        if(stage>=1 && stage<=5){CHECK(!entry && !instantiated && !iputs && !acquires);}
        else if(stage==6){CHECK(!entry && !instantiated && iputs==1 && acquires==1 && !orphan_count);}
        else if(stage==7 || stage==8) {
            if(!rollback_error)CHECK(!entry && !instantiated && iputs==1 && acquires==1 && !orphan_count && deletes==1);
            else CHECK(entry && instantiated==1 && !iputs && !orphan_count && !deletes);
        } else {CHECK(entry && instantiated==1 && !iputs && !acquires && !deletes);}
        CHECK(sync_calls==((stage==0 || stage==10) && dirsync));cases++;
    }
    /* Ordinary unlink remains available to static device-alias consumers. */
    for(stage=0;stage<=10;stage+=10) for(rollback_error=0;rollback_error<=6;rollback_error++) {
        reset();dirsync=casefold=true;rolling_back=entry=true;
        child=(struct inode){.i_sb=&sb,.i_ino=99,.i_mode=S_IFREG,.i_nlink=1};
        struct dentry d={.inode=&child,.d_name={.name="alias"}};
        int r=f2fs_unlink(&dir,&d);
        int errs[]={stage==10?-EIO:0,-EIO,-EDQUOT,-EDQUOT,-EIO,-ENOENT,-ENOSPC};
        CHECK(r==errs[rollback_error]);CHECK(!locked && !folio_refs);
        CHECK(deletes==!rollback_error);cases++;
    }
    printf("%u cases, %u assertions, %u failures\n",cases,assertions,failures);
    return !!failures;
}
'''
variants = {'port': body,
            'lost_writeback_error_control': body.replace('err = filemap_write_and_wait_range', 'ret = filemap_write_and_wait_range'),
            'double_orphan_control': body.replace('add_orphan = false;', 'add_orphan = true;'),
            'missing_entry_success_control': body.replace('PTR_ERR(folio) : -ENOENT', 'PTR_ERR(folio) : 0')}
results = {}
with tempfile.TemporaryDirectory(prefix='f2fs-symlink-') as tmp:
    for name, code in variants.items():
        c, exe = Path(tmp)/(name+'.c'), Path(tmp)/name
        c.write_text(prefix+code+suffix)
        subprocess.run(['cc','-std=gnu11','-Wall','-Werror','-Wno-unused-parameter',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
        r = subprocess.run([str(exe)],capture_output=True,text=True)
        assert (r.returncode==0)==(name=='port'), (name,r.stdout,r.stderr)
        results[name] = {'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
report = {'scope':__doc__+' Models VFS, quota, encryption, storage and orphan operations; no actual filesystem, concurrency, crash recovery or I/O.',
          'source_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'results':results}
(D/'evidence/f2fs-symlink-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(results['port']['stdout'].strip())
print('All three negative controls rejected')
