#!/usr/bin/env python3
"""Check extracted dm-user copy helpers across segment boundaries and short user copies."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
s=(D.parents[1]/'drivers/md/dm-user.c').read_text()
def function(n):
 m=re.search(r'^.*\b'+n+r'\([^;{}]*\)\n\{',s,re.M);assert m,n
 return s[m.start():s.index('\n}',m.end())+2]+'\n'
body=function('bio_size')+function('bio_copy_from_iter')+function('bio_copy_to_iter')
prefix=r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
struct bio_vec {unsigned char *bv_page;size_t bv_offset,bv_len;};
struct bvec_iter {unsigned i;};
struct bio {unsigned n;struct bio_vec v[4];struct {size_t bi_size;} bi_iter;int nodata;};
#define bio_has_data(b) (!(b)->nodata && (b)->bi_iter.bi_size)
struct iov_iter {unsigned char data[128];size_t remaining,position,fault;};
#define bio_for_each_segment(vec,b,it) for((it).i=((b)->bi_iter.bi_size && !(b)->n ? (abort(),0):0);(it).i<(b)->n && ((vec)=(b)->v[(it).i],1);(it).i++)
#define iov_iter_count(it) ((it)->remaining)
#define WARN_ON(x) ((void)(x))
static size_t transfer(unsigned char *p,size_t off,size_t len,struct iov_iter *it,int from){
 size_t n=len;if(n>it->remaining)n=it->remaining;
 size_t safe=it->position<it->fault?it->fault-it->position:0;if(n>safe)n=safe;
 if(from)memcpy(p+off,it->data+it->position,n);else memcpy(it->data+it->position,p+off,n);
 it->position+=n;it->remaining-=n;return n;
}
#define copy_page_from_iter(p,o,n,it) transfer(p,o,n,it,1)
#define copy_page_to_iter(p,o,n,it) transfer(p,o,n,it,0)
'''
main=r'''
int main(void){unsigned cases=0,failures=0,checks=0;
 for(int direction=0;direction<2;direction++)for(unsigned count=1;count<=4;count++)for(unsigned offset=0;offset<4;offset++)for(unsigned cap=0;cap<=35;cap++)for(unsigned fault=0;fault<=35;fault++){
  unsigned char pages[4][32];memset(pages,0,sizeof(pages));struct bio b={.n=count};struct iov_iter it={.remaining=cap,.fault=fault};size_t total=0;
  for(unsigned i=0;i<count;i++){b.v[i]=(struct bio_vec){.bv_page=pages[i],.bv_offset=offset,.bv_len=3+i*2};for(unsigned j=0;j<b.v[i].bv_len;j++)pages[i][offset+j]=(unsigned char)(total+j+1);total+=b.v[i].bv_len;}
  b.bi_iter.bi_size=total;
  if(direction)for(unsigned i=0;i<sizeof(it.data);i++)it.data[i]=(unsigned char)(i+71);
  size_t expected=total;if(expected>cap)expected=cap;if(expected>fault)expected=fault;
  ssize_t ret=direction?bio_copy_from_iter(&b,&it):bio_copy_to_iter(&b,&it);
  checks+=3;failures+=ret!=(ssize_t)expected;failures+=it.position!=expected;failures+=it.remaining!=cap-expected;
  size_t index=0;for(unsigned i=0;i<count;i++)for(unsigned j=0;j<b.v[i].bv_len;j++,index++){
   if(index<expected){checks++;failures+=direction?pages[i][offset+j]!=(unsigned char)(index+71):it.data[index]!=(unsigned char)(index+1);}
  }
  cases++;
 }
 for(unsigned op=0;op<3;op++)for(unsigned length=0;length<65536;length+=512){
  struct bio b={.nodata=1,.bi_iter={.bi_size=length}};struct iov_iter it={.remaining=64,.fault=64};
  checks+=5;failures+=bio_size(&b)!=length;failures+=bio_copy_from_iter(&b,&it)!=0;failures+=bio_copy_to_iter(&b,&it)!=0;failures+=it.position!=0;failures+=it.remaining!=64;cases++;
 }
 printf("%u %u %u\n",cases,checks,failures);return !!failures;
}
'''
with tempfile.TemporaryDirectory(prefix='dm-user-copy-') as tmp:
 t=Path(tmp)
 def run(name,b,expected):
  p=t/(name+'.c');exe=t/name;p.write_text(prefix+b+main)
  r=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr
  r=subprocess.run([str(exe)],capture_output=True,text=True);assert (r.returncode==0)==expected,(name,r.stdout,r.stderr);return r.stdout
 output=run('current',body,True)
 old=body.replace('if (ret < bvec.bv_len)\n\t\t\tbreak;','if (ret < bvec.bv_len)\n\t\t\treturn ret;');assert old!=body
 run('drop_preceding_segments',old,False)
 unguarded=body.replace('if (!bio_has_data(bio))\n\t\treturn 0;','');assert unguarded!=body
 run('nodata_vector_dereference',unguarded,False)
 old_size=body.replace('return bio->bi_iter.bi_size;', 'struct bio_vec v; struct bvec_iter it; size_t out=0; bio_for_each_segment(v,bio,it) out+=v.bv_len; return out;')
 run('nodata_length_vector_walk',old_size,False)
counts=list(map(int,output.split()));report={'cases':counts[0],'assertions':counts[1],'failures':counts[2],'extracted_sha256':hashlib.sha256(body.encode()).hexdigest(),'negative_controls_rejected':['drop_preceding_segments','nodata_vector_dereference','nodata_length_vector_walk'],'scope':__doc__+' User-copy fault locations and lengths are modeled; no real page faults, IOV pinning or block I/O.'};(D/'evidence/dm-user-copy-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
