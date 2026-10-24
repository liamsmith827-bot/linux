#!/usr/bin/env python3
"""Exercise extracted UVC fallback with modeled vb2 failure/ownership states.

No real videobuf2 allocation, DMA, mappings or V4L2 ioctls are executed.
"""
import hashlib,json,subprocess,tempfile
from pathlib import Path
from check_scx_donor_retry import function
ROOT=Path(__file__).resolve().parents[2]
OLD='98b3d1d421be044e2d77c35d75c7841cc6fd76f3'
PRE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
struct vb2_queue { int mem_ops;unsigned buffers;bool streaming; };
struct uvc_video_queue { struct vb2_queue queue;bool use_sg; };
struct v4l2_requestbuffers { unsigned count,memory; };
#define V4L2_MEMORY_MMAP 1
#define UVC_TRACE_IOCTL 0
#define uvc_trace(...) ((void)0)
static const int vb2_vmalloc_memops=2;
static int first_result,retry_result,calls;
static unsigned vb2_get_num_buffers(struct vb2_queue *q) { return q->buffers; }
static bool vb2_is_streaming(struct vb2_queue *q) { return q->streaming; }
static int vb2_reqbufs(struct vb2_queue *q,struct v4l2_requestbuffers *r) {
 calls++;assert(calls<=2);int ret=calls==1?first_result:retry_result;
 if(!ret && r->count)r->count=4;
 return ret;
}
'''
# mem_ops is an actual pointer in extracted code.
PRE=PRE.replace('int mem_ops;','const int *mem_ops;')
MAIN=r'''
int main(void) {
 int results[]={0,-ENOMEM,-EBUSY,-EINVAL,-EIO};int checks=0,policy_errors=0,live_allocator_changes=0;
 for(int e=0;e<5;e++)for(int sg=0;sg<2;sg++)for(int count=0;count<2;count++)
 for(int mem=1;mem<=3;mem++)for(int bufs=0;bufs<2;bufs++)for(int stream=0;stream<2;stream++)for(int again=0;again<2;again++) {
  int sgops=1;struct uvc_video_queue q={.queue={.mem_ops=&sgops,.buffers=bufs,.streaming=stream},.use_sg=sg};
  struct v4l2_requestbuffers rb={.count=count,.memory=mem};
  first_result=results[e];retry_result=again?-ENOMEM:0;calls=0;
  bool fallback=first_result==-ENOMEM && sg && count && mem==V4L2_MEMORY_MMAP && !bufs && !stream;
  int ret=uvcg_alloc_buffers(&q,&rb);checks++;
  int final_result=fallback?retry_result:first_result;
  int expected=final_result?final_result:(count?4:0);
  if(ret!=expected || calls!=(fallback?2:1) || q.use_sg!=(fallback?false:sg) || (q.queue.mem_ops!=&sgops)!=fallback)policy_errors++;
  if((bufs || stream) && q.queue.mem_ops!=&sgops)live_allocator_changes++;
 }
 printf("{\"checks\":%d,\"fallback_policy_errors\":%d,\"allocator_changes_with_live_buffers_or_stream\":%d}\n",checks,policy_errors,live_allocator_changes);
 return 0;
}
'''
def run(ref):
    p='drivers/usb/gadget/function/uvc_queue.c'
    src=(ROOT/p).read_text() if ref=='working-tree' else subprocess.check_output(['git','show',ref+':'+p],cwd=ROOT,text=True)
    code=PRE+function(src,'uvcg_alloc_buffers')+MAIN
    with tempfile.TemporaryDirectory(prefix='uvc-allocator-') as td:
        c=Path(td)/'check.c';e=Path(td)/'check';c.write_text(code)
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-parameter','-Wno-unused-function',str(c),'-o',str(e)],check=True)
        result=json.loads(subprocess.check_output([str(e)],text=True))
    return dict(source=ref,extracted_model_sha256=hashlib.sha256(code.encode()).hexdigest(),**result)
if __name__=='__main__':
    old=run(OLD);current=run('working-tree')
    assert current['fallback_policy_errors']==current['allocator_changes_with_live_buffers_or_stream']==0
    assert old['fallback_policy_errors']>0 and old['allocator_changes_with_live_buffers_or_stream']>0
    report=dict(scope=__doc__,old=old,current=current,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/uvc-allocator-fallback-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
