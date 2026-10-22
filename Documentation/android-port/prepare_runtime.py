#!/usr/bin/env python3
"""Prepare, but do not apply, a scoped three-way runtime port for review."""
import json
import os
import subprocess
from inventory import HERE, ROOT, LINUX, LTS, git

BASE = '5366199be46fb53de62861721d34ba816e7e440e'
normalized = json.loads((HERE/'evidence/ack-normalization.json').read_text())['normalized_commit']
paths = git(LINUX, 'diff', '--name-only', BASE, normalized).splitlines()
core = ('block/', 'fs/', 'include/', 'init/', 'kernel/', 'mm/', 'net/', 'rust/', 'security/')
drivers = ('drivers/android/', 'drivers/base/', 'drivers/block/zram/',
           'drivers/dma-buf/', 'drivers/md/', 'drivers/net/wireless/virtual/',
           'drivers/staging/android/', 'drivers/thermal/', 'drivers/usb/gadget/')
explicit = {'arch/Kconfig', 'drivers/cpufreq/Kconfig', 'drivers/cpufreq/Makefile',
            'drivers/cpufreq/cpufreq.c', 'drivers/cpufreq/cpufreq_times.c',
            'drivers/cpufreq/freq_table.c', 'drivers/cpufreq/dummy-cpufreq.c',
            'drivers/misc/Kconfig', 'drivers/misc/Makefile', 'drivers/misc/uid_sys_stats.c',
            'drivers/staging/Kconfig', 'drivers/staging/Makefile', 'drivers/tty/sysrq.c',
            'drivers/char/random.c', 'lib/Kconfig.debug', 'lib/bug.c', 'lib/nmi_backtrace.c',
            'scripts/Makefile.build', 'scripts/Makefile.compiler', 'scripts/Makefile.lib',
            'scripts/Makefile.kasan', 'scripts/headers_install.sh'}
excluded = {
    # Retain LTS tracing implementation and its complete failure-path fixes.
    'kernel/trace/fprobe.c', 'include/linux/android_kabi.h',
    # No old KMI wrapper around the upstream networking fix.
    'include/linux/skmsg.h',
}
excluded_terms = ('pkvm', 'gunyah', 'geniezone', 'fips140', 'pkvm_', 'hyp_')
selected=[]
for p in paths:
    if p in excluded or any(x in p for x in excluded_terms): continue
    take = p.startswith(core + drivers) or p in explicit
    # Generic graphics core and virtual display drivers, not physical GPUs.
    if p.startswith('drivers/gpu/drm/'):
        tail = p.removeprefix('drivers/gpu/drm/')
        take = '/' not in tail or tail.startswith(('ttm/', 'virtio/', 'tests/'))
    # Test sources packaged by the original SDK kernel build.
    if p.startswith(('tools/testing/selftests/filesystems/incfs/',
                     'tools/testing/selftests/filesystems/fuse/',
                     'tools/testing/selftests/drivers/wrapfd/',
                     'tools/testing/selftests/android/',
                     'tools/testing/kunit/android/')):
        take = True
    if take: selected.append(p)

env=dict(os.environ,GIT_INDEX_FILE=str(ROOT/'sdk-runtime.index'))
def run(*args,input=None):
    return subprocess.run(['git','-C',str(LINUX),*args],input=input,capture_output=True,env=env)
assert run('read-tree',BASE).returncode==0
patch=run('diff','--binary',BASE,normalized,'--',*selected).stdout
r=run('apply','--cached',input=patch)
assert r.returncode==0,r.stderr
tree=run('write-tree').stdout.strip().decode()
candidate=run('commit-tree',tree,'-p',BASE,input=b'analysis: scoped Android runtime delta for SDK review\n').stdout.strip().decode()
merged=run('merge-tree','--write-tree','--messages',LTS,candidate)
(HERE/'evidence/scoped-runtime-merge.txt').write_bytes(merged.stdout)
(HERE/'evidence/scoped-runtime-paths.json').write_text(json.dumps({
    'status':'proposed, not yet applied or fully reviewed', 'normalized_input':normalized,
    'candidate':candidate,'merge_tree':merged.stdout.decode().splitlines()[0],
    'selected':selected,'excluded':[p for p in paths if p not in selected],
},indent=2)+'\n')
print('Proposed paths',len(selected),'merge conflicts',merged.stdout.count(b'CONFLICT ('),
      'tree',merged.stdout.decode().splitlines()[0])
