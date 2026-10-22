import subprocess,json,re,collections,sys
from pathlib import Path
D=Path('Documentation/android-port'); A='23112ce1886ea26b19be03207c0227a06a6ca009';L='2ff600d29ee478d0a8d46ef8a58afb5e038fe692';N='b440e75ff4b8f13c673c304be8e148af110f274d'
def tree(ref):
 return {l.split('\t',1)[1]:l.split('\t')[0].split()[2] for l in subprocess.check_output(['git','ls-tree','-r',ref]).decode().splitlines()}
a,l,n,c=map(tree,[A,L,N,'HEAD']);base=tree('5366199be46fb53de62861721d34ba816e7e440e');rows=[json.loads(s) for s in (D/'candidates.jsonl').read_text().splitlines()]
ps=sorted({p for r in rows for p in r['files']});out={};unknown=[]
blob_cache={}
def nonblank_blob(oid):
 if oid not in blob_cache:
  content=subprocess.check_output(['git','cat-file','blob',oid]) if oid else b''
  blob_cache[oid]=b'\n'.join(line.rstrip() for line in content.splitlines() if line.strip())
 return blob_cache[oid]
def omitted(p):
 if p.startswith('drivers/android/debug_kinfo'):return 'physical-device'
 if p=='kernel/irq/irqdomain.c':return 'lts-native-source-api'
 if p in ('drivers/pci/pci-acpi.c','drivers/pci/probe.c','drivers/thunderbolt/tb.c'):return 'physical-device'
 if p in ('drivers/pci/pci.h','mm/memory_hotplug.c') or p.startswith('kernel/time/'):return 'lts-native-source-api'
 if p in {x['header'] for x in json.loads((D/'evidence/hook-platform-pruning.json').read_text())}:return 'physical-device'
 if p.endswith('TEST_MAPPING'):return 'build-test-metadata'
 if re.search(r'(^|/)(abi_gki[^/]*|abi\.stg|abi\.xml)$',p) or re.search(r'^gki/[^/]+/symbols/',p) or p.startswith(('android/abi','android/kabi')) or p=='include/linux/android_kabi.h':return 'historical-kmi'
 if re.match(r'arch/(?!x86/)[^/]+/',p) or re.match(r'lib/(crypto|crc)/(arm|arm64)/',p):return 'other-architecture'
 if any(t in p for t in ['pkvm','gunyah','geniezone','gzvm','hyp-trace','microdroid','crashdump']):return 'protected-virtualization'
 if p.startswith(('arch/x86/kvm/','arch/x86/coco/','virt/kvm/','drivers/iommu/','drivers/virt/','include/kvm/','drivers/vfio/','Documentation/virt/')):return 'protected-virtualization'
 if p.startswith(('crypto/','lib/crypto/','include/crypto/','scripts/crypto/','arch/x86/crypto/','lib/raid6/')):return 'lts-crypto'
 if p.startswith(('fs/','block/','drivers/md/')) or p in ('include/linux/fsverity.h','include/uapi/linux/f2fs.h','include/linux/netfs.h','mm/mempool.c','include/linux/mempool.h'):return 'lts-filesystem-storage'
 if p.startswith(('kernel/trace/','include/trace/events/')) or p in ('include/linux/ring_buffer.h','include/linux/trace_printk.h','include/linux/kernel.h'):return 'lts-tracing'
 if p.startswith(('net/','kernel/bpf/','include/net/','include/linux/net','include/linux/bpf','include/linux/skmsg','include/linux/ieee80211')):return 'lts-networking'
 if p.startswith(('drivers/base/','include/linux/device','include/linux/fwnode','drivers/of/','drivers/i2c/i2c-core-of','drivers/net/phy/mdio_bus_provider','drivers/bus/imx-weim','drivers/spi/spi.c')):return 'lts-device-core'
 if p.startswith(('drivers/gpu/drm/','include/drm/','include/uapi/drm/')):return 'lts-graphics'
 if p.startswith(('drivers/gpu/drm/','include/drm/','include/uapi/drm/','sound/','include/sound/','drivers/ufs/','include/ufs/','include/dt-bindings/','Documentation/devicetree/','drivers/accel/','drivers/pci/controller/','drivers/irqchip/','drivers/pinctrl/','drivers/soc/','include/linux/soc/','drivers/platform/','drivers/pmdomain/','drivers/usb/typec/','drivers/usb/host/','drivers/usb/dwc3/','drivers/clk/','drivers/clocksource/','drivers/regulator/','drivers/power/supply/','drivers/remoteproc/','drivers/gpio/','drivers/interconnect/','drivers/misc/mei/','drivers/amba/','drivers/acpi/','drivers/perf/','drivers/hwtracing/','drivers/iio/','drivers/mfd/','drivers/mmc/','drivers/extcon/','drivers/firmware/','drivers/scsi/','drivers/nvme/','drivers/net/ethernet/','drivers/net/wireless/','drivers/staging/','drivers/xen/','drivers/media/','drivers/hid/','drivers/cpufreq/','drivers/cpuidle/cpuidle-psci','drivers/tty/serial/','drivers/tty/hvc/hvc_dcc','drivers/misc/open-dice','drivers/usb/gadget/function/f_midi')):return 'physical-device'
 if p.startswith(('arch/x86/events/','arch/x86/kernel/fpu/','arch/x86/mm/','arch/x86/kernel/','arch/x86/include/')) or p in ('arch/x86/Makefile','arch/x86/Kconfig'):return 'lts-x86-platform'
 if p.startswith(('drivers/virtio/','drivers/block/null_blk/')):return 'lts-virtual-io'
 if p.startswith(('include/','rust/kernel/block/')):return 'lts-native-source-api'
 if p.startswith(('tools/','Documentation/','samples/','scripts/','bazel/','gki/','android/','build.config','arch/x86/configs/')) or p.endswith(('TEST_MAPPING','Kconfig')) or p in ('MAINTAINERS','OWNERS','README.md','.mailmap','.gitignore','.clang-format','BUILD.bazel','Makefile'):return 'build-test-metadata'
 if p.startswith('rust/'):return 'lts-rust-api'
 return None
for p in ps:
 x={'ack_blob':a.get(p),'lts_blob':l.get(p),'port_blob':c.get(p)}
 if a.get(p)==l.get(p): x['policy']='no-final-ack-delta'
 elif c.get(p)!=l.get(p):x['policy']='ported-net-source'
 elif n.get(p)==base.get(p):x['policy']='no-normalized-ack-delta'
 elif nonblank_blob(n.get(p))==nonblank_blob(base.get(p)):x['policy']='no-substantive-normalized-ack-delta'
 elif nonblank_blob(n.get(p))==nonblank_blob(l.get(p)):x['policy']='normalized-matches-lts'
 else:
  x['policy']=omitted(p)
  if x['policy'] is None:unknown.append(p)
 out[p]=x
(D/'evidence/path-review.json').write_text(json.dumps(out,indent=2)+'\n')
print(collections.Counter(x['policy'] for x in out.values()))
print('UNRESOLVED:\n'+'\n'.join(unknown))

# Complete rows using the reviewed path decisions, not a consumer-search heuristic.
# The initial candidate inventory and exact patch-equivalence evidence remain intact.
from inventory import render
from policy_text import POLICIES
assert not unknown, unknown
head=subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()
history=subprocess.check_output(['git','log','--format=@@%H','--name-only','--no-renames',L+'..HEAD']).decode()
result_ids=collections.defaultdict(list)
for line in history.splitlines():
 if line.startswith('@@'): sha=line[2:]
 elif line: result_ids[line].append(sha)
for p,x in out.items():
 x['rationale']=POLICIES[x['policy']]
 x['result_commits']=result_ids[p] if x['policy']=='ported-net-source' else []
 if x['policy']=='ported-net-source':assert x['result_commits'],p
 x['normalized_ack_blob']=n.get(p)
 x['common_ancestor_blob']=base.get(p)
 if x['policy']=='other-architecture':
  x['specific_evidence']='The verified SDK build selects CONFIG_X86_64=y and CONFIG_X86=y. Makefile maps ARCH=x86_64 to SRCARCH=x86 and selects arch/$(SRCARCH) headers/build rules; lib/crypto/Makefile and lib/crc/Makefile select the same architecture directory. This path belongs to another architecture and remains exactly at pinned LTS. Its ACK changes are excluded by the current-target requirement, including any architecture-local merge resolution. Generic shared paths are reviewed separately. See evidence/build-results.json, attempt 22.'
  x['review_record']='SECURITY.md: Architecture-only exclusions'
 if x['policy']=='historical-kmi':
  x['specific_evidence']='This path is an Android historical ABI/KMI symbol inventory, layout artifact or compatibility helper. The user excludes historical vendor-binary KMI; use native LTS layouts and rebuilt modules. The unchanged public emulator workflow runs without ABI enforcement or trimming. The virtual-device mixed-build staging import list is separately retained and adapted, so it is not covered by this exclusion.'
  x['review_record']='SECURITY.md: historical KMI and module compatibility'
# Reviewed specific evidence prevents broad policy names from hiding source differences.
notes={
 'kernel/time/posix-cpu-timers.c':'LTS also has timer_lock_sighand; keep newer expiry-list retry, timer deletion on nanosleep error, and 64-bit rlimit multiplication.',
 'kernel/time/alarmtimer.c':'The residual ACK difference is an inaccurate Return documentation comment on a void callback; the bool rearm/arm implementation is already LTS.',
 'kernel/time/timer_migration.c':'Remote expiry fix already exists in LTS; keep later kfree(stack) on the invalid-hierarchy error path.',
 'mm/memory_hotplug.c':'Altmap error cleanup is already LTS; retain later enum mmop typing and free_area_init_core_hotplug failure handling.',
 'drivers/pci/pci-acpi.c':'Microsoft DmaProperty support is for external/untrusted physical devices. No physical device assignment is enabled for this ordinary SDK guest.',
 'drivers/pci/probe.c':'The new hook controls DT-created PCI power-supply platform devices. The SDK ACPI/virtio guest does not use that DT power-control path; generic PCI power hooks are retained in pci.c.',
 'drivers/pci/pci.h':'Retain newer LTS PCI helpers and signatures, not older ACK-private declarations.',
 'drivers/base/firmware_loader/fallback.c':'LTS has the same fw_state_is_done early check before pending-list insertion; difference is a blank line.',
 'fs/crypto/keysetup.c':'Both trees retain the multiple-data-unit-size key setup fix; LTS uses kzalloc_obj instead of the older explicit-size allocator.',
 'kernel/bpf/cgroup.c':'The size-gated query.revision copy and uattr_size propagation are already in LTS.',
 'include/linux/hid.h':'Native LTS report buffer size argument and 16-bit hat fields replace the historical wrapper/narrow layout; android_f_accessory uses the native API.',
 'drivers/virtio/virtio_balloon.c':'Local packages/modules/Virtualization/guest/microdroid_manager/src/main.rs set_bail_on_out_of_puff names the separate Microdroid guest consumer. Its protected guest memory ABI is not the SDK guest ABI.',
 'rust/kernel/net/mod.rs':'The selected netlink abstraction is implemented in rust/kernel/net.rs and rust/kernel/net/netlink.rs; 8dca59f73173 resolves the conflicting module paths.',
}
for p,note in notes.items():
 if p in out:out[p]['specific_evidence']=note
for p,review in json.loads((D/'evidence/native-api-review.json').read_text()).items():
 if p in out:
  out[p]['specific_evidence']=review['rationale']
  out[p]['review_record']='evidence/native-api-review.json'
for p,review in json.loads((D/'evidence/generic-source-review.json').read_text()).items():
 if p in out:
  out[p]['specific_evidence']=review['rationale']
  out[p]['review_record']='evidence/generic-source-review.json'
(D/'evidence/path-review.json').write_text(json.dumps(out,indent=2)+'\n')
kmi={x['commit']:x for x in json.loads((D/'evidence/kmi-revert-candidates.json').read_text())}
merge_patches=(D/'evidence/merge-resolutions.patch').read_text()
import hashlib
merge_evidence={}
for part in re.split(r'^MERGE ',merge_patches,flags=re.M)[1:]:
 sha=part.splitlines()[0].split()[0]
 merge_evidence[sha]={'patch_sha256':hashlib.sha256(part.encode()).hexdigest(),'hunks':len(re.findall(r'^@@',part,re.M))}
for r in rows:
 sha=r['commit'];fs=r['files'];groups=collections.defaultdict(list)
 for p in fs:groups[out[p]['policy']].append(p)
 r['path_policies']={k:v for k,v in sorted(groups.items())}
 r['code_review_head']=head
 if len(r['parents'])>1 and fs:
  assert sha in merge_evidence,sha
  r['merge_resolution_review']={**merge_evidence[sha], 'path_policies':r['path_policies'], 'hunk_evidence':'evidence/merge-hunk-examination.json: '+sha, 'method':'Unique resolution delta from git --remerge-diff, not first-parent changes; reconcile each resolution path through its final ACK state and reviewed port policy. Both parents are independently inventoried.'}
 if sha in kmi:
  r.update(disposition='omitted-kmi-only',rationale='The local commit message explicitly reverts an upstream change because it breaks the Android kernel ABI. That reason is excluded by the user. Retain the LTS fix/native layout; do not replay this revert. Source effects are covered by normalization, explicit LTS restorations and the per-path evidence.',result_commits=[])
  ev='evidence/kmi-revert-candidates.json: '+sha
  if ev not in r['evidence']:r['evidence'].append(ev)
 elif r['disposition']=='pending' or r.get('net_reconciled'):
  active='ported-net-source' in groups
  equivalent={'no-final-ack-delta','no-normalized-ack-delta','no-substantive-normalized-ack-delta','normalized-matches-lts'}
  omitted=any(k not in equivalent|{'ported-net-source'} for k in groups)
  if active: disposition='partially-adapted-net-state' if omitted else 'adapted-net-state'
  elif set(groups)<=equivalent:disposition='superseded-no-residual-code'
  elif set(groups)<=equivalent|{'physical-device','other-architecture','protected-virtualization','build-test-metadata','historical-kmi'}:disposition='omitted-current-target'
  else:disposition='reconciled-to-lts'
  if len(r['parents'])>1:disposition='merge-resolution-'+disposition
  r['disposition']=disposition;r['net_reconciled']=True
  r['rationale']=' '.join(k+': '+POLICIES[k] for k in sorted(groups))
  r['result_commits']=sorted({q for p in fs for q in out[p]['result_commits']}) if active else []
  ev='evidence/path-review.json: exact ACK/LTS/port blobs and reviewed policy for every path in this row; SECURITY.md; evidence/conflict-decisions.json; evidence/lts-line-overlaps.json'
  if ev not in r['evidence']:r['evidence'].append(ev)
# Whole-commit application where the code genuinely matches that commit.
for r in rows:
 if r['commit'].startswith('79f0b44406ff'):
  r.update(disposition='applied',rationale='The SDK uses virtio-block. Null vqs after free on init failure and freeze to prevent double-free after failed resume. This fix is absent from pinned LTS; cherry-pick applies while retaining newer LTS zone limits.',result_commits=[subprocess.check_output(['git','rev-parse','2d970aadc952']).decode().strip()])
  r.pop('net_reconciled',None)
# Reviewed overrides concern the actual patch, not just the subsystem it touched.
code_decisions=D/'evidence/explicit-code-decisions.json'
if code_decisions.exists():
 for d in json.loads(code_decisions.read_text()):
  r=next(r for r in rows if r['commit']==d['commit'])
  r.update({k:v for k,v in d.items() if k!='commit'})
  r.pop('net_reconciled',None)
  r.pop('final_net_review',None)
  ev='evidence/explicit-code-decisions.json: '+r['commit']
  if ev not in r['evidence']:r['evidence'].append(ev)
explicit=json.loads((D/'evidence/explicit-kmi-decisions.json').read_text())
for d in explicit:
 r=next(r for r in rows if r['commit']==d['commit'])
 r.update({k:v for k,v in d.items() if k!='commit'})
 r.pop('net_reconciled',None)
for r in rows:
 if r['disposition']=='omitted-kmi-only' and 'gki/x86_64/symbols/virtual_device' in r['files']:
  r.update(disposition='adapted-build-metadata',rationale='Historical ABI enforcement is omitted. The x86 virtual-device symbol list is adapted for the unchanged mixed-build staging import check, with 16 native LTS imports added in 4a8a3df378ad. Trimming and strict ABI enforcement are disabled; no historical signature, layout or symbol CRC is promised.',result_commits=result_ids['gki/x86_64/symbols/virtual_device'])
 r['review_status']='draft-net-reconciliation' if r.get('net_reconciled') else 'reviewed'
# A separately reviewed net decision is final only while every source witness
# still matches. Later integration must not silently inherit stale completion.
completed_path=D/'evidence/final-net-decisions.json'
if completed_path.exists():
 completed={x['commit']:x for x in json.loads(completed_path.read_text())['decisions']}
 for r in rows:
  decision=completed.get(r['commit'])
  if not decision or not r.get('net_reconciled'):continue
  valid=set(decision['path_witnesses'])==set(r['files']) and all(
   all(out[p].get(k)==v for k,v in witness.items())
   for p,witness in decision['path_witnesses'].items())
  if valid and decision['disposition']==r['disposition']:
   r['review_status']='reviewed'
   r['final_net_review']={'source_head':decision['source_head'],'method':decision['method']}
   ev='evidence/final-net-decisions.json: '+r['commit']
   if ev not in r['evidence']:r['evidence'].append(ev)
  else:
   r.pop('final_net_review',None)
text_completed_path=D/'evidence/final-text-presence-decisions.json'
if text_completed_path.exists():
 report=json.loads(text_completed_path.read_text())
 completed={x['commit']:x for x in report['decisions']}
 for r in rows:
  r.pop('final_text_review',None)
  decision=completed.get(r['commit'])
  if not decision or not r.get('net_reconciled'):continue
  if set(decision['path_witnesses'])!=set(r['files']):continue
  if not all(all(out[p].get(k)==v for k,v in witness.items())
             for p,witness in decision['path_witnesses'].items()):continue
  r.update(disposition='already-represented-upstream',review_status='reviewed',
           rationale='The complete post-change textual patch is present in both pinned LTS and the port, verified by reverse-apply checks against temporary committed-tree indexes. No additional application is required. This is code-presence evidence, not a claim of identical upstream commit identity or runtime validation. For a deletion/revert, it establishes that the removed text is absent at the matching surrounding code. Later unrelated edits remain in place.',result_commits=[])
  r['final_text_review']={'source_head':report['source_head'],'patch_sha256':decision['patch_sha256'],'method':report['method']}
  ev='evidence/final-text-presence-decisions.json: '+r['commit']
  if ev not in r['evidence']:r['evidence'].append(ev)
# Configuration-only reviews cover the changed settings, not unrelated kernel
# implementations or other settings in the same defconfig. Whole-file witnesses
# invalidate the review conservatively if either selected configuration changes.
config_completed_path=D/'evidence/final-config-decisions.json'
if config_completed_path.exists():
 report=json.loads(config_completed_path.read_text())
 completed={x['commit']:x for x in report['decisions']}
 for r in rows:
  r.pop('final_config_review',None)
  decision=completed.get(r['commit'])
  if not decision or not r.get('net_reconciled'):continue
  if set(decision['path_witnesses'])!=set(r['files']):continue
  if not all(all(out[p].get(k)==v for k,v in witness.items())
             for p,witness in decision['path_witnesses'].items()):continue
  r.update(disposition=decision['disposition'],review_status='reviewed',
           rationale=decision['rationale'],result_commits=decision['result_commits'])
  r['final_config_review']={'source_head':report['source_head'],
                           'keys':decision['keys'],
                           'patch_sha256':decision['patch_sha256']}
  ev='evidence/final-config-decisions.json: '+r['commit']
  if ev not in r['evidence']:r['evidence'].append(ev)
assert len(rows)==11731
assert all(r['disposition']!='pending' and r['rationale'] for r in rows)
(D/'candidates.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows));render(rows)
(D/'evidence/decision-counts.json').write_text(json.dumps(dict(collections.Counter(r['disposition'] for r in rows)),indent=2)+'\n')
reviewed = [r for r in rows if r['review_status'] == 'reviewed']
progress = {
 'source_head': head,
 'candidate_count': len(rows),
 'finalized_count': len(reviewed),
 'provisional_count': len(rows) - len(reviewed),
 'finalized_percent': round(100 * len(reviewed) / len(rows), 2),
 'metric': 'Finalized candidate dispositions, including justified omissions, upstream representation and merge resolutions. This is not a percentage of code lines ported or runtime compatibility verified.',
 'finalized_dispositions': dict(collections.Counter(r['disposition'] for r in reviewed)),
 'provisional_dispositions': dict(collections.Counter(r['disposition'] for r in rows if r['review_status'] != 'reviewed')),
}
(D/'evidence/progress.json').write_text(json.dumps(progress, indent=2)+'\n')
print('Decisions:',collections.Counter(r['disposition'] for r in rows))
