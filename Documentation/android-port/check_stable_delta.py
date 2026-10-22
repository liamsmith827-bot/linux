#!/usr/bin/env python3
"""Find textual overlaps for semantic review, never infer security equivalence."""
import subprocess,json,re
from pathlib import Path
D=Path(__file__).resolve().parent;r=D.parents[1]
L='2ff600d29ee478d0a8d46ef8a58afb5e038fe692';B='v6.18';A='23112ce1886ea26b19be03207c0227a06a6ca009'
def git(*a):return subprocess.check_output(['git','-C',str(r),*a]).decode(errors='replace')
changed=set(git('diff','--name-only',L,'HEAD','--',':!Documentation/android-port').splitlines())
# Account for the two ACK source renames that matter to this target.
renames={'drivers/net/wireless/virtual/mac80211_hwsim.c':'drivers/net/wireless/virtual/mac80211_hwsim_main.c','rust/kernel/net.rs':'rust/kernel/net.rs'}
changed.update(renames)
patches=git('log','--no-merges','--format=STABLECOMMIT %H %s','--no-renames','-p','-U0',B+'..'+L,'--',*sorted(changed))
previous_path=D/'evidence/full-stable-overlaps.json'
previous_report=json.loads(previous_path.read_text()) if previous_path.exists() else {}
previous={x['commit']:x for x in previous_report.get('overlaps',[])}
cache={};out=[];count=0
for part in re.split(r'^STABLECOMMIT ',patches,flags=re.M)[1:]:
 first,_,patch=part.partition('\n');sha,sub=first.split(' ',1);p=None;lost=[];old_again=[];count+=1
 for line in patch.splitlines():
  if line.startswith('+++ b/'):p=line[6:]
  elif line.startswith('@@'):hunk=line
  elif line.startswith(('+','-')) and not line.startswith(('+++','---')) and p in changed:
   sign=line[0];s=line[1:].strip()
   if len(s)<18 or s.startswith(('*','/*','//')):continue
   if p not in cache:
    lp=git('show',L+':'+p) if (r/p).exists() or p in renames else ''
    cp=r/renames.get(p,p);cur=cp.read_text(errors='replace') if cp.is_file() else ''
    cache[p]=(set(x.strip() for x in lp.splitlines()),set(x.strip() for x in cur.splitlines()))
   if sign=='+' and s in cache[p][0] and s not in cache[p][1]:lost.append({'path':p,'port_path':renames.get(p,p),'hunk':hunk,'line':s})
   if sign=='-' and s not in cache[p][0] and s in cache[p][1]:old_again.append({'path':p,'port_path':renames.get(p,p),'hunk':hunk,'line':s})
 if lost or old_again:
  entry={'commit':sha,'subject':sub,'lts_added_line_absent':lost,'lts_removed_line_present':old_again,'status':'requires semantic review; literal line overlap is not proof of regression'}
  old=previous.get(sha,{})
  if old.get('lts_added_line_absent')==lost and old.get('lts_removed_line_present')==old_again and 'assessment' in old:
   entry.update(status=old['status'],assessment=old['assessment'],assessment_source_head=old.get('assessment_source_head',previous_report.get('port')))
  out.append(entry)
(D/'evidence/full-stable-overlaps.json').write_text(json.dumps({'base':git('rev-parse',B+'^{}').strip(),'lts':L,'port':git('rev-parse','HEAD').strip(),'commits_examined':count,'overlaps':out},indent=2)+'\n')
print('examined',count,'overlapping',len(out))
for x in out:print(x['commit'][:12],len(x['lts_added_line_absent']),len(x['lts_removed_line_present']),x['subject'])
