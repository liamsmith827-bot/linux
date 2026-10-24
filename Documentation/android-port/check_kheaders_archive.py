#!/usr/bin/env python3
"""Run the actual archive generator with symlinked headers and an LTS control.

Temporary source/object trees model Kleaf inputs. This does not execute a module,
test make's incremental dependency handling, or certify whole-build reproducibility.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def main():
    source = (ROOT/'kernel/gen_kheaders.sh').read_bytes()
    native = subprocess.check_output(['git','show',LTS+':kernel/gen_kheaders.sh'],cwd=ROOT)
    results = []
    with tempfile.TemporaryDirectory(prefix='kheaders-audit-') as td:
        base = Path(td)
        src = base/'src'
        obj = base/'obj'
        for p in [src/'include', obj/'include/generated', obj/'kernel']:
            p.mkdir(parents=True)
        (src/'include/direct.h').write_text('/* SPDX-License-Identifier: GPL-2.0 */\n/* remove me */\n#define SOURCE 1\n')
        (src/'include/relative.h').symlink_to('direct.h')
        (src/'include/absolute.h').symlink_to(src/'include/direct.h')
        generated = base/'generated.h'
        generated.write_text('/* remove me */\n#define GENERATED 2\n')
        (obj/'include/generated/autoconf.h').symlink_to(generated)
        (obj/'include/generated/version.h').write_text('#define VERSION 3\n')
        srclist = obj/'kernel/srclist'
        objlist = obj/'kernel/objlist'
        srclist.write_text(''.join(str(src/'include'/n)+'\n' for n in ['direct.h','relative.h','absolute.h']))
        objlist.write_text('include/generated/autoconf.h\ninclude/generated/version.h\n')
        env = dict(os.environ, srctree=str(src), TAR='tar', XZ='xz')
        for label, script in [('port-first',source),('port-repeat',source),('native-control',native)]:
            scriptpath = base/(label+'.sh')
            scriptpath.write_bytes(script)
            archive = obj/'kernel/headers.tar.xz'
            subprocess.run(['sh',str(scriptpath),'kernel/headers.tar.xz',str(srclist),str(objlist),'@1700000000'],cwd=obj,env=env,check=True,capture_output=True)
            data = archive.read_bytes()
            with tarfile.open(fileobj=io.BytesIO(data),mode='r:xz') as tf:
                entries = tf.getmembers()
                headers = [m for m in entries if m.name.endswith('.h')]
                links = [m.name for m in headers if m.issym() or m.islnk()]
                modes = {m.mode for m in headers if m.isfile()}
                content = {m.name:tf.extractfile(m).read().decode() for m in headers if m.isfile()}
                assert len(headers)==5
                assert all(m.uid==0 and m.gid==0 and m.mtime==1700000000 for m in entries)
                assert modes=={0o644}
                if label.startswith('port'):
                    assert not links
                    assert all('remove me' not in b for b in content.values())
                    assert sum('SPDX-License-Identifier' in b for b in content.values())==3
                    assert sum('#define SOURCE 1' in b for b in content.values())==3
                    assert '#define GENERATED 2' in content['./include/generated/autoconf.h']
                else:
                    assert len(links)==3
            dep=(obj/'kernel/.headers.tar.xz.d').read_text()
            assert 'include/generated/autoconf.h' not in dep
            assert 'include/generated/version.h' in dep
            results.append(dict(run=label,script_sha256=sha(script),archive_sha256=sha(data),header_count=len(headers),link_members=links,regular_header_modes=sorted(modes),normalized_owner_and_timestamp=True))
            # Change input timestamps and permissions: output metadata remains fixed.
            for p in [src/'include/direct.h',generated,obj/'include/generated/version.h']:
                os.utime(p,(1800000000,1800000000))
                p.chmod(0o600)
        assert results[0]['archive_sha256']==results[1]['archive_sha256']
    output=dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),runs=results,scope=__doc__,remote_sources_used=[])
    (ROOT/'Documentation/android-port/evidence/kheaders-archive-check.json').write_text(json.dumps(output,indent=2)+'\n')
    print('Five headers materialized; changed-input-metadata repeat identical; native control retains three symlinks.')

if __name__=='__main__':
    main()
