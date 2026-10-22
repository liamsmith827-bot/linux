#!/usr/bin/env python3
"""Record artifacts after a completed workflow; verify their detached signatures.

Run only after observing build_virt.sh exit zero, before changing common or
starting another build. This does not execute the build or establish bootability.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('workspace', type=Path)
p.add_argument('log', type=Path)
p.add_argument('--run', required=True)
args = p.parse_args()
root = args.workspace.resolve()
doc = Path(__file__).resolve().parent

def command(*argv, cwd=root, **kwargs):
    return subprocess.check_output(argv, cwd=cwd, **kwargs)

def revision(path):
    return command('git', '-C', str(path), 'rev-parse', 'HEAD').decode().strip()

def sha256(data):
    return hashlib.sha256(data).hexdigest()

execroot = Path(command('tools/bazel', 'info', 'execution_root').decode().strip())
certpath = command('tools/bazel', 'cquery', '--output=files',
                   '--output_groups=certs/signing_key.x509',
                   '//common:kernel_x86_64').decode().strip()
assert len(certpath.splitlines()) == 1
certificate = (execroot / certpath).read_bytes()
marker = b'~Module signature appended~\n'
modules = sorted(root.glob('common_dist/*.ko')) + sorted(root.glob('virt_dist/*.ko'))
assert modules and (root / 'common_dist/bzImage').stat().st_size > 0
assert (root / 'common_dist/bzImage').read_bytes() == (root / 'virt_dist/bzImage').read_bytes()

with tempfile.TemporaryDirectory(prefix='sdk-module-verification-') as tmp:
    tmp = Path(tmp)
    der, pem, sig, data = (tmp / name for name in ('cert.der', 'cert.pem', 'sig.der', 'payload'))
    der.write_bytes(certificate)
    command('openssl', 'x509', '-inform', 'DER', '-in', str(der), '-out', str(pem))
    verify = ['openssl', 'cms', '-verify', '-binary', '-noverify', '-nointern',
              '-inform', 'DER', '-in', str(sig), '-content', str(data),
              '-certfile', str(pem), '-out', '/dev/null']
    for module in modules:
        raw = module.read_bytes()
        assert raw.endswith(marker), module
        footer_end = len(raw) - len(marker)
        footer = raw[footer_end - 12:footer_end]
        assert footer[2] == 2 and footer[3:8] == bytes(5), (module, footer)
        length = int.from_bytes(footer[8:12], 'big')
        signature_end = footer_end - 12
        assert 0 < length < signature_end, module
        sig.write_bytes(raw[signature_end - length:signature_end])
        payload = raw[:signature_end - length]
        data.write_bytes(payload)
        command(*verify, stderr=subprocess.PIPE)
        cms = command('openssl', 'cms', '-cmsout', '-print', '-inform', 'DER', '-in', str(sig)).decode()
        assert re.search(r'algorithm: sha256\b', cms) and not re.search(r'algorithm: sha1\b', cms), module
    # A negative control verifies that signature checking actually reads content.
    modified = bytearray(payload)
    modified[len(modified) // 2] ^= 1
    data.write_bytes(modified)
    negative = subprocess.run(verify, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert negative.returncode != 0, 'Tampered payload unexpectedly accepted'

artifacts = modules + [root / 'common_dist/bzImage', root / 'virt_dist/bzImage']
artifacts += sorted(root.glob('*_dist/*dot_config'))
record = {
    'run': args.run,
    'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'command': 'ARCH=x86_64 common/build_virt.sh',
    'exit_code': 0,
    'linux_commit': revision(root / 'common'),
    'build_dependency_commit': revision(root / 'build/kernel'),
    'manifest_commit': revision(root / '.repo/manifests'),
    'module_counts': {d: sum(m.parent.name == d for m in modules) for d in ('common_dist', 'virt_dist')},
    'signature_trailer_present': {'common_dist': True, 'virt_dist': True},
    'artifact_sha256': {str(a.relative_to(root)): sha256(a.read_bytes()) for a in artifacts},
    'log_sha256': sha256(args.log.read_bytes()),
    'verification_scope': 'Compilation, packaging and signing completed. Distributed modules verified against the exact kernel certificate. No runtime/boot test.',
    'cryptographic_signature_verification': {
        'verified_modules': len(modules), 'digest': 'sha256',
        'certificate_der_sha256': sha256(certificate),
        'openssl_version': command('openssl', 'version').decode().strip(),
        'method': 'openssl cms -verify -binary -noverify -nointern with the exact kernel output certificate; no certificate-chain trust assertion',
        'tampered_payload_rejected': True,
    },
}
output = doc / 'evidence/build-results.json'
report = json.loads(output.read_text()) if output.exists() else {'runs': []}
assert all(r['run'] != args.run for r in report['runs']), 'Run already recorded'
report['runs'].append(record)
output.write_text(json.dumps(report, indent=2) + '\n')
print(f'Recorded {args.run}: verified {len(modules)} modules; tampered control rejected')
