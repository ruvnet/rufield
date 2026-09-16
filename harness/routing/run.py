"""Test actual pinned RuVector routing sources without its unrelated workspace.

Optionally pass a local routing directory; bytes must match the pinned hashes.
No benchmark numbers from this harness represent full workspace performance.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
REV = 'a55d429117c040adcdc5d17a814230f98ffbd8e2'
hashes = json.loads((ROOT / 'harness/routing/kernel-hashes.json').read_text())
with tempfile.TemporaryDirectory(prefix='rufield-routing-') as tmp:
    out = pathlib.Path(tmp)
    (out / 'src/routing').mkdir(parents=True)
    for name, digest in hashes.items():
        if len(sys.argv) == 2:
            data = (pathlib.Path(sys.argv[1]) / name).read_bytes()
        else:
            url = f'https://raw.githubusercontent.com/ruvnet/RuVector/{REV}/crates/ruvector-mincut/src/routing/{name}'
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(262145)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Pinned kernel checksum mismatch: ' + name)
        (out / 'src/routing' / name).write_bytes(data)
    shutil.copyfile(ROOT / 'harness/routing/contract.rs', out / 'src/lib.rs')
    shutil.copyfile(ROOT / 'crates/rufield-ruvector/tests/fixtures/ruview.json', out / 'src/ruview.json')
    deps = '\n'.join(f'{name} = {{ path = {json.dumps(str(ROOT / "crates" / name))} }}' for name in ['rufield-core','rufield-provenance','rufield-ruvector'])
    (out / 'Cargo.toml').write_text('[package]\nname="routing-contract"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[dependencies]\nserde={version="1",features=["derive"]}\nserde_json="1"\n'+deps+'\n')
    subprocess.run(['cargo','test','--release','--manifest-path',str(out/'Cargo.toml')],check=True)
