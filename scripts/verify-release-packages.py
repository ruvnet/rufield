#!/usr/bin/env python3
"""Verify all ten release archives include the same accessible animated SVG."""
import argparse,hashlib,tarfile,tomllib
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument("directory",type=Path)
a=p.parse_args()
root=Path(__file__).resolve().parents[1]
expected=(root/"docs/assets/rufield-rf-observatory.svg").read_bytes()
names=tomllib.loads((root/"Cargo.toml").read_text())["workspace"]["members"]
lines=[]
for member in names:
 name=Path(member).name
 archive=a.directory/(name+"-0.2.0.crate")
 with tarfile.open(archive) as t:
  prefix=name+"-0.2.0/"
  assert t.extractfile(prefix+"assets/rufield-rf-observatory.svg").read()==expected,name
  assert t.extractfile(prefix+"README.md").read(),name
  manifest=tomllib.loads(t.extractfile(prefix+"Cargo.toml").read().decode())
  assert manifest["package"]["version"]=="0.2.0",name
 lines.append(hashlib.sha256(archive.read_bytes()).hexdigest()+"  "+archive.name)
 print("PASS",archive.name,"README, SVG and version")
(a.directory/"SHA256SUMS").write_text("\n".join(lines)+"\n")
