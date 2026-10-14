#!/usr/bin/env python3
"""Synthetic C producer -> RuView validator -> RuField replay and analyzer."""
import argparse,json,os,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--ruview",type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[1]
target=Path(os.environ.get("CARGO_TARGET_DIR",root/"target"))/"debug"
bridge=a.ruview.resolve()/"tools/w1700k"
def run(args,**kw):
 return subprocess.run([str(x) for x in args],capture_output=True,check=True,timeout=30,**kw)
run(["python3",bridge/"verify_integration.py","--rufield-bin",target/"rf-diagnostics-replay"])
with tempfile.TemporaryDirectory() as tmp:
 for scenario in ("normal","gap","event","flat","tag","badkind"):
  fixture=Path(tmp)/"stream.shm"
  run([bridge/"build/w1700k-fixture",fixture,scenario])
  wire=run([bridge/"build/w1700k-diagnostics","--input",fixture,"--source-kind","synthetic","--once"]).stdout
  reports=[json.loads(x) for x in run([target/"rf-diagnostics-analyze"],input=wire).stdout.splitlines()]
  assert len(reports)==4
  for r in reports:
   assert r["schema"]=="rufield.rf_quality_analysis.v1"
   assert r["valid"] is False and r["confidence"]==0 and r["cause"]=="unknown"
   assert r["key"]["source_kind"]=="synthetic"
   assert r["status"]=="abstained" and not r["power_rise"]
  print("PASS",scenario,"producer, validator, replay, analyzer; absent configuration abstains")
print("PASS synthetic cross-repository E2E; no hardware claim")
