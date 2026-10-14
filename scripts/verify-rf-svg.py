#!/usr/bin/env python3
"""Validate the portable, script-free RF observatory SVG."""
import re
from pathlib import Path
import xml.etree.ElementTree as ET

path = Path(__file__).resolve().parents[1] / "docs/assets/rufield-rf-observatory.svg"
text = path.read_text()
root = ET.fromstring(text)
ns = "{http://www.w3.org/2000/svg}"
assert root.tag == ns + "svg"
assert root.get("viewBox") == "0 0 1100 460"
assert root.get("role") == "img"
assert len(text.splitlines()) < 500
ids = [e.get("id") for e in root.iter() if e.get("id")]
assert len(ids) == len(set(ids)), "duplicate ids"
for label in root.get("aria-labelledby", "").split():
    assert label in ids
for e in root.iter():
    assert e.tag not in {ns + t for t in ("script", "foreignObject", "image", "use")}
    for key, value in e.attrib.items():
        assert not key.lower().startswith("on")
        assert not key.endswith("href")
for target in re.findall(r"url\(([^)]+)\)", text):
    assert target.startswith("#") and target[1:] in ids
assert "@import" not in text and "prefers-reduced-motion:reduce" in text
for marker in ("UNKNOWN", "ADVISORY ONLY", "No presence inference", "not measured data"):
    assert marker in text
print("PASS XML, accessibility, local references, bounded size, reduced motion and evidence labels")
