#!/usr/bin/env python3
"""Regenerate self-contained README artwork; no external assets or JavaScript."""
from pathlib import Path
from html import escape
import math

ROOT = Path(__file__).resolve().parents[1] / 'docs/assets'
ROOT.mkdir(parents=True, exist_ok=True)
STYLE = '''<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#061824"/><stop offset="1" stop-color="#15132e"/></linearGradient><linearGradient id="accent"><stop stop-color="#55edcb"/><stop offset="1" stop-color="#8d8cff"/></linearGradient></defs><style>text{font-family:system-ui,-apple-system,Segoe UI,sans-serif;fill:#eff7ff}.muted{fill:#acc0d4}.eyebrow{fill:#55edcb;font-size:14px;letter-spacing:2px}.flow{stroke-dasharray:8 12;animation:flow 3s linear infinite}.pulse{animation:pulse 4s ease-in-out infinite}.orbit{transform-origin:752px 158px;animation:orbit 24s linear infinite}@keyframes flow{to{stroke-dashoffset:-80}}@keyframes pulse{50%{opacity:.35}}@keyframes orbit{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.flow,.pulse,.orbit{animation:none!important}}</style>'''
def text(x,y,value,size=18,cls=''):
    return f'<text x="{x}" y="{y}" font-size="{size}" class="{cls}">{escape(value)}</text>'
def box(x,y,w,h):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="#102438" stroke="#314864"/>'
def save(name,title,desc,height,body):
    svg=f'<svg xmlns="http://www.w3.org/2000/svg" width="960" height="{height}" viewBox="0 0 960 {height}" role="img" aria-labelledby="title desc"><title id="title">{escape(title)}</title><desc id="desc">{escape(desc)}</desc>{STYLE}<rect width="960" height="{height}" rx="20" fill="url(#bg)"/><rect x="1" y="1" width="958" height="{height-2}" rx="19" fill="none" stroke="#314864"/>{body}</svg>\n'
    (ROOT/name).write_text(svg)

b=''.join(f'<path d="M{x} 0v360" stroke="#31536a" opacity=".14"/>' for x in range(0,960,40))
b+=text(36,42,'RUFIELD / MULTIMODAL FIELD SENSING',14,'eyebrow')
b+=text(36,102,'Many signals.',44)+text(36,155,'One field of evidence.',40)
b+=text(36,202,'Camera-free sensing with trust built in.',21,'muted')
for i,t in enumerate(['NORMALIZE','VERIFY','FUSE']):
    x=36+i*172;b+=box(x,242,154,40)+text(x+18,268,t,14)
b+=text(36,328,'Synthetic ≠ captured replay ≠ validated physical accuracy',16,'muted')
for r in [45,83,124]:
    b+=f'<circle cx="752" cy="158" r="{r}" fill="none" stroke="#55edcb" opacity=".25"/>'
b+='<g class="orbit">'
for k in range(6):
    a=k*math.pi/3;x=752+124*math.cos(a);y=158+124*math.sin(a)
    b+=f'<path d="M752 158L{x:.2f} {y:.2f}" stroke="#8d8cff" opacity=".45"/><circle cx="{x:.2f}" cy="{y:.2f}" r="6" fill="#55edcb"/>'
b+='</g><circle class="pulse" cx="752" cy="158" r="34" fill="#193e51" stroke="#55edcb"/>'+text(731,164,'MFS',18)+text(673,308,'Events → inferences',16)
save('rufield-hero.svg','RuField: many signals, one field of evidence','An animated sensing constellation illustrates the common event model. Conceptual artwork, not measured data.',360,b)
b=text(32,40,'THE REFERENCE PIPELINE',14,'eyebrow')+text(32,80,'Evidence must pass before state changes.',29)
for i,(a,c,d) in enumerate([('01 / ADAPT','Sensor inputs','Real + synthetic paths'),('02 / NORMALIZE','FieldEvent','Common data model'),('03 / AUTHORIZE','Trust + privacy','Policy controls'),('04 / FUSE','FieldInference','Confidence + expiry')]):
    x=32+i*232;b+=box(x,112,204,119)+text(x+14,142,a,14,'eyebrow')+text(x+14,179,c,20)+text(x+14,211,d,14,'muted')
    if i<3:b+=f'<path class="flow" d="M{x+204} 170h28" stroke="#55edcb" stroke-width="2"/>'
b+=text(32,272,'Simulation: explicit synthetic evidence. Production: independently enrolled sensor keys.',16)
b+=text(32,307,'Rejected input never becomes trusted evidence simply because a signature is present.',15,'muted')
save('rufield-pipeline.svg','RuField evidence pipeline','Adapters normalize events; trust and privacy policies govern fusion. Production keys must be independently enrolled.',336,b)
b=text(32,40,'PRIVACY / PUBLIC PROJECTION',14,'eyebrow')+text(32,80,'Release only what the policy permits.',30)
for i,(label,detail) in enumerate([('P0','Raw signal'),('P1','Features'),('P2','Occupancy'),('P3','Aggregate'),('P4','Biometric'),('P5','Identity')]):
    x=32+i*154;b+=box(x,112,140,101)+text(x+16,148,label,25)+text(x+16,187,detail,15,'muted')
    color='#55edcb' if i in [1,2] else '#8d8cff'
    b+=f'<path class="pulse" d="M{x+16} 204h108" stroke="{color}" stroke-width="2"/>'
b+=text(32,255,'Default live projection: P1 / P2 only; identifiers and provenance internals are redacted.',16)
b+=text(32,289,'P0 stays at the edge. P4 requires consent. P5 requires identity binding and audit.',16,'muted')
save('rufield-privacy.svg','RuField privacy classes','Six privacy classes. Default live network projection permits P1 and P2; other classes are withheld. No numeric privacy ranking implies automatic release.',321,b)
b=text(32,40,'EVIDENCE / HONEST CLAIMS',14,'eyebrow')+text(32,80,'Three modes. Three different claims.',30)
for i,(a,c,d,e) in enumerate([('SYNTHETIC','Deterministic simulator','Pipeline conformance','Not physical accuracy'),('CAPTURED REPLAY','Recorded measurements','Replay + trust checks','Labels determine validity'),('PRODUCTION','Enrolled live sensors','Freshness + replay defense','Field validation still needed')]):
    x=32+i*308;b+=box(x,112,280,156)+text(x+16,143,a,14,'eyebrow')+text(x+16,183,c,19)+text(x+16,216,d,16)+text(x+16,246,e,14,'muted')
b+=text(32,309,'A working demo is evidence of a working demo. Promote claims only with verified artifacts.',15,'muted')
save('rufield-evidence.svg','RuField evidence modes','Synthetic demonstrations, captured replay and production each have distinct trust and evidence requirements.',337,b)
