# ADR 266: RuCelium Applications — Deployment Wedges and the Biological Frontier

Status: Accepted — strategy of record for deployment sequencing

Date: 2026 08 02

Deciders: rUv

Tags: rucelium, deployment, commercialization, pilots, flood, agriculture, compliance, wildfire, biodiversity, bioelectronics, governance

## 1. Context

ADR-264 defined the fabric; ADR-265 built the runtime. Neither answers the
question that decides what gets engineered next: **what is the first thing
someone pays for, and what must be true for it to work in a field?**

The honest status is that RuCelium is a working reference implementation and
simulation — roughly 70 % complete as an architectural specification, ~40 % as
a software platform, and ~15 % as a deployable physical system. Every claim
below is scoped against that.

## 2. Decision — sequence: one paid biome, never a planetary launch

**Do not begin with a planetary network. Begin with one paid biome.**

The sellable unit is *one governed biome*: a watershed, a farm, a mine
boundary, a protected area. The planetary layer is the eventual network
effect, not the product. This mirrors the ADR-264 §13 engineering rule
("federate three biomes before designing the planetary service") and makes the
commercial and technical sequencing identical — which is the point.

The fabric's strongest fit is regional environmental monitoring where
**connectivity is unreliable, data ownership matters, and decisions must be
made locally**. Those three conditions are exactly what the four-layer
sovereignty model buys, and exactly what a cloud-centralized competitor
cannot offer.

## 3. Decision — flood and watershed intelligence is wedge #1

Chosen because the outcome is *measurable* and the cost of a missed event is
high — the two properties that make a pilot convertible.

Deployment: water level, rainfall, soil saturation, flow, weather, plus
RuView motion/surface-change context across a watershed.

Detections: rising water ahead of conventional gauge triggers; blocked
culverts and drainage channels; soil saturation preceding runoff; sensor
displacement during storms; contradictions between water sensors and
surrounding environmental evidence.

Pilot shape: **16–40 nodes, 2–4 gateways, local alerts under 5 s**, roughly
$30k–$100k. Buyers: municipalities, conservation authorities, insurers,
utilities.

Engineering implication (this is why it is an ADR, not a slide): a 5-second
local alert budget is 20× looser than the ADR-264 §10 250 ms local-safety
target, so the *existing* pipeline latency is not the risk. The risks are
storm-time sensor displacement (RuView tamper/displacement context becomes
load-bearing, not decorative) and multi-gateway agreement inside one biome —
which is the first feature gap this wedge exposes.

### 3.1 The other four wedges, in priority order

| # | Wedge | Core sensing | Commercial shape | What it demands of the fabric |
|---|---|---|---|---|
| 2 | Precision agriculture / irrigation | soil moisture + conductivity, temp, humidity, leaf wetness, rainfall, optical | $10–50/acre/yr; $15k–60k initial; 10–30 % water-saving target | **Governed actuation** (irrigation valves) — the ADR-264 §9 control path stops being theoretical |
| 3 | Industrial environmental compliance | PM, chemical emissions, noise, radiation, water discharge, boundary activity, tamper | $50k–250k/site; $2k–20k/month | **Signed provenance as the product**: device identity, calibration, location, quality, lineage — already core observation attributes |
| 4 | Wildfire risk and early detection | temp, humidity, wind, soil moisture, optical smoke, PM, acoustic, RF context | Buyers are forestry, utilities, insurers, resorts, landowners — often *not* the fire service | **RF severity cap holds**: RF may support or contradict, never independently raise a critical fire alert |
| 5 | Biodiversity and habitat monitoring | acoustic, eDNA interfaces, optical traps, soil, water quality, weather, RF | Grant- and compliance-funded; slower cycles | **Disclosure policy as a feature**: coordinate coarsening and delayed release for sensitive species |

Note the pattern: each wedge stresses a *different* already-built subsystem.
Compliance monetizes provenance; agriculture monetizes governed actuation;
wildfire monetizes evidence discipline; biodiversity monetizes sovereignty.
That is the argument that the four-layer model was not over-engineering.

## 4. Decision — the biological frontier is a research track, not a roadmap

RuCelium's genuinely exotic opportunity is to be an **interface between
biological intelligence and machine intelligence** — biological sensors are
transducers the fabric already knows how to distrust properly (uncertainty,
calibration lineage, contradiction edges, quarantine).

These are tracked as candidates with explicit risk, **not** committed
deliverables. The supporting literature referenced below comes from the
strategy brief and is recorded as *claimed prior art to verify before any
pilot commitment* — none of it has been independently reproduced by this
project, and no RuCelium claim may cite it as validation of RuCelium.

| Track | Idea | Pilot cost | Time | Commercial | Sci. risk |
|---|---|---|---|---|---|
| B1 | **Living sentinel forests** — electrodes on trees/crops/fungal colonies; learn each organism's normal electrical signature, detect drought/heat/ozone/pest/damage deviation | $40k–120k | ~6 mo | 4/5 | 4/5 |
| B2 | **Ecosystem immune system** — electroactive microbial biofilms in waterways/discharge points; toxic exposure → electrical response → verification → source localization → governed intervention | $75k–250k | — | 5/5 | 3/5 |
| B3 | **Airborne DNA observatory** — anomaly-triggered air/water/soil DNA sampling enriching the WorldGraph with species, pathogens, invasives, AMR markers | $100k–300k | — | 5/5 | 2/5 |
| B4 | **Biohybrid pollinator nodes** — hives as biome nodes (acoustics, weight, vibration, electric field, air chemistry, pollen DNA) | $30k–80k | — | 4/5 | — |
| B5 | **Biohybrid chemical search** — biological olfaction on drones/ground robots; plume + wind model → probable source | — | 12–24 mo | 4/5 | eng. 4/5 |
| B6 | **Self-sensing living infrastructure** — mycelium composites reporting moisture, contamination, compression, viability, thermal stress | — | ~12 mo | 3/5 | — |
| B7 | **Autonomous bioremediation zones** — sensing organisms + remediation organisms under the governed control path | — | — | 5/5 | reg. 5/5 |
| B8 | **Ecosystem memory (RuVector)** — encode biome state; retrieve historically similar states ("91 % similar to three days before the 2028 bloom") | — | 6–9 mo | 5/5 | needs ≥1 seasonal cycle |
| B9 | **Ecosystem guardian agent** — a persistent, evidence-backed representative for a river/forest/watershed | — | — | 3/5 | gov. 5/5 |

**Priority three:** B1 (makes the mycelium vision tangible), B2 (clear
industrial buyers), B3 (turns RuCelium into biodiversity intelligence rather
than another IoT network).

### 4.1 Non-negotiable constraints on the biological track

1. **Biological confounding is the dominant failure mode.** Temperature,
   moisture, organism age, species, electrode placement, circadian rhythm and
   season can all mimic the signal of interest.
2. **Paired experimental design is mandatory.** Every biological node requires
   conventional reference sensors, local controls, organism-specific
   baselines, causal stimulus experiments, and geographically separated
   validation sites.
3. **Acceptance test (biological):** one biological signal predicts a
   *confirmed* environmental condition **≥ 30 minutes earlier** than the
   conventional sensor, at **> 90 % precision**, across **three independent
   locations**, **without per-location retraining**. Until that passes,
   biological modalities enter the WorldGraph as evidence with capped weight
   — the same discipline ADR-264 §8 applies to RF.
4. **B3 privacy is a 5/5 risk**: airborne DNA may contain human genetic
   material. No airborne-DNA pilot proceeds without an explicit human-DNA
   handling policy, and the ADR-264 §6 disclosure controls (coarsening,
   delay, access control) are minimum, not sufficient.
5. **B7 regulatory risk is 5/5**: agents may *recommend* remediation; only
   deterministic local policy actuates. This is the ADR-264 §9 rule,
   restated because the temptation is highest here.

## 5. Decision — the primary risk is scientific trust, not software

A cryptographically valid sensor can still produce meaningless data through
placement, drift, contamination, or seasonal change. Therefore calibration
authority, reference stations, stated uncertainty, drift detection, and field
validation are **product features with roadmap priority**, not internal
plumbing. ADR-265's calibration-authority work is the first payment against
this; field validation evidence is the outstanding one.

## 6. Physical acceptance test (supersedes simulation claims)

RuCelium crosses from architecture into product when **one physical biome of
8–16 nodes**:

1. runs for 30 days,
2. survives a 7-day outage **and** a gateway restart,
3. rejects replayed packets after that restart,
4. detects one deliberately drifting sensor,
5. preserves signed calibration lineage end-to-end,
6. produces one independently verifiable environmental event.

Until then, the deterministic 64-node result is labelled **fabric
reference-model acceptance** and never described as a field pilot.

## 7. Consequences

Positive: engineering priorities now derive from a buyer, not from
architectural symmetry. Multi-gateway agreement within a biome, actuation
safety, and field calibration evidence rise to the top precisely because
wedges 1–3 require them.

Negative / accepted: focusing on one watershed defers the planetary layer
indefinitely (intended); the biological tracks risk becoming a distraction if
promoted before B-track acceptance passes; several cited studies remain
unverified by this project and must not be used as marketing support.
