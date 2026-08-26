#!/usr/bin/env node
/**
 * rucelium — the RuCelium metaharness.
 *
 * A Darwinian flywheel for the implementation process:
 *
 *   VARY      you (or an agent swarm) change the Rust implementation
 *   EVALUATE  `rucelium fitness` scores the change against the repo's
 *             own selection pressure: workspace tests, clippy, and the
 *             ADR-264 §14 biome acceptance benchmark
 *   SELECT    `rucelium evolve` compares fitness with the ledger head and
 *             only records non-regressing generations (survivors)
 *   RETAIN    the generation ledger (.rucelium/ledger.json) keeps the
 *             lineage of surviving implementations; commit what survives
 *
 * Zero dependencies. Node >= 18. All scoring is derived from the same
 * commands CI runs — the harness adds the loop, not new truth.
 *
 * Commands:
 *   rucelium fitness [--fast]     score the working tree, print breakdown
 *   rucelium evolve -m "msg"      score + select against the ledger head
 *   rucelium ledger               show the generation lineage
 *   rucelium gate                 strict ADR-264 acceptance gate (exit code)
 *   rucelium doctor               environment sanity check
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Repo + ledger plumbing
// ---------------------------------------------------------------------------

function findRepoRoot() {
  let dir = resolve(__dirname);
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, "Cargo.toml")) && existsSync(join(dir, "crates"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // Fall back to cwd (running via npx from the repo).
  let cwd = process.cwd();
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(cwd, "Cargo.toml")) && existsSync(join(cwd, "crates"))) {
      return cwd;
    }
    const parent = dirname(cwd);
    if (parent === cwd) break;
    cwd = parent;
  }
  fail("could not locate the rufield workspace root (Cargo.toml + crates/)");
}

const ROOT = findRepoRoot();
const LEDGER_DIR = join(ROOT, ".rucelium");
const LEDGER = join(LEDGER_DIR, "ledger.json");

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: opts.timeoutMs ?? 30 * 60 * 1000,
    env: { ...process.env, CARGO_TERM_COLOR: "never" },
  });
  return {
    ok: r.status === 0,
    status: r.status,
    out: (r.stdout ?? "") + (r.stderr ?? ""),
    stdout: r.stdout ?? "",
  };
}

function readLedger() {
  if (!existsSync(LEDGER)) return { generations: [] };
  try {
    return JSON.parse(readFileSync(LEDGER, "utf8"));
  } catch {
    fail(`ledger at ${LEDGER} is corrupt — fix or delete it`);
  }
}

function writeLedger(ledger) {
  mkdirSync(LEDGER_DIR, { recursive: true });
  writeFileSync(LEDGER, JSON.stringify(ledger, null, 2) + "\n");
}

function gitInfo() {
  const sha = sh("git", ["rev-parse", "--short", "HEAD"]);
  const dirty = sh("git", ["status", "--porcelain"]);
  return {
    sha: sha.ok ? sha.stdout.trim() : "unknown",
    dirty: dirty.ok ? dirty.stdout.trim().length > 0 : true,
  };
}

function fail(msg) {
  console.error(`rucelium: ${msg}`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Fitness — the selection pressure
// ---------------------------------------------------------------------------

/**
 * Fitness is 0..100, from the same signals CI enforces:
 *   tests    45  fraction of workspace tests passing (0 on build failure)
 *   clippy   15  15 - warnings, floored at 0
 *   accept   30  ADR-264 §14 criteria passed (of 8)
 *   quality  10  usable-calibrated % from the biome benchmark (scaled)
 */
function computeFitness({ fast = false } = {}) {
  const t0 = Date.now();
  const metrics = {
    tests_passed: 0,
    tests_failed: 0,
    build_ok: false,
    clippy_warnings: null,
    bench_criteria_passed: 0,
    bench_criteria_total: 8,
    usable_calibrated_pct: 0,
    attacks_rejected: null,
    attacks_injected: null,
    bench_ok: false,
  };

  // 1. Tests.
  process.stderr.write("→ cargo test --workspace\n");
  const test = sh("cargo", ["test", "--workspace"]);
  metrics.build_ok = !/error\[|error: could not compile/.test(test.out);
  for (const m of test.out.matchAll(
    /test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;/g
  )) {
    metrics.tests_passed += Number(m[2]);
    metrics.tests_failed += Number(m[3]);
  }

  // 2. Clippy (skipped with --fast).
  if (!fast) {
    process.stderr.write("→ cargo clippy --workspace --all-targets\n");
    const clippy = sh("cargo", ["clippy", "--workspace", "--all-targets"]);
    const warnings = [...clippy.out.matchAll(/^warning: /gm)].length;
    metrics.clippy_warnings = clippy.ok ? warnings : 99;
  }

  // 3. The ADR-264 §14 biome acceptance benchmark.
  process.stderr.write("→ cargo run -p rucelium-bench -- 2026 --json\n");
  const bench = sh("cargo", ["run", "-q", "-p", "rucelium-bench", "--", "2026", "--json"]);
  try {
    const report = JSON.parse(bench.stdout.trim());
    metrics.bench_ok = true;
    metrics.bench_criteria_total = report.criteria.length;
    metrics.bench_criteria_passed = report.criteria.filter((c) => c.pass).length;
    metrics.usable_calibrated_pct = report.usable_calibrated_pct;
    metrics.attacks_rejected = report.attacks_rejected;
    metrics.attacks_injected = report.attacks_injected;
  } catch {
    metrics.bench_ok = false;
  }

  const total_tests = metrics.tests_passed + metrics.tests_failed;
  const testScore =
    metrics.build_ok && total_tests > 0
      ? (metrics.tests_passed / total_tests) * 45
      : 0;
  const clippyScore =
    metrics.clippy_warnings === null
      ? 15 // --fast: don't punish, don't reward — carry full marks forward
      : Math.max(0, 15 - metrics.clippy_warnings);
  const acceptScore = metrics.bench_ok
    ? (metrics.bench_criteria_passed / metrics.bench_criteria_total) * 30
    : 0;
  const qualityScore = metrics.bench_ok
    ? Math.max(0, (metrics.usable_calibrated_pct - 90) / 10) * 10
    : 0;

  const fitness =
    Math.round((testScore + clippyScore + acceptScore + Math.min(10, qualityScore)) * 100) /
    100;

  return {
    fitness,
    components: {
      tests: Math.round(testScore * 100) / 100,
      clippy: Math.round(clippyScore * 100) / 100,
      acceptance: Math.round(acceptScore * 100) / 100,
      quality: Math.round(Math.min(10, qualityScore) * 100) / 100,
    },
    metrics,
    elapsed_s: Math.round((Date.now() - t0) / 100) / 10,
  };
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdFitness(args) {
  const result = computeFitness({ fast: args.includes("--fast") });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.fitness >= 99.99 ? 0 : 1);
}

function cmdEvolve(args) {
  const mIdx = args.findIndex((a) => a === "-m" || a === "--message");
  const message = mIdx >= 0 ? args[mIdx + 1] : "(no message)";
  const allowRegression = args.includes("--allow-regression");
  const fast = args.includes("--fast");

  const result = computeFitness({ fast });
  const ledger = readLedger();
  const head = ledger.generations.at(-1);
  const parentFitness = head ? head.fitness : null;
  const git = gitInfo();

  let verdict;
  if (parentFitness === null) {
    verdict = "founder";
  } else if (result.fitness > parentFitness) {
    verdict = "selected";
  } else if (result.fitness === parentFitness) {
    verdict = "neutral-selected";
  } else if (allowRegression) {
    verdict = "regression-allowed";
  } else {
    verdict = "rejected";
  }

  const gen = {
    gen: (head?.gen ?? 0) + 1,
    at: new Date().toISOString(),
    git_sha: git.sha,
    dirty: git.dirty,
    message,
    fitness: result.fitness,
    components: result.components,
    metrics: result.metrics,
    parent_fitness: parentFitness,
    verdict,
    elapsed_s: result.elapsed_s,
  };

  if (verdict !== "rejected") {
    ledger.generations.push(gen);
    writeLedger(ledger);
  }

  const arrow =
    parentFitness === null
      ? ""
      : ` (${parentFitness} → ${result.fitness})`;
  console.log(
    JSON.stringify(
      { verdict, gen: gen.gen, fitness: result.fitness, components: result.components },
      null,
      2
    )
  );
  if (verdict === "rejected") {
    console.error(
      `rucelium: REJECTED — fitness regressed${arrow}. The change does not survive selection.\n` +
        `Fix the regression, or record it deliberately with --allow-regression.`
    );
    process.exit(1);
  }
  console.error(`rucelium: generation ${gen.gen} ${verdict}${arrow} — retained in ${LEDGER}`);
}

function cmdLedger() {
  const ledger = readLedger();
  if (ledger.generations.length === 0) {
    console.log("ledger empty — run `rucelium evolve -m \"founding generation\"`");
    return;
  }
  const rows = ledger.generations.map((g) =>
    [
      String(g.gen).padStart(4),
      g.at,
      g.git_sha.padEnd(9),
      g.dirty ? "dirty" : "clean",
      String(g.fitness).padStart(7),
      g.verdict.padEnd(18),
      g.message,
    ].join("  ")
  );
  console.log(
    [" gen  timestamp                 sha        tree   fitness  verdict             message"]
      .concat(rows)
      .join("\n")
  );
}

function cmdGate() {
  // The strict acceptance gate: tests green, clippy silent, all §14
  // criteria pass. Exit 0 only when the implementation fully survives.
  const result = computeFitness({});
  const pass =
    result.metrics.tests_failed === 0 &&
    result.metrics.tests_passed > 0 &&
    result.metrics.build_ok &&
    (result.metrics.clippy_warnings ?? 99) === 0 &&
    result.metrics.bench_ok &&
    result.metrics.bench_criteria_passed === result.metrics.bench_criteria_total;
  console.log(JSON.stringify({ gate: pass ? "PASS" : "FAIL", ...result }, null, 2));
  process.exit(pass ? 0 : 1);
}

function cmdDoctor() {
  const checks = [];
  const node = process.versions.node.split(".").map(Number);
  checks.push({ check: "node >= 18", ok: node[0] >= 18, detail: process.versions.node });
  const cargo = sh("cargo", ["--version"], { timeoutMs: 30_000 });
  checks.push({ check: "cargo available", ok: cargo.ok, detail: cargo.stdout.trim() });
  const git = sh("git", ["--version"], { timeoutMs: 30_000 });
  checks.push({ check: "git available", ok: git.ok, detail: git.stdout.trim() });
  checks.push({ check: "workspace root", ok: true, detail: ROOT });
  checks.push({
    check: "rucelium-bench present",
    ok: existsSync(join(ROOT, "crates", "rucelium-bench", "Cargo.toml")),
    detail: "crates/rucelium-bench",
  });
  console.log(JSON.stringify(checks, null, 2));
  process.exit(checks.every((c) => c.ok) ? 0 : 1);
}

// ---------------------------------------------------------------------------

const [cmd, ...rest] = process.argv.slice(2);
switch (cmd) {
  case "fitness":
    cmdFitness(rest);
    break;
  case "evolve":
    cmdEvolve(rest);
    break;
  case "ledger":
    cmdLedger();
    break;
  case "gate":
    cmdGate();
    break;
  case "doctor":
    cmdDoctor();
    break;
  default:
    console.log(
      [
        "rucelium — RuCelium metaharness (Darwin flywheel)",
        "",
        "usage:",
        "  rucelium fitness [--fast]        score the working tree (tests/clippy/§14 bench)",
        '  rucelium evolve -m "msg" [--fast] [--allow-regression]',
        "                                   score + select vs the ledger head, retain survivors",
        "  rucelium ledger                  show the generation lineage",
        "  rucelium gate                    strict ADR-264 §14 acceptance gate (exit code)",
        "  rucelium doctor                  environment sanity check",
      ].join("\n")
    );
    process.exit(cmd ? 2 : 0);
}
