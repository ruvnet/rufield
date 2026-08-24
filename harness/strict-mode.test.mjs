import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

test("the harness fails closed when Cargo is unavailable", () => {
  const result = spawnSync("sh", ["harness/run-evidence-gate.sh"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      RUFIELD_INTERNAL_STRICT_PROBE: "1",
      RUFIELD_FORCE_CARGO_UNAVAILABLE: "1",
      RUFIELD_REQUIRE_PROMOTION: "1",
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
});

test("Cargo absence also fails without strict promotion mode", () => {
  const result = spawnSync("sh", ["harness/run-evidence-gate.sh"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      RUFIELD_INTERNAL_STRICT_PROBE: "1",
      RUFIELD_FORCE_CARGO_UNAVAILABLE: "1",
      RUFIELD_REQUIRE_PROMOTION: "0",
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
});

test("promotion harness requires authority registry and evaluated model", () => {
  const script = readFileSync(
    new URL("./run-evidence-gate.sh", import.meta.url),
    "utf8",
  );
  assert.match(script, /RUFIELD_AUTHORITY_REGISTRY/);
  assert.match(script, /RUFIELD_EVALUATED_MODEL/);
  assert.match(script, /--authority-registry/);
  assert.match(script, /--evaluated-model/);
});
