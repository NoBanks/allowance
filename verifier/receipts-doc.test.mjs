// RECEIPTS.md points at exact lines. This keeps those pointers from going stale: it
// checks each one lands on the kind of line the claim needs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const doc = readFileSync(new URL("RECEIPTS.md", root), "utf8");
const refs = [...new Set([...doc.matchAll(/`([\w./-]+\.(?:rs|mjs)):(\d+)`/g)].map((m) => `${m[1]}:${m[2]}`))];

test("RECEIPTS.md has line references to check", () => {
  assert.ok(refs.length > 30, `found ${refs.length}`);
});

test("every reference points at a real line of a real file", () => {
  for (const ref of refs) {
    const [path, line] = ref.split(":");
    const url = new URL(path, root);
    assert.ok(existsSync(url), `${path} does not exist`);
    const lines = readFileSync(url, "utf8").split("\n");
    assert.ok(lines[Number(line) - 1]?.trim(), `${ref} is blank or past the end of the file`);
  }
});

test("references to tests land on the first line of a test", () => {
  for (const ref of refs) {
    const [path, line] = ref.split(":");
    const text = readFileSync(new URL(path, root), "utf8").split("\n")[Number(line) - 1];
    if (path.endsWith("tests.rs")) assert.match(text, /^fn /, ref);
    if (path.endsWith(".test.mjs")) assert.match(text, /^test\(/, ref);
    if (path.endsWith("prove-the-box.mjs")) assert.match(text, /^(await mustBeRefusedBecause|record)\(/, ref);
  }
});

test("the documents named in the README exist", () => {
  for (const f of ["RECEIPTS.md", "deployment/testnet.json", "deployment/prove-the-box.json", "deployment/allowance.wasm", "dashboard/index.html"]) {
    assert.ok(existsSync(new URL(f, root)), f);
  }
});
