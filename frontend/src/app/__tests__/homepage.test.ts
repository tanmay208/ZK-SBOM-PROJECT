import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";

test("Homepage is defined and exports a valid React component", async () => {
  const homepageModule = await import("../page");
  assert.strictEqual(typeof homepageModule.default, "function", "Homepage must export a default component");
});

test("Homepage contains all mandatory presentation sections with valid anchor IDs", () => {
  const pagePath = path.resolve(process.cwd(), "src/app/page.tsx");
  const content = fs.readFileSync(pagePath, "utf-8");

  // Section A: Public navigation
  assert.match(content, /id="overview"/, "Must have #overview section");
  // Section C: Problem & dilemma
  assert.match(content, /id="problem"/, "Must have #problem section");
  // Section D: Workflow pipeline
  assert.match(content, /id="workflow"/, "Must have #workflow section");
  // Section E: System capabilities
  assert.match(content, /id="capabilities"/, "Must have #capabilities section");
  // Section F: Limitations & security boundaries
  assert.match(content, /id="limitations"/, "Must have #limitations section");
});

test("Homepage maintains functional entry points into existing application routes", () => {
  const pagePath = path.resolve(process.cwd(), "src/app/page.tsx");
  const content = fs.readFileSync(pagePath, "utf-8");

  assert.match(content, /href="\/login"/, "Must have functional link to /login");
  assert.match(content, /href="\/register"/, "Must have functional link to /register");
  assert.match(content, /href="\/dashboard"/, "Must have functional link to /dashboard for authenticated users");
  assert.match(content, /href="\/certificates"/, "Must have functional link to /certificates for authenticated users");
  assert.match(content, /Sign In to Verify|Sign In for Certificates/, "Must direct unauthenticated visitors to login for protected certificates");
});

test("Homepage explicitly bounds security claims and does not promise zero-day immunity", () => {
  const pagePath = path.resolve(process.cwd(), "src/app/page.tsx");
  const content = fs.readFileSync(pagePath, "utf-8");

  // Verify that the page explicitly states zero-day limitations
  assert.match(content, /zero-day/i, "Homepage must explicitly note limitations regarding zero-day vulnerabilities");
  assert.match(content, /prove that software is free from unknown zero-day/i, "Must not claim absolute vulnerability immunity");
  assert.match(content, /Poseidon/i, "Must reference Poseidon cryptographic commitment");
  assert.match(content, /UltraPlonk/i, "Must reference UltraPlonk proof system");
  assert.match(content, /2,144B UltraPlonk Proof Body|2,144-byte UltraPlonk proof body/i, "Must specify proof body size excluding public inputs");
  assert.match(content, /Zero Component Disclosure/i, "Must use precise privacy wording instead of Zero Leakage");
  assert.match(content, /Tamper-Evident Certificate/i, "Must use Tamper-Evident Certificate terminology");
  assert.match(content, /Automated Proof Check/i, "Must qualify verification check");
  assert.doesNotMatch(content, /~25ms/, "Must not contain unqualified ~25ms claims");
  assert.doesNotMatch(content, /Zero Leakage/, "Must not contain Zero Leakage badge");
});
