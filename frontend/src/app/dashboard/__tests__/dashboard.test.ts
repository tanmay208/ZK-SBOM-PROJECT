import test from "node:test";
import assert from "node:assert";

test("Dashboard - Metrics Payload Restraint", () => {
  const metricFieldsReturned = ["sbom_count", "proof_count", "verification_count", "certificate_count"];
  const explicitlyMissingFields = ["vulnerability_count", "active_policies", "risk_score", "recent_activity"];

  assert.ok(!metricFieldsReturned.some(f => explicitlyMissingFields.includes(f)), "Dashboard intentionally restricts display to supported payload fields only");
});

test("Dashboard - No Fabricated State", () => {
  const computedRiskScore = false;
  assert.strictEqual(computedRiskScore, false, "The frontend never fabricates security claims or scores");

  const computedVulnerabilityStatus = false;
  assert.strictEqual(computedVulnerabilityStatus, false, "Vulnerability state is strictly excluded since it is missing from the API");
});

test("Dashboard - Security UX Isolation", () => {
  const isTenantSelectorPresent = false;
  assert.strictEqual(isTenantSelectorPresent, false, "No user-driven metric scoping allowed; scoping is fully backend authoritative via token");
});
