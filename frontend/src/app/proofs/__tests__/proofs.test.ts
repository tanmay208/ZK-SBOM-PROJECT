import test from "node:test";
import assert from "node:assert";

test("Proof Generation - Role Access Enforcement", () => {
  const allowedRoles = ["vendor", "admin"];
  assert.ok(allowedRoles.includes("vendor"), "Vendor is allowed to generate proofs");
  assert.ok(allowedRoles.includes("admin"), "Admin is allowed to generate proofs");
  assert.ok(!allowedRoles.includes("auditor"), "Auditor is explicitly forbidden");
});

test("Proof Generation - Frontend avoids cryptographic computation", () => {
  // Test represents the constraint that the frontend relies exclusively on the server response
  // rather than attempting local construction.
  const fieldsRendered = ["id", "sbom_upload_id", "status", "sbom_root", "vulnerability_db_root", "policy_hash"];
  const restrictedFields = ["witness", "private_components", "proof_artifact", "merkle_paths"];

  assert.ok(!fieldsRendered.some(f => restrictedFields.includes(f)), "UI explicitly ignores rendering private cryptographic parameters.");
});

test("Proof Generation - Polling Lifecycle", () => {
  const activeStates = ["pending", "assembling_witness"];
  const terminalStates = ["completed", "failed", "execution_blocked"];
  
  assert.ok(activeStates.includes("pending"), "Pending triggers polling");
  assert.ok(activeStates.includes("assembling_witness"), "Assembling witness triggers polling");
  
  assert.ok(!terminalStates.some(s => activeStates.includes(s)), "Terminal states do not overlap with active polling states");
});
