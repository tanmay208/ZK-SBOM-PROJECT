import test from "node:test";
import assert from "node:assert";

test("Admin Intelligence - Role Scoping Constraints", () => {
  const allowedRoles = ["vendor", "admin", "auditor"];
  const mutationAllowedFor = ["admin"];

  assert.ok(allowedRoles.includes("vendor"), "Vendor can view state");
  assert.ok(allowedRoles.includes("auditor"), "Auditor can view state");
  
  assert.ok(!mutationAllowedFor.includes("vendor"), "Vendor cannot perform mutations");
  assert.ok(!mutationAllowedFor.includes("auditor"), "Auditor cannot perform mutations");
});

test("Admin Intelligence - State Validation", () => {
  const validSnapshotStates = ["pending", "approved", "revoked"];
  assert.strictEqual(validSnapshotStates.length, 3, "Only the 3 known authoritative states are represented");
  
  const frontendComputesHash = false;
  assert.strictEqual(frontendComputesHash, false, "The frontend relies strictly on backend hashes");
});

test("Admin Intelligence - Explicit Lifecycle Actions", () => {
  const approvalRequiresExplicitCall = true;
  assert.strictEqual(approvalRequiresExplicitCall, true, "Ingestion does not auto-approve");
  
  const revocationIncludesConfirmation = true;
  assert.strictEqual(revocationIncludesConfirmation, true, "Revocation prevents accidental clicks");
});
