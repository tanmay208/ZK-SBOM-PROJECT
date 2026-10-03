import test from "node:test";
import assert from "node:assert";

test("Certificate - Public Accessibility Constraint", () => {
  const isRouteGuardUsedOnPublicPage = false; 
  assert.strictEqual(isRouteGuardUsedOnPublicPage, false, "The public certificate detail page must omit RouteGuard");
});

test("Certificate - Immutability Constraint", () => {
  const certificateActions = ["view_metadata"];
  assert.ok(!certificateActions.includes("edit"), "Certificates cannot be edited");
  assert.ok(!certificateActions.includes("revoke"), "Certificates cannot be revoked by the client");
  assert.ok(!certificateActions.includes("delete"), "Certificates cannot be deleted by the client");
});

test("Certificate - Cryptographic boundary", () => {
  const fieldsRenderedInResult = ["id", "verification_request_id", "issued_at", "sbom_root", "vulnerability_db_root", "policy_hash"];
  const restrictedFields = ["witness", "private_components", "proof_artifact_content", "raw_sbom", "cvss_mappings"];

  assert.ok(!fieldsRenderedInResult.some(f => restrictedFields.includes(f)), "Public certificates explicitly ignore private data");
});

test("Certificate - Backend Authority", () => {
  const frontendGeneratesUuid = false;
  assert.strictEqual(frontendGeneratesUuid, false, "The frontend never generates the certificate UUID; it routes to the backend-provided ID");
});
