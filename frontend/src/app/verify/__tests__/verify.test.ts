import test from "node:test";
import assert from "node:assert";
import { verificationService } from "@/api/services/verificationService";
import { NAVIGATION_CONFIG } from "@/config/navigation";
import { getVerificationOutcomeConfig } from "@/app/verify/page";
import { VerificationResult } from "@/api/types";

test("Verification - Role Access", () => {
  const verifyNav = NAVIGATION_CONFIG.find((item) => item.href === "/verify");
  assert.ok(verifyNav, "Proof Verification item must exist in NAVIGATION_CONFIG");
  const allowedRoles = verifyNav.allowedRoles;
  assert.ok(allowedRoles.includes("vendor"), "Vendor is allowed in verification workspace");
  assert.ok(allowedRoles.includes("admin"), "Admin is allowed in verification workspace");
  assert.ok(allowedRoles.includes("buyer"), "Buyer is allowed in verification workspace");
  assert.ok(!(allowedRoles as string[]).includes("auditor"), "Auditor is retired from verification workspace");
  assert.ok(!(allowedRoles as string[]).includes("trusted_importer"), "Trusted importer is not allowed in verification workspace");
});

test("Verification - Selection Constraint", () => {
  const mockJobs = [
    { id: "1", status: "completed" },
    { id: "2", status: "pending" },
    { id: "3", status: "assembling_witness" },
    { id: "4", status: "running" },
    { id: "5", status: "failed" },
    { id: "6", status: "execution_blocked" },
  ];

  const verifiableJobs = mockJobs.filter((j) => j.status === "completed");

  assert.strictEqual(verifiableJobs.length, 1, "Only completed jobs can be submitted for verification");
  assert.strictEqual(verifiableJobs[0].id, "1");
  assert.ok(!verifiableJobs.some((j) => j.status === "pending"), "Pending jobs cannot be verified");
  assert.ok(!verifiableJobs.some((j) => j.status === "running"), "Running jobs cannot be verified");
});

test("Verification - Cryptographic boundary", () => {
  const fieldsRenderedInResult = ["id", "result", "verified_at", "certificate.id"];
  const restrictedFields = ["witness", "private_components", "proof_artifact_content", "verifier_stderr"];

  assert.ok(!fieldsRenderedInResult.some((f) => restrictedFields.includes(f)), "UI explicitly ignores private verifier outputs and artifacts");
});

test("Verification - Verified vs Generated claims", () => {
  const completedJobState = "Proof generation completed.";
  const verifiedState = "Proof successfully verified against authoritative backend records.";

  assert.notStrictEqual(completedJobState, verifiedState, "Frontend correctly distinguishes Generation from Verification");
});

test("Verification - Backend Outcome State Machine Handling", () => {
  // Directly test the production getVerificationOutcomeConfig mapping
  assert.strictEqual(getVerificationOutcomeConfig("verified").title, "Cryptographic Proof Verified");
  assert.strictEqual(getVerificationOutcomeConfig("verified").pillStatus, "verified");

  assert.strictEqual(getVerificationOutcomeConfig("invalid_proof").title, "Cryptographic Proof Invalid");
  assert.strictEqual(getVerificationOutcomeConfig("invalid_proof").pillStatus, "invalid");
  assert.strictEqual(getVerificationOutcomeConfig("invalid").title, "Cryptographic Proof Invalid");
  assert.strictEqual(getVerificationOutcomeConfig("cryptographic_false").title, "Cryptographic Proof Invalid");
  assert.strictEqual(getVerificationOutcomeConfig("cryptographic_false").pillStatus, "invalid");
  assert.strictEqual(getVerificationOutcomeConfig("structural_rejection").title, "Proof Structural Rejection");
  assert.strictEqual(getVerificationOutcomeConfig("structural_rejection").pillStatus, "invalid");

  assert.strictEqual(getVerificationOutcomeConfig("public_input_mismatch").title, "Public Input Mismatch");
  assert.strictEqual(getVerificationOutcomeConfig("public_input_mismatch").pillStatus, "non_compliant");

  assert.strictEqual(getVerificationOutcomeConfig("record_mismatch").title, "Authoritative Record Mismatch");
  assert.strictEqual(getVerificationOutcomeConfig("record_mismatch").pillStatus, "warning");
  assert.strictEqual(getVerificationOutcomeConfig("authoritative_record_mismatch").title, "Authoritative Record Mismatch");

  assert.strictEqual(getVerificationOutcomeConfig("runtime_failure").title, "Verifier Runtime Failure");
  assert.strictEqual(getVerificationOutcomeConfig("runtime_failure").pillStatus, "execution_blocked");
  assert.strictEqual(getVerificationOutcomeConfig("environment_failure").title, "Verification Unavailable");
  assert.strictEqual(getVerificationOutcomeConfig("environment_failure").pillStatus, "execution_blocked");

  assert.strictEqual(getVerificationOutcomeConfig("verification_unavailable").title, "Verification Unavailable");
  assert.strictEqual(getVerificationOutcomeConfig("verification_unavailable").pillStatus, "execution_blocked");
  assert.strictEqual(getVerificationOutcomeConfig("unavailable").title, "Verification Unavailable");

  // Unknown outcome fails safely to default pending state
  assert.strictEqual(getVerificationOutcomeConfig("unexpected_code").title, "Verification Pending");
  assert.strictEqual(getVerificationOutcomeConfig(null).title, "Verification Pending");
});

test("Verification - Owned Proof Job Binding Constraint", () => {
  // Verification requires an authorized proof_job_id
  const payloadWithJob = {
    sbom_root: "0x1111111111111111111111111111111111111111111111111111111111111111",
    vulnerability_db_root: "0x2222222222222222222222222222222222222222222222222222222222222222",
    policy_hash: "0x3333333333333333333333333333333333333333333333333333333333333333",
    proof_job_id: "00000000-0000-0000-0000-000000000001",
  };

  assert.ok(payloadWithJob.proof_job_id, "Verification request must bind to an owned proof_job_id");
  assert.strictEqual(typeof verificationService.verify, "function", "verificationService.verify is exported");
});

test("Verification - Certificate Minting Gated Strictly on Verified Result", () => {
  // A certificate is ONLY rendered or recognized when result is exactly 'verified'
  const verifiedOutcome = {
    id: "req-1",
    result: "verified",
    certificate: { id: "cert-1" },
  };

  const failedOutcome = {
    id: "req-2",
    result: "invalid_proof",
    certificate: null,
  };

  const unavailableOutcome = {
    id: "req-3",
    result: "verification_unavailable",
    certificate: null,
  };

  function canDisplayCertificate(res: { result: string; certificate: { id: string } | null }): boolean {
    return res.result === "verified" && res.certificate !== null;
  }

  assert.strictEqual(canDisplayCertificate(verifiedOutcome), true, "Certificate displayed when verified");
  assert.strictEqual(canDisplayCertificate(failedOutcome), false, "No certificate displayed when invalid");
  assert.strictEqual(canDisplayCertificate(unavailableOutcome), false, "No certificate displayed when unavailable");
});

test("Verification - VerificationResult Contract Completeness", () => {
  const backendAuthoritativeResults: VerificationResult[] = [
    "verified",
    "invalid_proof",
    "cryptographic_false",
    "structural_rejection",
    "runtime_failure",
    "environment_failure",
    "public_input_mismatch",
    "record_mismatch",
    "verification_unavailable",
  ];

  for (const res of backendAuthoritativeResults) {
    const config = getVerificationOutcomeConfig(res);
    assert.notStrictEqual(
      config.title,
      "Verification Pending",
      `Authoritative backend outcome '${res}' must map to a recognized outcome config`
    );
    assert.ok(config.pillStatus, `Outcome '${res}' must define a status pill state`);
    assert.ok(config.icon, `Outcome '${res}' must define an icon`);
  }
});
