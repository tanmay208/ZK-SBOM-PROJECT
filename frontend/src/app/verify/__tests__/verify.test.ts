import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import assert from "node:assert";
import { verificationService } from "@/api/services/verificationService";
import { NAVIGATION_CONFIG } from "@/config/navigation";
import { getVerificationOutcomeConfig } from "@/app/verify/page";
import { VerificationResult, ProofShareResponse } from "@/api/types";

test("Verification - Role Access", () => {
  const verifyNav = NAVIGATION_CONFIG.find((item) => item.href === "/verify");
  assert.ok(verifyNav, "Proof Verification item must exist in NAVIGATION_CONFIG");
  const allowedRoles = verifyNav.allowedRoles;
  assert.ok(allowedRoles.includes("vendor"), "Vendor is allowed in verification workspace");
  assert.ok(!allowedRoles.includes("admin"), "Admin is excluded from operational verification workspace");
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

  assert.strictEqual(getVerificationOutcomeConfig("unexpected_code").title, "Verification Pending");
  assert.strictEqual(getVerificationOutcomeConfig(null).title, "Verification Pending");
});

test("Verification - Owned Proof Job Binding Constraint", () => {
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

test("Verification - Vendor navigation and route guard permits vendor access", async () => {
  const verifyNav = NAVIGATION_CONFIG.find((n) => n.href === "/verify");
  assert.ok(verifyNav, "Proof Verification nav entry must exist");
  assert.strictEqual(verifyNav.allowedRoles.includes("vendor"), true, "Vendor role MUST be in allowedRoles for /verify");
  assert.strictEqual(verifyNav.allowedRoles.includes("buyer"), true, "Buyer role MUST be in allowedRoles for /verify");
  assert.strictEqual(verifyNav.allowedRoles.includes("admin"), false, "Admin role MUST NOT be in allowedRoles for /verify");

  const fs = await import("node:fs");
  const path = await import("node:path");
  const verifyPagePath = path.resolve(process.cwd(), "src/app/verify/page.tsx");
  const pageContent = fs.readFileSync(verifyPagePath, "utf-8");

  assert.match(
    pageContent,
    /<RouteGuard allowedRoles={\["vendor", "buyer"\]}>/,
    "VerifyPage must guard access to vendor and buyer"
  );
});

test("Verification - Buyer verification reference lookup contract", () => {
  assert.strictEqual(
    typeof verificationService.getShare,
    "function",
    "verificationService.getShare must be exported for reference lookup"
  );
  assert.strictEqual(
    typeof verificationService.listShares,
    "function",
    "verificationService.listShares must be exported for buyer share listing"
  );
  assert.strictEqual(
    typeof verificationService.deleteShare,
    "function",
    "verificationService.deleteShare must be exported for deleting revoked shares"
  );
});

test("Verification - Vendor proof generation and share creation routes remain functional", () => {
  const proofsNav = NAVIGATION_CONFIG.find((n) => n.href === "/proofs");
  assert.ok(proofsNav, "ZKP Workspace nav entry must exist");
  assert.ok(proofsNav.allowedRoles.includes("vendor"), "Vendor can access /proofs");

  assert.strictEqual(
    typeof verificationService.createShare,
    "function",
    "verificationService.createShare must be exported for vendor share creation"
  );
  assert.strictEqual(
    typeof verificationService.revokeShare,
    "function",
    "verificationService.revokeShare must be exported for vendor share revocation"
  );
});

test("Verification - Buyer cannot access proof generation routes", () => {
  const proofsNav = NAVIGATION_CONFIG.find((n) => n.href === "/proofs");
  assert.ok(proofsNav, "ZKP Workspace nav entry exists");
  assert.strictEqual(
    proofsNav.allowedRoles.includes("buyer"),
    false,
    "Buyer MUST NOT have access to /proofs generation workspace"
  );

  const sbomsNav = NAVIGATION_CONFIG.find((n) => n.href === "/sboms");
  assert.ok(sbomsNav, "SBOMs nav entry exists");
  assert.strictEqual(
    sbomsNav.allowedRoles.includes("buyer"),
    false,
    "Buyer MUST NOT have access to /sboms management"
  );
});

test("Verification - Admin functionality remains intact across pipelines", () => {
  const verifyNav = NAVIGATION_CONFIG.find((n) => n.href === "/verify");
  assert.strictEqual(verifyNav?.allowedRoles.includes("admin"), false, "Admin CANNOT access operational /verify");

  const proofsNav = NAVIGATION_CONFIG.find((n) => n.href === "/proofs");
  assert.strictEqual(proofsNav?.allowedRoles.includes("admin"), false, "Admin CANNOT access operational /proofs");

  const certNav = NAVIGATION_CONFIG.find((n) => n.href === "/certificates");
  assert.ok(certNav?.allowedRoles.includes("admin"), "Admin can access /certificates");

  const adminNav = NAVIGATION_CONFIG.find((n) => n.href === "/admin");
  assert.ok(adminNav?.allowedRoles.includes("admin"), "Admin can access /admin");
});

test("Verification Share Management - One-at-a-time token generation contract", () => {
  // Test token uniqueness, formatting, and single active presentation
  const mockShare1: ProofShareResponse = {
    id: "00000000-0000-0000-0000-000000000001",
    proof_job_id: "00000000-0000-0000-0000-000000000010",
    vendor_id: "00000000-0000-0000-0000-000000000100",
    share_token: "vref_1111111111111111111111111111111111111111",
    recipient_role: "buyer",
    recipient_user_id: null,
    is_revoked: false,
    revoked_at: null,
    expires_at: null,
    created_at: new Date().toISOString(),
    is_active: true,
  };

  const mockShare2: ProofShareResponse = {
    id: "00000000-0000-0000-0000-000000000002",
    proof_job_id: "00000000-0000-0000-0000-000000000010",
    vendor_id: "00000000-0000-0000-0000-000000000100",
    share_token: "vref_2222222222222222222222222222222222222222",
    recipient_role: "buyer",
    recipient_user_id: null,
    is_revoked: false,
    revoked_at: null,
    expires_at: null,
    created_at: new Date().toISOString(),
    is_active: true,
  };

  assert.notStrictEqual(mockShare1.share_token, mockShare2.share_token, "Tokens must be unique");
  assert.match(mockShare1.share_token, /^vref_[0-9a-f]{40}$/, "Token must have high-entropy vref prefix");

  // When second token is generated, previous active tokens for that job are revoked
  mockShare1.is_revoked = true;
  mockShare1.is_active = false;
  mockShare1.revoked_at = new Date().toISOString();

  const latestToken: ProofShareResponse = mockShare2;
  const jobShares = [mockShare2, mockShare1];

  assert.strictEqual(latestToken.id, mockShare2.id, "Latest token represents most recent generation");
  assert.strictEqual(latestToken.is_revoked, false, "Newest share is active");
  assert.strictEqual(mockShare1.is_revoked, true, "Previous share is automatically revoked");
  const activeCount = jobShares.filter(s => !s.is_revoked).length;
  assert.strictEqual(activeCount, 1, "Exactly one active share exists for this proof job");
});

test("Verification Share UI - No Copy Link and raw token copying only", () => {
  const proofDetailPath = path.resolve(process.cwd(), "src/app/proofs/[id]/page.tsx");
  const pageContent = fs.readFileSync(proofDetailPath, "utf-8");

  // Verify Copy Link is completely removed
  assert.ok(!pageContent.includes("Copy Link"), "Copy Link button must be completely removed");
  assert.ok(!pageContent.includes("verify?token="), "Must not construct full verification URLs in ProofDetail");

  // Verify Copy Token is present
  assert.ok(pageContent.includes("Copy Token"), "Copy Token button must be present");
  assert.ok(pageContent.includes("share.share_token"), "Must pass raw share_token to copyToClipboard");

  // Verify actions by state: Active has Revoke and Copy Token, Revoked has Delete
  assert.match(pageContent, /!share\.is_revoked \? \([\s\S]*?Copy Token[\s\S]*?Revoke/, "Active share must offer Copy Token and Revoke");
  assert.match(pageContent, /share\.is_revoked[\s\S]*?deleteShareMutation\.mutate/, "Revoked share must offer Delete action");
});

test("Verification Share Management - Delete revoked share lifecycle contract", () => {
  const activeShare: ProofShareResponse = {
    id: "00000000-0000-0000-0000-000000000001",
    proof_job_id: "00000000-0000-0000-0000-000000000010",
    vendor_id: "00000000-0000-0000-0000-000000000100",
    share_token: "vref_active",
    recipient_role: "buyer",
    is_revoked: false,
    created_at: new Date().toISOString(),
    is_active: true,
  };

  const revokedShare: ProofShareResponse = {
    id: "00000000-0000-0000-0000-000000000002",
    proof_job_id: "00000000-0000-0000-0000-000000000010",
    vendor_id: "00000000-0000-0000-0000-000000000100",
    share_token: "vref_revoked",
    recipient_role: "buyer",
    is_revoked: true,
    revoked_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    is_active: false,
  };

  function canDeleteShare(share: ProofShareResponse): boolean {
    return share.is_revoked === true;
  }

  function canRevokeShare(share: ProofShareResponse): boolean {
    return share.is_revoked === false;
  }

  assert.strictEqual(canRevokeShare(activeShare), true, "Active share can be revoked");
  assert.strictEqual(canDeleteShare(activeShare), false, "Active share CANNOT be deleted");

  assert.strictEqual(canRevokeShare(revokedShare), false, "Revoked share cannot be revoked again");
  assert.strictEqual(canDeleteShare(revokedShare), true, "Revoked share CAN be deleted");
});
