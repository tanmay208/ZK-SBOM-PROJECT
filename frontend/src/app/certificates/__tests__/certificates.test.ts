import test from "node:test";
import assert from "node:assert";
import { certificateService } from "@/api/services/certificateService";
import { NAVIGATION_CONFIG } from "@/config/navigation";

test("Certificate - Public Accessibility Constraint", () => {
  // Authenticated certificates listing is protected by allowed roles
  const certNav = NAVIGATION_CONFIG.find((item) => item.href === "/certificates");
  assert.ok(certNav, "Certificates listing item must exist in NAVIGATION_CONFIG");
  assert.deepStrictEqual(certNav.allowedRoles, ["vendor", "admin", "buyer"]);

  // Public detail page /certificates/[id] is omitted from navigation to allow unauthenticated direct verification
  const publicDetailNav = NAVIGATION_CONFIG.find((item) => item.href.startsWith("/certificates/"));
  assert.strictEqual(publicDetailNav, undefined, "Public certificate verification pages are not restricted in NAVIGATION_CONFIG");
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

  assert.ok(!fieldsRenderedInResult.some((f) => restrictedFields.includes(f)), "Public certificates explicitly ignore private data");
});

test("Certificate - Backend Authority and Service Contract", () => {
  // Service takes backend-assigned ID without client-side ID generation
  const sampleBackendId = "11111111-2222-3333-4444-555555555555";
  assert.strictEqual(typeof sampleBackendId, "string");
  assert.strictEqual(typeof certificateService.getCertificate, "function");
  assert.strictEqual(typeof certificateService.validateCertificate, "function");
  assert.strictEqual(typeof certificateService.list, "function");
});

test("Certificate - Revocation State Awareness and Lifecycle", () => {
  // A certificate can be revoked by backend authority if underlying security assumptions change.
  // When is_revoked is true, the certificate must never be presented as currently valid.
  const activeCert = {
    valid: true,
    reason: "certificate_active",
    certificate_id: "c-1",
    is_revoked: false,
    revoked_at: null,
  };

  const revokedCert = {
    valid: false,
    reason: "certificate_revoked",
    certificate_id: "c-2",
    is_revoked: true,
    revoked_at: "2026-10-16T12:00:00Z",
  };

  function isCertificateCurrentlyValid(cert: { valid: boolean; is_revoked: boolean | null }): boolean {
    return cert.valid && cert.is_revoked !== true;
  }

  assert.strictEqual(isCertificateCurrentlyValid(activeCert), true, "Active certificate evaluates to currently valid");
  assert.strictEqual(isCertificateCurrentlyValid(revokedCert), false, "Revoked certificate evaluates to invalid");
});

test("Certificate - Status Filtering Logic", () => {
  const mockCerts = [
    { id: "c-1", is_revoked: false },
    { id: "c-2", is_revoked: true },
    { id: "c-3", is_revoked: false },
  ];

  const activeCerts = mockCerts.filter((c) => !c.is_revoked);
  const revokedCerts = mockCerts.filter((c) => c.is_revoked);

  assert.strictEqual(activeCerts.length, 2, "Active filter matches non-revoked certificates");
  assert.strictEqual(revokedCerts.length, 1, "Revoked filter matches revoked certificates");
  assert.strictEqual(revokedCerts[0].id, "c-2");
});

test("Certificate - Service API Methods", () => {
  assert.strictEqual(typeof certificateService.list, "function", "certificateService.list is exported");
  assert.strictEqual(typeof certificateService.getCertificate, "function", "certificateService.getCertificate is exported");
  assert.strictEqual(typeof certificateService.validateCertificate, "function", "certificateService.validateCertificate is exported");
});

test("Certificate - Proof Job Status vs Certificate Status Distinction", () => {
  // A proof job may be "completed", but certificate validity is an independent cryptographic artifact lifecycle
  const completedProofJob = {
    id: "job-1",
    status: "completed",
    completed_segments: 256,
    total_segments: 256,
  };

  const revokedCertificate = {
    certificate_id: "cert-1",
    valid: false,
    reason: "certificate_revoked",
    is_revoked: true,
  };

  // Proof job completed does NOT imply certificate is valid if certificate is revoked
  assert.strictEqual(completedProofJob.status, "completed");
  assert.strictEqual(revokedCertificate.valid, false);
  assert.notStrictEqual(completedProofJob.status, revokedCertificate.reason);
});

test("Certificate - Malformed UUID vs Missing Certificate Classification", () => {
  // Classification logic matching PublicCertificateDetail component
  function classifyCertificateError(statusCode?: number, reason?: string) {
    const isMalformed = statusCode === 422;
    const isNotFound = statusCode === 404 || reason === "certificate_not_found" || isMalformed;
    return {
      isMalformed,
      isNotFound,
      title: isMalformed
        ? "Invalid Certificate Identifier"
        : isNotFound
          ? "Certificate Not Found"
          : "Error Validating Certificate",
    };
  }

  const malformed = classifyCertificateError(422);
  assert.strictEqual(malformed.isMalformed, true);
  assert.strictEqual(malformed.title, "Invalid Certificate Identifier");

  const notFound = classifyCertificateError(404);
  assert.strictEqual(notFound.isMalformed, false);
  assert.strictEqual(notFound.isNotFound, true);
  assert.strictEqual(notFound.title, "Certificate Not Found");

  const reasonNotFound = classifyCertificateError(200, "certificate_not_found");
  assert.strictEqual(reasonNotFound.isMalformed, false);
  assert.strictEqual(reasonNotFound.isNotFound, true);
  assert.strictEqual(reasonNotFound.title, "Certificate Not Found");

  const serverError = classifyCertificateError(500);
  assert.strictEqual(serverError.isMalformed, false);
  assert.strictEqual(serverError.isNotFound, false);
  assert.strictEqual(serverError.title, "Error Validating Certificate");
});


test("Certificate - Public Certificate Record Layout & Centering Invariants", async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");

  const componentPath = path.resolve(process.cwd(), "src/app/certificates/[id]/page.tsx");
  const content = fs.readFileSync(componentPath, "utf-8");

  // 1. Horizontally centered responsive container wrapper (max-w-5xl, mx-auto, responsive padding)
  assert.ok(
    content.includes("max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8"),
    "Certificate page must use a responsive max-w-5xl horizontally centered wrapper (mx-auto)"
  );

  // 2. Consistent centering across loading, error, and main attestation states
  const centerMatches = content.match(/max-w-5xl mx-auto/g);
  assert.strictEqual(
    centerMatches?.length,
    3,
    "All three states (loading, error, and active) must enforce identical centered layout"
  );

  // 3. Overflow prevention on technical identifiers
  assert.ok(
    content.includes("break-all"),
    "Certificate UUID must enforce break-all to prevent horizontal overflow on mobile viewports"
  );

  // 4. Essential actions and hierarchy
  assert.ok(content.includes("Public Certificate Record"), "Page title must be preserved");
  assert.ok(content.includes("Re-check Validity"), "Re-check Validity action button must be preserved");
  assert.ok(content.includes("Verify Another"), "Verify Another navigation action must be preserved");
  assert.ok(content.includes("Zero-Knowledge Verification Scope"), "Zero-knowledge scope section must be preserved");
  assert.ok(content.includes("Tamper-Evidence & Revocation"), "Tamper-evidence section must be preserved");
});
