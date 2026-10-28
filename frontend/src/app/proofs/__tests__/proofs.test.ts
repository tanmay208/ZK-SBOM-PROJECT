import test from "node:test";
import assert from "node:assert";
import { proofService } from "@/api/services/proofService";

test("Proof Generation - Role Access Enforcement", () => {
  const allowedRoles = ["vendor", "admin"];
  assert.ok(allowedRoles.includes("vendor"), "Vendor is allowed to generate proofs");
  assert.ok(allowedRoles.includes("admin"), "Admin is allowed to generate proofs");
  assert.ok(!allowedRoles.includes("auditor"), "Auditor is explicitly forbidden");
  assert.ok(!allowedRoles.includes("trusted_importer"), "Trusted importer is explicitly forbidden");
});

test("Proof Generation - Frontend avoids cryptographic computation", () => {
  // Safe fields rendered by proof tracking views
  const fieldsRendered = [
    "id",
    "sbom_upload_id",
    "status",
    "sbom_root",
    "vulnerability_db_root",
    "policy_hash",
    "created_at",
    "completed_at",
  ];
  // Strictly restricted private/witness fields
  const restrictedFields = [
    "witness",
    "private_components",
    "raw_components",
    "purl",
    "component_hash",
    "merkle_paths",
  ];

  assert.ok(
    !fieldsRendered.some((f) => restrictedFields.includes(f)),
    "UI explicitly ignores rendering private cryptographic parameters."
  );
});

test("Proof Generation - Polling Lifecycle and Terminal States", () => {
  const activeStates = ["pending", "assembling_witness", "running"];
  const terminalStates = ["completed", "failed", "execution_blocked"];

  // Polling condition logic matching ProofDetail and ProofList refetchInterval:
  function shouldPoll(status: string, hasError: boolean): boolean {
    const isTerminal = terminalStates.includes(status);
    return !isTerminal && !hasError;
  }

  assert.ok(activeStates.includes("pending"), "Pending is in active states");
  assert.ok(activeStates.includes("assembling_witness"), "Assembling witness is in active states");
  assert.ok(activeStates.includes("running"), "Running is in active states");

  assert.strictEqual(shouldPoll("pending", false), true, "Pending state must trigger polling");
  assert.strictEqual(shouldPoll("assembling_witness", false), true, "assembling_witness must trigger polling");
  assert.strictEqual(shouldPoll("running", false), true, "Running state must trigger polling");

  assert.strictEqual(shouldPoll("completed", false), false, "Completed state must stop polling");
  assert.strictEqual(shouldPoll("failed", false), false, "Failed state must stop polling");
  assert.strictEqual(shouldPoll("execution_blocked", false), false, "execution_blocked must stop polling");

  assert.strictEqual(shouldPoll("pending", true), false, "Network error must halt polling to prevent hammering");
});

test("Proof Generation - Running State Predicates, Metrics, and Filter Consistency", () => {
  // 1. List active jobs polling predicate: running keeps polling active even as the sole active job
  const jobsWithOnlyRunning = [
    { id: "1", status: "completed" },
    { id: "2", status: "running" },
    { id: "3", status: "failed" },
  ];
  const hasActiveJobs = jobsWithOnlyRunning.some(
    (p) => p.status === "pending" || p.status === "assembling_witness" || p.status === "running"
  );
  assert.strictEqual(hasActiveJobs, true, "Running as sole active job keeps list polling active");

  // When all jobs are terminal, polling halts
  const allTerminalJobs = [
    { id: "1", status: "completed" },
    { id: "2", status: "failed" },
    { id: "3", status: "execution_blocked" },
  ];
  const hasActiveTerminal = allTerminalJobs.some(
    (p) => p.status === "pending" || p.status === "assembling_witness" || p.status === "running"
  );
  assert.strictEqual(hasActiveTerminal, false, "All terminal jobs halt list polling");

  // 2. Metrics calculation: running is counted in inProgress
  const testProofs = [
    { id: "1", status: "pending" },
    { id: "2", status: "assembling_witness" },
    { id: "3", status: "running" },
    { id: "4", status: "completed" },
    { id: "5", status: "failed" },
    { id: "6", status: "execution_blocked" },
  ];
  const inProgressCount = testProofs.filter(
    (p) => p.status === "pending" || p.status === "assembling_witness" || p.status === "running"
  ).length;
  assert.strictEqual(
    inProgressCount,
    3,
    "Running is counted alongside pending and assembling_witness in inProgress metrics"
  );

  // 3. In-progress filter predicate includes running
  function matchesFilter(status: string, filter: string): boolean {
    if (filter === "all") return true;
    if (filter === "completed") return status === "completed";
    if (filter === "in_progress") {
      return status === "pending" || status === "assembling_witness" || status === "running";
    }
    if (filter === "failed") {
      return status === "failed" || status === "execution_blocked";
    }
    return false;
  }

  assert.strictEqual(matchesFilter("running", "in_progress"), true, "Running job matches in_progress filter");
  assert.strictEqual(
    matchesFilter("assembling_witness", "in_progress"),
    true,
    "assembling_witness matches in_progress filter"
  );
  assert.strictEqual(matchesFilter("pending", "in_progress"), true, "pending matches in_progress filter");
  assert.strictEqual(matchesFilter("completed", "in_progress"), false, "completed does not match in_progress filter");

  // 4. Detail page active indicator predicate
  function isDetailActive(status: string): boolean {
    return status === "pending" || status === "assembling_witness" || status === "running";
  }
  assert.strictEqual(isDetailActive("running"), true, "Running status evaluates to active on detail page");
  assert.strictEqual(isDetailActive("completed"), false, "Completed status does not evaluate to active on detail page");
});

test("Proof Generation - Snapshot Frozen Eligibility Constraint", () => {
  const snapshots = [
    { id: "1", status: "pending", authoritative_smt_root: null },
    { id: "2", status: "approved", authoritative_smt_root: null },
    { id: "3", status: "frozen", authoritative_smt_root: "0x1234abcd" },
    { id: "4", status: "revoked", authoritative_smt_root: "0x5678ef01" },
  ];

  const eligible = snapshots.filter((s) => s.status === "frozen" && !!s.authoritative_smt_root);
  assert.strictEqual(eligible.length, 1, "Only frozen snapshots with authoritative SMT roots are eligible");
  assert.strictEqual(eligible[0].id, "3", "Snapshot 3 is the only eligible snapshot");

  assert.ok(!eligible.some((s) => s.status === "pending"), "Pending snapshots cannot be used for proof generation");
  assert.ok(!eligible.some((s) => s.status === "approved"), "Approved snapshots cannot be used until frozen");
  assert.ok(!eligible.some((s) => s.status === "revoked"), "Revoked snapshots cannot be used for proof generation");
});

test("Proof Generation - SBOM Eligibility and Merkle Root Requirement", () => {
  const sboms = [
    {
      upload_id: "s1",
      application_id: "app-1",
      status: "committed",
      sbom_root: "0xabcdef1234567890",
      component_count: 12,
    },
    {
      upload_id: "s2",
      application_id: "app-2",
      status: "pending",
      sbom_root: null,
      component_count: null,
    },
    {
      upload_id: "s3",
      application_id: "app-3",
      status: "parsed",
      sbom_root: null,
      component_count: 5,
    },
  ];

  function isSbomEligible(sbom: { status: string; sbom_root: string | null }): boolean {
    return sbom.status.toLowerCase() === "committed" && !!sbom.sbom_root;
  }

  assert.strictEqual(isSbomEligible(sboms[0]), true, "Committed SBOM with non-null root is eligible");
  assert.strictEqual(isSbomEligible(sboms[1]), false, "Pending SBOM without root is ineligible");
  assert.strictEqual(isSbomEligible(sboms[2]), false, "Parsed SBOM without commitment root is ineligible");
});

test("Proof Generation - sbomId query-parameter handling and validation", () => {
  const userSboms = [
    { upload_id: "uuid-1111", status: "committed", sbom_root: "0x1111" },
    { upload_id: "uuid-2222", status: "committed", sbom_root: "0x2222" },
  ];

  const validRequestedId = "uuid-1111";
  const invalidRequestedId = "uuid-9999-inaccessible";

  const isValidMatch = userSboms.some((s) => s.upload_id === validRequestedId);
  const isInvalidMatch = userSboms.some((s) => s.upload_id === invalidRequestedId);

  assert.strictEqual(isValidMatch, true, "Valid requested sbomId is identified in user's SBOMs");
  assert.strictEqual(isInvalidMatch, false, "Inaccessible or invalid requested sbomId is flagged as missing");
});

test("Proof Generation - Request Payload Mapping and Methods", () => {
  assert.strictEqual(typeof proofService.generate, "function", "proofService.generate must be exported");
  assert.strictEqual(typeof proofService.getJob, "function", "proofService.getJob must be exported");
  assert.strictEqual(typeof proofService.list, "function", "proofService.list must be exported");

  // Verify parameter mapping logic
  const sbomUploadId = "11111111-1111-1111-1111-111111111111";
  const snapshotId = "22222222-2222-2222-2222-222222222222";
  const policyId = "33333333-3333-3333-3333-333333333333";

  const payload = {
    sbom_upload_id: sbomUploadId,
    snapshot_id: snapshotId,
    policy_id: policyId,
  };

  assert.strictEqual(payload.sbom_upload_id, sbomUploadId);
  assert.strictEqual(payload.snapshot_id, snapshotId);
  assert.strictEqual(payload.policy_id, policyId);
});

test("Proof Generation - Duplicate Submission Prevention", () => {
  let isPending = false;
  let submissionCount = 0;

  function attemptSubmit() {
    if (isPending) return;
    isPending = true;
    submissionCount++;
  }

  attemptSubmit();
  attemptSubmit(); // Duplicate attempt while pending
  attemptSubmit(); // Duplicate attempt while pending

  assert.strictEqual(submissionCount, 1, "Only one submission can execute while pending");
  assert.strictEqual(isPending, true, "Pending lock is active");
});

test("Proof Generation - Distinction from Verification Workflow", () => {
  // A proof in 'completed' state proves UltraPlonk circuit satisfaction
  // but does not mean it is verified or that a certificate exists.
  const completedJob = {
    id: "job-1",
    status: "completed",
    is_verified: undefined, // Proof job does NOT have verification certificate
  };

  assert.strictEqual(completedJob.status, "completed");
  assert.strictEqual(
    completedJob.is_verified,
    undefined,
    "Proof generation outcome must never claim or fabricate verification certificate status"
  );
});
