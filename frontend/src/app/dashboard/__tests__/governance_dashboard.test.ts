import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { AdminGovernanceMetrics } from "@/api/types";

test("Admin Governance - Metrics Contract covers all 8 authoritative domains", () => {
  const mockGovMetrics: AdminGovernanceMetrics = {
    timestamp: "2026-10-29T18:00:00Z",
    users: {
      total: 5,
      by_role: { vendor: 2, admin: 1, buyer: 2 },
      by_status: { active: 5 },
    },
    applications: {
      total: 5,
      active: 5,
      archived: 0,
    },
    sboms: {
      total: 5,
      committed: 5,
      by_status: { committed: 5 },
    },
    proof_jobs: {
      total: 6,
      completed: 1,
      running: 1,
      pending: 0,
      failed: 4,
      by_status: { failed: 4, running: 1, completed: 1 },
    },
    verifications: {
      total: 18,
      verified: 8,
      unavailable: 10,
      by_result: { verified: 4, VALID: 4, verification_unavailable: 10 },
    },
    certificates: {
      total: 4,
      active: 4,
      revoked: 0,
    },
    policies: {
      total: 1,
      active: 1,
      inactive: 0,
    },
    vulnerabilities: {
      total_snapshots: 1,
      frozen: 1,
      by_status: { frozen: 1 },
      latest_snapshot_root: "0x2c99425c861a6939b877114aaa877649e75391dcbdc9f78944979ba7abf86167",
      latest_snapshot_created_at: "2026-10-23T03:31:13Z",
    },
  };

  assert.strictEqual(mockGovMetrics.users.total, 5);
  assert.strictEqual(mockGovMetrics.applications.total, 5);
  assert.strictEqual(mockGovMetrics.sboms.committed, 5);
  assert.strictEqual(mockGovMetrics.proof_jobs.total, 6);
  assert.strictEqual(mockGovMetrics.verifications.total, 18);
  assert.strictEqual(mockGovMetrics.certificates.active, 4);
  assert.strictEqual(mockGovMetrics.policies.active, 1);
  assert.strictEqual(mockGovMetrics.vulnerabilities.frozen, 1);
});

test("Admin Governance - Dashboard Source Code Structure & Security Invariants", () => {
  const dashboardPath = path.resolve(process.cwd(), "src/app/dashboard/page.tsx");
  const content = fs.readFileSync(dashboardPath, "utf-8");

  // Admin Governance View Elements
  assert.match(content, /Platform Governance Dashboard/, "Admin header title must reflect governance role");
  assert.match(content, /Platform-Wide Governance Telemetry \(8 Domains\)/, "Admin dashboard must render the 8-domain telemetry header");
  assert.match(content, /Administrative Governance Capabilities/, "Admin dashboard must render governance capabilities");
  assert.match(content, /getGovernanceMetrics/, "Must fetch governance metrics from service");

  // Admin Quick Action links
  assert.match(content, /href="\/admin\/users"/, "Admin must have link to user administration");
  assert.match(content, /href="\/admin\/policies"/, "Must link to security policies");
  assert.match(content, /href="\/admin\/vulnerabilities"/, "Must link to vulnerability intel");
  assert.match(content, /href="\/applications"/, "Must link to applications");
  assert.match(content, /href="\/sboms"/, "Must link to SBOM inventory");
  assert.match(content, /href="\/certificates"/, "Must link to certificates");

  // Operational Alerts
  assert.match(content, /Active Prover Telemetry/, "Must render active prover telemetry notice for running jobs");
  assert.match(content, /Proof Telemetry Diagnostic Notice/, "Must render diagnostic notice for failed jobs");
  assert.match(content, /Certificate Revocation Alert/, "Must render revocation alert when revoked certs exist");
});

test("Admin Role Separation - Routine Vendor Actions Excluded for Admin", () => {
  const appPagePath = path.resolve(process.cwd(), "src/app/applications/page.tsx");
  const appContent = fs.readFileSync(appPagePath, "utf-8");
  assert.match(appContent, /all_tenants: isAdmin/, "Applications list must request all tenants when admin");
  assert.match(appContent, /!isAdmin && \(\s*<Button[\s\S]*?Register Application/, "Admin must not see routine Register Application action");
  assert.match(appContent, /!isAdmin && \(\s*<Link[\s\S]*?Upload SBOM/, "Admin must not see routine Upload SBOM action in application rows");

  const sbomPagePath = path.resolve(process.cwd(), "src/app/sboms/page.tsx");
  const sbomContent = fs.readFileSync(sbomPagePath, "utf-8");
  assert.match(sbomContent, /all_tenants: isAdmin/, "SBOM list must request all tenants when admin");
  assert.match(sbomContent, /!isAdmin && \(\s*<Link[\s\S]*?Upload SBOM/, "Admin must not see routine Upload SBOM header button");
  assert.match(sbomContent, /!isAdmin && \(\s*<Link[\s\S]*?Proof/, "Admin must not see routine Proof button in SBOM rows");

  const proofsPagePath = path.resolve(process.cwd(), "src/app/proofs/page.tsx");
  const proofsContent = fs.readFileSync(proofsPagePath, "utf-8");
  assert.match(proofsContent, /!isAdmin && \(\s*<Link[\s\S]*?Generate Proof/, "Admin must not see routine Generate Proof button on proofs workspace");
});
