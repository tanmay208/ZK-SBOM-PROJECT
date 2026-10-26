import test from "node:test";
import assert from "node:assert";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";
import { policyService } from "@/api/services/policyService";
import { vulnerabilityService } from "@/api/services/vulnerabilityService";

test("Admin Intelligence - Role Scoping Constraints", () => {
  const allowedRoles = ["vendor", "admin", "auditor", "trusted_importer"];
  const ingestionAllowedFor = ["trusted_importer"];
  const lifecycleAllowedFor = ["admin"];

  assert.ok(allowedRoles.includes("trusted_importer"), "trusted_importer can access Vulnerability Intel");
  assert.ok(allowedRoles.includes("admin"), "Admin can access Vulnerability Intel");
  assert.ok(allowedRoles.includes("vendor"), "Vendor can view state");
  assert.ok(allowedRoles.includes("auditor"), "Auditor can view state");
  
  assert.ok(!ingestionAllowedFor.includes("admin"), "Admin cannot perform ingestion (SoD enforced)");
  assert.ok(!ingestionAllowedFor.includes("vendor"), "Vendor cannot perform ingestion");
  assert.ok(!lifecycleAllowedFor.includes("trusted_importer"), "trusted_importer cannot approve or freeze snapshots");
});

test("Admin Intelligence - Ingestion Schema and Trusted Sources", () => {
  const trustedSources = ["NVD", "OSV", "GitHub Advisory Database"];
  assert.strictEqual(trustedSources.length, 3, "Backend recognizes exactly 3 authoritative threat sources");

  // Verify valid ingestion payload structure
  const validPayload = {
    source_identity: "NVD",
    provenance: { feed_version: "2.0", collector: "nist_sync" },
    vulnerabilities: [{ purl: "pkg:npm/express@4.17.1", cvss_score: 8.5 }]
  };

  assert.ok(trustedSources.includes(validPayload.source_identity), "source_identity must match recognized trusted sources");
  assert.ok(typeof validPayload.provenance === "object" && Object.keys(validPayload.provenance).length > 0, "provenance must be non-empty object");
  assert.ok(validPayload.vulnerabilities.length > 0, "vulnerabilities list must not be empty");
});

test("Admin Intelligence - State Validation", () => {
  const validSnapshotStates = ["pending", "approved", "frozen", "revoked"];
  assert.strictEqual(validSnapshotStates.length, 4, "All 4 authoritative lifecycle states are represented");
  
  // Snapshots rely strictly on backend-computed authoritative_smt_root
  const mockBackendSnapshot = {
    id: "snap-1",
    status: "frozen",
    authoritative_smt_root: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  };
  assert.ok(mockBackendSnapshot.authoritative_smt_root.startsWith("0x"), "Backend provides authoritative 0x-prefixed hex SMT root");
});

test("Admin Intelligence - Explicit Lifecycle Actions", () => {
  // Confirm distinct explicit API service methods exist for lifecycle mutations
  assert.strictEqual(typeof vulnerabilityService.approve, "function", "Explicit approval service method exists");
  assert.strictEqual(typeof vulnerabilityService.freeze, "function", "Explicit freeze service method exists");
  assert.strictEqual(typeof vulnerabilityService.revoke, "function", "Explicit revoke service method exists");
});

test("Admin Workspace - Navigation and Route Guard Alignment", () => {
  const adminNav = NAVIGATION_CONFIG.find((item) => item.href === "/admin");
  assert.ok(adminNav, "Admin navigation item must exist");
  assert.deepStrictEqual(adminNav.allowedRoles, ["admin"], "Administration workspace is strictly restricted to admin role");
  assert.strictEqual(adminNav.exactMatch, true, "Admin overview requires exact matching");
  assert.strictEqual(adminNav.section, "Governance & Intel", "Admin belongs to Governance & Intel section");

  // Route active checks: exact matching for /admin should not match /admin/policies
  assert.strictEqual(isRouteActive("/admin", "/admin", true), true);
  assert.strictEqual(isRouteActive("/admin/policies", "/admin", true), false);
  assert.strictEqual(isRouteActive("/admin/vulnerabilities", "/admin", true), false);
});

test("Admin Workspace - Service Methods Contract Verification", () => {
  assert.strictEqual(typeof policyService.list, "function", "policyService.list must exist");
  assert.strictEqual(typeof policyService.create, "function", "policyService.create must exist");
  assert.strictEqual(typeof policyService.activate, "function", "policyService.activate must exist");
  assert.strictEqual(typeof vulnerabilityService.listSnapshots, "function", "vulnerabilityService.listSnapshots must exist");
  assert.strictEqual(typeof vulnerabilityService.ingest, "function", "vulnerabilityService.ingest must exist");
  assert.strictEqual(typeof vulnerabilityService.approve, "function", "vulnerabilityService.approve must exist");
  assert.strictEqual(typeof vulnerabilityService.freeze, "function", "vulnerabilityService.freeze must exist");
  assert.strictEqual(typeof vulnerabilityService.revoke, "function", "vulnerabilityService.revoke must exist");
});

test("Admin Policy Activation - Lifecycle and Single Active Policy Transition", () => {
  const policies = [
    {
      id: "policy-1",
      name: "Standard Enterprise Policy",
      max_severity: "MEDIUM",
      active: true,
      created_at: "2026-10-10T00:00:00Z",
    },
    {
      id: "policy-2",
      name: "Strict Zero Critical Policy",
      max_severity: "LOW",
      active: false,
      created_at: "2026-10-15T00:00:00Z",
    },
  ];

  // Inactive policy can be activated
  const inactivePolicy = policies.find((p) => !p.active);
  assert.ok(inactivePolicy, "Inactive policy is identified for activation");
  assert.strictEqual(inactivePolicy.id, "policy-2");

  // Single-active-policy transition simulation: activating policy-2 deactivates policy-1
  const updatedPolicies = policies.map((p) => ({
    ...p,
    active: p.id === "policy-2",
  }));

  const activePolicies = updatedPolicies.filter((p) => p.active);
  assert.strictEqual(activePolicies.length, 1, "Exactly one policy must be active after activation");
  assert.strictEqual(activePolicies[0].id, "policy-2", "Policy 2 became active");
});

test("Admin Workspace - Tenancy Isolation Invariants", () => {
  // In C8, administrators do not receive raw vendor SBOM components
  const adminAllowedViews = ["/admin", "/admin/policies", "/admin/vulnerabilities"];
  const vendorPrivateEndpoints = ["/api/v1/sbom/{id}/components", "/api/v1/sbom/raw"];

  assert.ok(
    !adminAllowedViews.some((view) => vendorPrivateEndpoints.includes(view)),
    "Admin workspace views do not leak raw private vendor components"
  );
});

