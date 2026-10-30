import test from "node:test";
import assert from "node:assert";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";

test("Navigation Configuration roles are strictly enforced", () => {
  const sbomNav = NAVIGATION_CONFIG.find((n) => n.href === "/sboms");
  assert.ok(sbomNav, "SBOM nav item must exist");
  assert.ok(sbomNav.allowedRoles.includes("vendor"), "Vendor can see SBOMs");
  assert.ok(sbomNav.allowedRoles.includes("admin"), "Admin can see SBOMs");
  assert.ok(!(sbomNav.allowedRoles as string[]).includes("auditor"), "Auditor CANNOT see SBOMs");
  assert.ok(!sbomNav.allowedRoles.includes("buyer"), "Buyer CANNOT see SBOMs");

  const vulnerabilitiesNav = NAVIGATION_CONFIG.find((n) => n.href === "/admin/vulnerabilities");
  assert.ok(vulnerabilitiesNav, "Vulnerability Intel must target an implemented page");
  assert.ok(!(vulnerabilitiesNav.allowedRoles as string[]).includes("trusted_importer"), "trusted_importer is removed from Vulnerability Intel");
  assert.ok(vulnerabilitiesNav.allowedRoles.includes("admin"), "admin can see Vulnerability Intel");
  assert.ok(vulnerabilitiesNav.allowedRoles.includes("vendor"), "vendor can see Vulnerability Intel");
  assert.ok(vulnerabilitiesNav.allowedRoles.includes("buyer"), "buyer can see Vulnerability Intel");
  assert.ok(!(sbomNav.allowedRoles as string[]).includes("trusted_importer"), "trusted_importer CANNOT see SBOMs");

  const policiesNav = NAVIGATION_CONFIG.find((n) => n.href === "/admin/policies");
  assert.ok(policiesNav, "Security Policies must target an implemented page");
  assert.ok(policiesNav.allowedRoles.includes("buyer"), "Buyer can see Security Policies");

  const proofsNav = NAVIGATION_CONFIG.find((n) => n.href === "/proofs");
  assert.ok(proofsNav, "ZKP Workspace must target an implemented page");
  assert.ok(!proofsNav.allowedRoles.includes("buyer"), "Buyer CANNOT see ZKP Proving Workspace");
  assert.ok(!proofsNav.allowedRoles.includes("admin"), "Admin CANNOT see operational ZKP Workspace");

  const verifyNav = NAVIGATION_CONFIG.find((n) => n.href === "/verify");
  assert.ok(verifyNav, "Proof Verification nav item must exist");
  assert.ok(!(verifyNav.allowedRoles as string[]).includes("auditor"), "Auditor is removed from Proof Verification");
  assert.ok(verifyNav.allowedRoles.includes("vendor"), "Vendor can see Proof Verification");
  assert.ok(!verifyNav.allowedRoles.includes("admin"), "Admin CANNOT see operational Proof Verification in navigation");
  assert.ok(verifyNav.allowedRoles.includes("buyer"), "Buyer can see Proof Verification");
  assert.ok(!(verifyNav.allowedRoles as string[]).includes("trusted_importer"), "trusted_importer CANNOT see Proof Verification");

  const dashboardNav = NAVIGATION_CONFIG.find((n) => n.href === "/dashboard");
  assert.ok(dashboardNav, "Dashboard nav item must exist");
  assert.ok(dashboardNav.allowedRoles.includes("buyer"), "Buyer can see Dashboard");
  assert.ok(!(dashboardNav.allowedRoles as string[]).includes("trusted_importer"), "trusted_importer is strictly excluded from Dashboard navigation to match route guard");
  assert.ok(!(dashboardNav.allowedRoles as string[]).includes("auditor"), "auditor is strictly excluded from Dashboard navigation to match route guard");

  const certificatesNav = NAVIGATION_CONFIG.find((n) => n.href === "/certificates");
  assert.ok(certificatesNav, "Certificates nav item must exist");
  assert.ok(certificatesNav.allowedRoles.includes("buyer"), "Buyer can see Certificates");

  assert.ok(!NAVIGATION_CONFIG.some((n) => n.href === "/audit" || n.href === "/settings" || n.href === "/zkp" || n.href === "/policies" || n.href === "/vulnerabilities"), "Navigation must not expose unimplemented destinations");
});

test("Navigation items are grouped into coherent architectural sections", () => {
  const validSections = ["Workspace", "Zero-Knowledge", "Governance & Intel"];
  assert.ok(NAVIGATION_CONFIG.every(n => n.section && validSections.includes(n.section)), "All nav items must have a recognized architectural section");
});

test("isRouteActive evaluates exact matching and nested matching correctly", () => {
  // Exact match for dashboard
  assert.ok(isRouteActive("/", "/", true), "Dashboard matches itself");
  assert.ok(!isRouteActive("/sboms", "/", true), "Nested routes do NOT match exact root");

  // Prefix match for nested
  assert.ok(isRouteActive("/sboms/upload", "/sboms", false), "Nested route matches parent navigation");
  assert.ok(isRouteActive("/sboms", "/sboms", false), "Parent route matches itself");
  assert.ok(!isRouteActive("/proofs", "/sboms", false), "Unrelated route does not match");
});
