import test from "node:test";
import assert from "node:assert";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";

test("Navigation Configuration roles are strictly enforced", () => {
  const sbomNav = NAVIGATION_CONFIG.find((n) => n.href === "/sboms");
  assert.ok(sbomNav, "SBOM nav item must exist");
  assert.ok(sbomNav.allowedRoles.includes("vendor"), "Vendor can see SBOMs");
  assert.ok(sbomNav.allowedRoles.includes("admin"), "Admin can see SBOMs");
  assert.ok(!sbomNav.allowedRoles.includes("auditor"), "Auditor CANNOT see SBOMs");

  const vulnerabilitiesNav = NAVIGATION_CONFIG.find((n) => n.href === "/admin/vulnerabilities");
  assert.ok(vulnerabilitiesNav, "Vulnerability Intel must target an implemented page");
  const policiesNav = NAVIGATION_CONFIG.find((n) => n.href === "/admin/policies");
  assert.ok(policiesNav, "Security Policies must target an implemented page");
  const proofsNav = NAVIGATION_CONFIG.find((n) => n.href === "/proofs");
  assert.ok(proofsNav, "ZKP Workspace must target an implemented page");
  assert.ok(!NAVIGATION_CONFIG.some((n) => n.href === "/audit" || n.href === "/settings" || n.href === "/zkp" || n.href === "/policies" || n.href === "/vulnerabilities"), "Navigation must not expose unimplemented destinations");
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
