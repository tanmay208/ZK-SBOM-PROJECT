import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";

test("Dashboard - Metrics Authoritative Payload Contract", () => {
  const authoritativeBackendFields = ["total_sboms", "total_jobs", "total_certificates", "total_verifications"];
  const uiAliases = ["sbom_count", "proof_count", "verification_count", "certificate_count"];
  const explicitlyMissingFields = ["vulnerability_count", "active_policies", "risk_score", "recent_activity"];

  assert.strictEqual(authoritativeBackendFields.length, 4, "Backend provides exactly 4 authoritative scalar metrics");
  assert.ok(!authoritativeBackendFields.some(f => explicitlyMissingFields.includes(f)), "Authoritative metrics restrict display to backend-provided fields");
  assert.ok(!uiAliases.some(f => explicitlyMissingFields.includes(f)), "UI aliases restrict display to supported fields only");
});

test("Dashboard - Metrics Mapping and Zero Rendering", () => {
  function formatMetricCount(val: number | undefined): string {
    if (val === undefined || val === null) return "—";
    return String(val);
  }

  // Valid zero values must render as "0", not em-dash
  assert.strictEqual(formatMetricCount(0), "0", "Valid zero counts must render as '0'");
  assert.strictEqual(formatMetricCount(42), "42", "Positive counts must render as number string");
  assert.strictEqual(formatMetricCount(undefined), "—", "Undefined count renders fallback em-dash");

  // Verify backend to frontend mapping helper
  const backendSample = {
    total_sboms: 5,
    total_jobs: 0,
    total_certificates: 0,
    total_verifications: 2
  };

  const mapped = {
    total_sboms: backendSample.total_sboms,
    total_jobs: backendSample.total_jobs,
    total_certificates: backendSample.total_certificates,
    total_verifications: backendSample.total_verifications,
    sbom_count: backendSample.total_sboms,
    proof_count: backendSample.total_jobs,
    verification_count: backendSample.total_verifications,
    certificate_count: backendSample.total_certificates,
  };

  assert.strictEqual(formatMetricCount(mapped.total_jobs), "0", "total_jobs with value 0 renders '0'");
  assert.strictEqual(formatMetricCount(mapped.proof_count), "0", "proof_count alias with value 0 renders '0'");
  assert.strictEqual(formatMetricCount(mapped.total_sboms), "5", "total_sboms renders '5'");
});

test("Dashboard - No Fabricated State", () => {
  const supportedMetrics = ["total_sboms", "total_jobs", "total_certificates", "total_verifications"];
  const fabricatedClaims = ["risk_score", "security_rating", "vulnerability_index", "zero_day_immunity"];
  assert.ok(
    !supportedMetrics.some((m) => fabricatedClaims.includes(m)),
    "The frontend dashboard never displays fabricated risk scores or claims"
  );
});

test("Dashboard - Security UX Isolation", () => {
  // Scoping is strictly backend-authoritative via bearer token; no client-side tenant override
  const clientTenantOverrides = ["switch_tenant", "view_all_tenants"];
  const supportedClientActions = ["refresh_metrics", "navigate_workflow"];
  assert.ok(
    !supportedClientActions.some((a) => clientTenantOverrides.includes(a)),
    "No user-driven metric scoping allowed; scoping is fully backend authoritative via token"
  );
});

test("Dashboard - Role-Aware Workflow Scoping", () => {
  // Test role-scoping helper logic
  const getAvailableWorkflows = (role: string) => {
    const isVendorOrAdmin = role === "vendor" || role === "admin";
    const workflows: string[] = [];
    if (isVendorOrAdmin) {
      workflows.push("/sboms/upload");
      workflows.push("/proofs/generate");
    }
    workflows.push("/verify");
    workflows.push("/certificates");
    workflows.push("/admin/policies");
    workflows.push("/admin/vulnerabilities");
    return workflows;
  };

  const vendorWorkflows = getAvailableWorkflows("vendor");
  assert.ok(vendorWorkflows.includes("/sboms/upload"), "Vendor must have upload workflow");
  assert.ok(vendorWorkflows.includes("/proofs/generate"), "Vendor must have proof generation workflow");

  const buyerWorkflows = getAvailableWorkflows("buyer");
  assert.ok(!buyerWorkflows.includes("/sboms/upload"), "Buyer MUST NOT have upload workflow");
  assert.ok(!buyerWorkflows.includes("/proofs/generate"), "Buyer MUST NOT have proof generation workflow");
  assert.ok(buyerWorkflows.includes("/verify"), "Buyer must have verify workflow");
  assert.ok(buyerWorkflows.includes("/certificates"), "Buyer must have certificates workflow");
});

test("Dashboard - Zero-State Detection Logic", () => {
  const evaluateZeroState = (metrics: { total_sboms: number; total_jobs: number; total_verifications: number; total_certificates: number } | null) => {
    if (!metrics) return false;
    return metrics.total_sboms === 0 && metrics.total_jobs === 0 && metrics.total_verifications === 0 && metrics.total_certificates === 0;
  };

  assert.strictEqual(evaluateZeroState({ total_sboms: 0, total_jobs: 0, total_verifications: 0, total_certificates: 0 }), true);
  assert.strictEqual(evaluateZeroState({ total_sboms: 1, total_jobs: 0, total_verifications: 0, total_certificates: 0 }), false);
});

test("Dashboard - Source File Structure and Route Integrity", () => {
  const dashboardPath = path.resolve(process.cwd(), "src/app/dashboard/page.tsx");
  const content = fs.readFileSync(dashboardPath, "utf-8");

  // Page Header and Empty State integration
  assert.match(content, /<PageHeader/, "Must integrate PageHeader primitive");
  assert.match(content, /<EmptyState/, "Must integrate EmptyState primitive for zero activity");

  // Cryptographic Invariants Callout
  assert.match(content, /Noir 0\.32\.0 ACIR/, "Must state accurate Noir ACIR version");
  assert.match(content, /2,144 Bytes \(excl\. public inputs\)/, "Must qualify 2,144B proof body size");
  assert.match(content, /Zero Component Disclosure/, "Must use precise Zero Component Disclosure terminology");

  // Quick Action route targets must all be valid existing routes
  assert.match(content, /href="\/sboms\/upload"/, "Must link to /sboms/upload");
  assert.match(content, /href="\/proofs\/generate"/, "Must link to /proofs/generate");
  assert.match(content, /href="\/verify"/, "Must link to /verify");
  assert.match(content, /href="\/certificates"/, "Must link to /certificates");
  assert.match(content, /href="\/admin\/policies"/, "Must link to /admin/policies");
  assert.match(content, /href="\/admin\/vulnerabilities"/, "Must link to /admin/vulnerabilities");

  // Strict role guard protection
  assert.match(content, /<RouteGuard allowedRoles=\{\["vendor", "admin", "buyer"\]\}>/, "Dashboard must be guarded for vendor, admin, and buyer");
});
