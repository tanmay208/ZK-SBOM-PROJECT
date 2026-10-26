import test from "node:test";
import assert from "node:assert";
import { badgeVariants } from "../badge";
import { alertVariants } from "../alert";

test("Badge variants include semantic tokens for supply-chain security states", () => {
  const successBadge = badgeVariants({ variant: "success" });
  assert.match(successBadge, /bg-success/, "Success variant must use semantic bg-success token");
  assert.match(successBadge, /text-emerald/, "Success variant must maintain high-contrast green text");

  const warningBadge = badgeVariants({ variant: "warning" });
  assert.match(warningBadge, /bg-warning/, "Warning variant must use semantic bg-warning token");
  assert.match(warningBadge, /text-amber/, "Warning variant must maintain readable amber text");

  const infoBadge = badgeVariants({ variant: "info" });
  assert.match(infoBadge, /bg-info/, "Info variant must use semantic bg-info token");
  assert.match(infoBadge, /text-blue/, "Info variant must use readable blue text");

  const destructiveBadge = badgeVariants({ variant: "destructive" });
  assert.match(destructiveBadge, /text-destructive/, "Destructive variant must use text-destructive");
});

test("Alert variants include semantic statuses with accessible foreground styling", () => {
  const successAlert = alertVariants({ variant: "success" });
  assert.match(successAlert, /border-success/, "Success alert must have border-success");
  assert.match(successAlert, /bg-success/, "Success alert must have subtle bg-success");

  const warningAlert = alertVariants({ variant: "warning" });
  assert.match(warningAlert, /border-warning/, "Warning alert must have border-warning");
  assert.match(warningAlert, /bg-warning/, "Warning alert must have subtle bg-warning");

  const infoAlert = alertVariants({ variant: "info" });
  assert.match(infoAlert, /border-info/, "Info alert must have border-info");
  assert.match(infoAlert, /bg-info/, "Info alert must have subtle bg-info");

  const destructiveAlert = alertVariants({ variant: "destructive" });
  assert.match(destructiveAlert, /border-destructive/, "Destructive alert must have border-destructive");
});

test("StatusPill correctly maps supply-chain security lifecycle states to semantic variants", async () => {
  const { getStatusConfig } = await import("../status-pill");

  assert.strictEqual(getStatusConfig("verified").variant, "success");
  assert.strictEqual(getStatusConfig("compliant").variant, "success");
  assert.strictEqual(getStatusConfig("active").variant, "success");
  assert.strictEqual(getStatusConfig("approved").variant, "success");
  assert.strictEqual(getStatusConfig("committed").variant, "success");
  assert.strictEqual(getStatusConfig("committed").defaultLabel, "Committed");

  assert.strictEqual(getStatusConfig("generating").variant, "info");
  assert.strictEqual(getStatusConfig("in_progress").variant, "info");
  assert.strictEqual(getStatusConfig("assembling_witness").variant, "info");
  assert.strictEqual(getStatusConfig("running").variant, "info");
  assert.strictEqual(getStatusConfig("running").defaultLabel, "Running");

  assert.strictEqual(getStatusConfig("completed").variant, "success");
  assert.strictEqual(getStatusConfig("completed").defaultLabel, "Completed");

  assert.strictEqual(getStatusConfig("pending").variant, "warning");
  assert.strictEqual(getStatusConfig("queued").variant, "warning");
  assert.strictEqual(getStatusConfig("non_compliant").variant, "warning");

  assert.strictEqual(getStatusConfig("frozen").variant, "secondary");

  assert.strictEqual(getStatusConfig("revoked").variant, "destructive");
  assert.strictEqual(getStatusConfig("invalid").variant, "destructive");
  assert.strictEqual(getStatusConfig("failed").variant, "destructive");
  assert.strictEqual(getStatusConfig("execution_blocked").variant, "destructive");
});

test("PageHeader and EmptyState primitives export correctly", async () => {
  const { PageHeader } = await import("../page-header");
  const { EmptyState } = await import("../empty-state");

  assert.strictEqual(typeof PageHeader, "function", "PageHeader component must be exported");
  assert.strictEqual(typeof EmptyState, "function", "EmptyState component must be exported");
});
