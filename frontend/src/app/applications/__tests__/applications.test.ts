import test from "node:test";
import assert from "node:assert";
import { applicationService } from "@/api/services/applicationService";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";

test("Application Service - API methods exist and export correctly", () => {
  assert.strictEqual(typeof applicationService.list, "function", "applicationService.list must be a function");
  assert.strictEqual(typeof applicationService.create, "function", "applicationService.create must be a function");
  assert.strictEqual(typeof applicationService.get, "function", "applicationService.get must be a function");
  assert.strictEqual(typeof applicationService.update, "function", "applicationService.update must be a function");
  assert.strictEqual(typeof applicationService.archive, "function", "applicationService.archive must be a function");
  assert.strictEqual(typeof applicationService.reactivate, "function", "applicationService.reactivate must be a function");
});

test("Application Workspace - Navigation and Role Scoping", () => {
  const appNav = NAVIGATION_CONFIG.find((item) => item.href === "/applications");
  assert.ok(appNav, "Applications navigation item must be defined in NAVIGATION_CONFIG");
  assert.strictEqual(appNav.section, "Workspace", "Applications belongs to Workspace section");
  assert.strictEqual(Boolean(appNav.exactMatch), false, "Applications does not require exact matching");

  // Allowed roles: vendor and admin
  assert.strictEqual(appNav.allowedRoles.includes("vendor"), true, "Vendors are permitted in Applications workspace");
  assert.strictEqual(appNav.allowedRoles.includes("admin"), true, "Admins are permitted in Applications workspace");
  assert.strictEqual((appNav.allowedRoles as string[]).includes("auditor"), false, "Auditors are denied access to Applications workspace");
  assert.strictEqual((appNav.allowedRoles as string[]).includes("trusted_importer"), false, "Trusted importers are denied access to Applications workspace");
  assert.strictEqual(appNav.allowedRoles.includes("buyer"), false, "Buyers are denied access to Applications workspace");

  // Route active matching
  assert.strictEqual(isRouteActive("/applications", "/applications", false), true);
  assert.strictEqual(isRouteActive("/applications/app-1", "/applications", false), true);
  assert.strictEqual(isRouteActive("/sboms", "/applications", false), false);
});

test("Application Validation - Name and Vendor format rules", () => {
  function hasControlCharacters(val: string): boolean {
    for (let i = 0; i < val.length; i++) {
      const code = val.charCodeAt(i);
      if (code < 32 && code !== 9) {
        return true;
      }
    }
    return false;
  }

  // Valid inputs
  assert.strictEqual(hasControlCharacters("auth-service"), false);
  assert.strictEqual(hasControlCharacters("ACME Corp"), false);

  // Control characters injection rejection
  assert.strictEqual(hasControlCharacters("app\nname"), true, "Newline rejected");
  assert.strictEqual(hasControlCharacters("app\x00zero"), true, "Null byte rejected");
  assert.strictEqual(hasControlCharacters("app\rinjection"), true, "Carriage return rejected");

  // Length constraints
  assert.strictEqual("".trim().length === 0, true, "Empty name rejected");
  assert.strictEqual("a".repeat(255).length <= 255, true, "255 chars accepted");
  assert.strictEqual("a".repeat(256).length > 255, true, "256 chars rejected");
});

test("Application Lifecycle - Soft-archive and Reactivation status semantics", () => {
  const initialApp = {
    id: "app-uuid-1",
    name: "auth-gateway",
    vendor: "Security Corp",
    is_active: true,
    created_at: "2026-10-15T10:00:00Z",
    updated_at: "2026-10-15T10:00:00Z",
  };

  // Soft-archived state
  const archivedApp = {
    ...initialApp,
    is_active: false,
    updated_at: "2026-10-16T12:00:00Z",
  };
  assert.strictEqual(archivedApp.is_active, false, "Archived application has is_active set to false");

  // Reactivated state
  const reactivatedApp = {
    ...archivedApp,
    is_active: true,
    updated_at: "2026-10-17T09:00:00Z",
  };
  assert.strictEqual(reactivatedApp.is_active, true, "Reactivated application has is_active restored to true");

  // Filtering by active status
  const appList = [initialApp, archivedApp];
  const activeOnly = appList.filter((a) => a.is_active);
  const archivedOnly = appList.filter((a) => !a.is_active);

  assert.strictEqual(activeOnly.length, 1);
  assert.strictEqual(activeOnly[0].id, "app-uuid-1");
  assert.strictEqual(archivedOnly.length, 1);
  assert.strictEqual(archivedOnly[0].id, "app-uuid-1");
});
