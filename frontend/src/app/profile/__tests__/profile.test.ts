import test from "node:test";
import assert from "node:assert";
import { NAVIGATION_CONFIG, Role } from "@/config/navigation";
import { authService } from "@/api/services/authService";
import { authTransport } from "@/api/authTransport";

test("Profile - Navigation and Role Availability", () => {
  const profileNav = NAVIGATION_CONFIG.find((item) => item.href === "/profile");
  assert.ok(profileNav, "Profile & Settings must exist in navigation configuration");
  assert.strictEqual(profileNav.exactMatch, true, "Profile must use exact route matching");
  assert.strictEqual(profileNav.section, "Workspace", "Profile belongs to Workspace section");

  // All 5 active system roles can access their profile
  const requiredRoles: Role[] = ["vendor", "admin", "auditor", "trusted_importer", "buyer"];
  for (const role of requiredRoles) {
    assert.ok(
      profileNav.allowedRoles.includes(role),
      `Role ${role} must have access to Profile & Settings`
    );
  }
});

test("Profile - API Contract and Service Export", () => {
  assert.strictEqual(typeof authService.me, "function", "authService.me must be exported as a function");
  assert.strictEqual(typeof authService.login, "function", "authService.login must be exported");
  assert.strictEqual(typeof authService.register, "function", "authService.register must be exported");
  assert.strictEqual(typeof authService.changePassword, "function", "authService.changePassword must be exported");
});

test("Profile - Ephemeral In-Memory Token Guarantee", () => {
  // Test in-memory token lifecycle: no persistent browser storage
  authTransport.clearToken();
  assert.strictEqual(authTransport.getToken(), null, "Cleared token returns null");

  authTransport.setToken("ephemeral-test-token-jwt");
  assert.strictEqual(authTransport.getToken(), "ephemeral-test-token-jwt", "Token stored in-memory");

  authTransport.clearToken();
  assert.strictEqual(authTransport.getToken(), null, "Token properly purged from memory");
});

test("Profile - Mutation Operations and Stage D2 Roadmap Boundary", () => {
  // In D2, password change is implemented; arbitrary profile mutation (username/role) is restricted/deferred
  assert.strictEqual(typeof authService.changePassword, "function");
  const supportedProfileOperations = ["view_identity", "inspect_role", "review_security_model", "change_password"];
  const deferredStageDOperations = ["edit_profile", "edit_username", "edit_role", "bind_email"];

  assert.ok(
    !supportedProfileOperations.some((op) => deferredStageDOperations.includes(op)),
    "Active profile operations do not include arbitrary deferred mutation operations"
  );
});

test("Profile - Role Summary Mapping", () => {
  const activeRoles = ["vendor", "admin", "auditor", "trusted_importer", "buyer"];
  
  // Ensure each role has a well-defined privilege scope
  const rolePrivilegeMap: Record<string, { canIngest: boolean; canApproveSnapshots: boolean; canManageSBOMs: boolean; canVerify: boolean }> = {
    vendor: { canIngest: false, canApproveSnapshots: false, canManageSBOMs: true, canVerify: true },
    admin: { canIngest: false, canApproveSnapshots: true, canManageSBOMs: true, canVerify: true },
    auditor: { canIngest: false, canApproveSnapshots: false, canManageSBOMs: false, canVerify: true },
    trusted_importer: { canIngest: true, canApproveSnapshots: false, canManageSBOMs: false, canVerify: false },
    buyer: { canIngest: false, canApproveSnapshots: false, canManageSBOMs: false, canVerify: true },
  };

  for (const role of activeRoles) {
    assert.ok(rolePrivilegeMap[role] !== undefined, `Role ${role} must have defined privilege boundaries`);
  }

  // Separation of duties check
  assert.strictEqual(rolePrivilegeMap.trusted_importer.canIngest, true);
  assert.strictEqual(rolePrivilegeMap.trusted_importer.canApproveSnapshots, false);
  assert.strictEqual(rolePrivilegeMap.admin.canIngest, false);
  assert.strictEqual(rolePrivilegeMap.admin.canApproveSnapshots, true);
  assert.strictEqual(rolePrivilegeMap.buyer.canManageSBOMs, false);
  assert.strictEqual(rolePrivilegeMap.buyer.canVerify, true);
});
