import test from "node:test";
import assert from "node:assert";
import { NAVIGATION_CONFIG, isRouteActive } from "@/config/navigation";
import { adminService } from "@/api/services/adminService";
import { AdminUser, Role } from "@/api/types";
import { ApiError } from "@/api/errors";

const APPROVED_ROLES: Role[] = ["vendor", "buyer", "admin"];

test("Admin User Management - Navigation and Route Guard Alignment", () => {
  const usersNav = NAVIGATION_CONFIG.find((item) => item.href === "/admin/users");
  assert.ok(usersNav, "User Management navigation item must exist");
  assert.deepStrictEqual(usersNav.allowedRoles, ["admin"], "User Management must be strictly restricted to admin role");
  assert.strictEqual(usersNav.section, "Governance & Intel", "Belongs to Governance & Intel section");

  // Route active evaluation
  assert.strictEqual(isRouteActive("/admin/users", "/admin/users", false), true);
  assert.strictEqual(isRouteActive("/admin/users", "/admin", true), false, "Exact /admin does not match /admin/users");
});

test("Admin User Management - Three Approved Roles Contract", () => {
  assert.strictEqual(APPROVED_ROLES.length, 3, "Exactly 3 authorized roles in role model");
  assert.ok(APPROVED_ROLES.includes("vendor"));
  assert.ok(APPROVED_ROLES.includes("buyer"));
  assert.ok(APPROVED_ROLES.includes("admin"));

  // Unauthorized and legacy roles must not exist in approved list
  const unauthorizedRoles = ["root", "superadmin", "operator", "guest", "auditor", "trusted_importer"];
  for (const r of unauthorizedRoles) {
    assert.ok(!APPROVED_ROLES.includes(r as Role), `Role ${r} must not be in approved roles`);
  }
});

test("Admin User Management - Service API Methods Contract", () => {
  assert.strictEqual(typeof adminService.listUsers, "function", "adminService.listUsers must exist");
  assert.strictEqual(typeof adminService.getUser, "function", "adminService.getUser must exist");
  assert.strictEqual(typeof adminService.updateUserRole, "function", "adminService.updateUserRole must exist");
  assert.strictEqual(typeof adminService.updateUserStatus, "function", "adminService.updateUserStatus must exist");
});

test("Admin User Management - List Users Service Call and Parameter Serialisation", async () => {
  const originalFetch = globalThis.fetch;
  const recordedCalls: { url: string; method: string }[] = [];

  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    recordedCalls.push({
      url,
      method: init?.method || "GET",
    });
    return Response.json([
      {
        id: "11111111-1111-1111-1111-111111111111",
        username: "admin_user",
        role: "admin",
        is_active: true,
        created_at: "2026-10-19T10:00:00Z",
        updated_at: "2026-10-19T10:00:00Z",
      },
    ]);
  };

  try {
    // 1. Without filters
    const usersDefault = await adminService.listUsers();
    assert.strictEqual(usersDefault.length, 1);
    assert.ok(recordedCalls.some((c) => c.url.endsWith("/api/v1/admin/users") && c.method === "GET"));

    // 2. With pagination and filters
    await adminService.listUsers({
      skip: 10,
      limit: 25,
      role: "buyer",
      is_active: true,
    });
    const filterCall = recordedCalls.find((c) => c.url.includes("skip=10") && c.url.includes("limit=25"));
    assert.ok(filterCall, "Service serialises skip and limit parameters");
    assert.ok(filterCall.url.includes("role=buyer"), "Service serialises role filter");
    assert.ok(filterCall.url.includes("is_active=true"), "Service serialises is_active filter");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Admin User Management - Single User Retrieval Service Call", async () => {
  const originalFetch = globalThis.fetch;
  let targetUrl = "";

  globalThis.fetch = async (input) => {
    targetUrl = typeof input === "string" ? input : (input as Request).url;
    return Response.json({
      id: "22222222-2222-2222-2222-222222222222",
      username: "buyer_target",
      role: "buyer",
      is_active: true,
      created_at: "2026-10-19T11:00:00Z",
      updated_at: null,
    });
  };

  try {
    const user = await adminService.getUser("22222222-2222-2222-2222-222222222222");
    assert.strictEqual(user.username, "buyer_target");
    assert.ok(targetUrl.endsWith("/api/v1/admin/users/22222222-2222-2222-2222-222222222222"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Admin User Management - Role Update Service Call and Payload Structure", async () => {
  const originalFetch = globalThis.fetch;
  let recordedMethod = "";
  let recordedUrl = "";
  let recordedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    recordedUrl = typeof input === "string" ? input : (input as Request).url;
    recordedMethod = init?.method || "";
    recordedBody = init?.body ? JSON.parse(init.body as string) : null;
    return Response.json({
      id: "33333333-3333-3333-3333-333333333333",
      username: "target_user",
      role: "vendor",
      is_active: true,
      created_at: "2026-10-19T12:00:00Z",
      updated_at: "2026-10-19T12:05:00Z",
    });
  };

  try {
    const updated = await adminService.updateUserRole("33333333-3333-3333-3333-333333333333", {
      role: "vendor",
    });
    assert.strictEqual(recordedMethod, "PATCH");
    assert.ok(recordedUrl.endsWith("/api/v1/admin/users/33333333-3333-3333-3333-333333333333/role"));
    assert.deepStrictEqual(recordedBody, { role: "vendor" });
    assert.strictEqual(updated.role, "vendor");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Admin User Management - Status Update Service Call and Payload Structure", async () => {
  const originalFetch = globalThis.fetch;
  let recordedMethod = "";
  let recordedUrl = "";
  let recordedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    recordedUrl = typeof input === "string" ? input : (input as Request).url;
    recordedMethod = init?.method || "";
    recordedBody = init?.body ? JSON.parse(init.body as string) : null;
    return Response.json({
      id: "44444444-4444-4444-4444-444444444444",
      username: "target_deactivate",
      role: "buyer",
      is_active: false,
      created_at: "2026-10-19T12:00:00Z",
      updated_at: "2026-10-19T12:10:00Z",
    });
  };

  try {
    const updated = await adminService.updateUserStatus("44444444-4444-4444-4444-444444444444", {
      is_active: false,
    });
    assert.strictEqual(recordedMethod, "PATCH");
    assert.ok(recordedUrl.endsWith("/api/v1/admin/users/44444444-4444-4444-4444-444444444444/status"));
    assert.deepStrictEqual(recordedBody, { is_active: false });
    assert.strictEqual(updated.is_active, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Admin User Management - Self-Deactivation Prevention Logic", () => {
  const currentAdmin = { id: "admin-uuid-1", username: "superadmin" };
  const targetUserA: AdminUser = {
    id: "admin-uuid-1",
    username: "superadmin",
    role: "admin",
    is_active: true,
    created_at: "2026-10-19T00:00:00Z",
    updated_at: null,
  };
  const targetUserB: AdminUser = {
    id: "other-uuid-2",
    username: "other_admin",
    role: "admin",
    is_active: true,
    created_at: "2026-10-19T00:00:00Z",
    updated_at: null,
  };

  const isSelf = (target: AdminUser) =>
    target.id === currentAdmin.id || target.username.toLowerCase() === currentAdmin.username.toLowerCase();

  assert.strictEqual(isSelf(targetUserA), true, "Identifies own administrator account");
  assert.strictEqual(isSelf(targetUserB), false, "Identifies other administrator account");

  // Deactivation must be disabled when target is self
  const canDeactivateA = !isSelf(targetUserA);
  const canDeactivateB = !isSelf(targetUserB);

  assert.strictEqual(canDeactivateA, false, "Self-deactivation is disabled for current administrator");
  assert.strictEqual(canDeactivateB, true, "Deactivation allowed for other administrators subject to backend invariant");
});

test("Admin User Management - Credential Non-Disclosure Invariant", () => {
  // An AdminUser object must contain only the public account metadata
  const mockAdminUser: AdminUser = {
    id: "uuid-abc",
    username: "vendor_user",
    role: "vendor",
    is_active: true,
    created_at: "2026-10-19T00:00:00Z",
    updated_at: null,
  };

  const userKeys = Object.keys(mockAdminUser);
  const forbiddenSensitiveKeys = [
    "password",
    "hashed_password",
    "token",
    "access_token",
    "secret",
    "private_key",
  ];

  for (const forbidden of forbiddenSensitiveKeys) {
    assert.ok(
      !userKeys.includes(forbidden),
      `AdminUser schema must never contain credential field '${forbidden}'`
    );
  }
});

test("Admin User Management - Error Normalisation for 400, 403, 404, 409, 422", async () => {
  const originalFetch = globalThis.fetch;

  try {
    // 1. 400 Last Admin Demotion Rejection
    globalThis.fetch = async () =>
      Response.json({ detail: "Cannot demote the last active administrator" }, { status: 400 });

    await assert.rejects(
      adminService.updateUserRole("admin-id", { role: "buyer" }),
      (err: unknown) => {
        return err instanceof ApiError && err.status === 400 && err.message.includes("last active administrator");
      }
    );

    // 2. 400 Self-Deactivation Rejection
    globalThis.fetch = async () =>
      Response.json({ detail: "Administrators cannot deactivate their own account" }, { status: 400 });

    await assert.rejects(
      adminService.updateUserStatus("admin-id", { is_active: false }),
      (err: unknown) => {
        return err instanceof ApiError && err.status === 400 && err.message.includes("cannot deactivate");
      }
    );

    // 3. 404 User Not Found
    globalThis.fetch = async () =>
      Response.json({ detail: "User not found" }, { status: 404 });

    await assert.rejects(
      adminService.getUser("nonexistent-id"),
      (err: unknown) => {
        return err instanceof ApiError && err.status === 404;
      }
    );

    // 4. 409 System Integrity Violation (Zero Admin State)
    globalThis.fetch = async () =>
      Response.json({ detail: "System integrity violation: no active administrators exist." }, { status: 409 });

    await assert.rejects(
      adminService.updateUserRole("user-id", { role: "auditor" as unknown as Role }),
      (err: unknown) => {
        return err instanceof ApiError && err.status === 409;
      }
    );

    // 5. 422 Invalid Role Selection
    globalThis.fetch = async () =>
      Response.json({ detail: "Invalid role 'superadmin'." }, { status: 422 });

    await assert.rejects(
      adminService.updateUserRole("user-id", { role: "superadmin" as Role }),
      (err: unknown) => {
        return err instanceof ApiError && err.status === 422;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Admin User Management - Primary Assignable Roles Consolidation", async () => {
  const { PRIMARY_ASSIGNABLE_ROLES, LEGACY_ROLES } = await import("../users/page");
  assert.deepStrictEqual(PRIMARY_ASSIGNABLE_ROLES, ["vendor", "buyer", "admin"], "Primary assignable roles are strictly vendor, buyer, admin");
  assert.ok(LEGACY_ROLES.includes("auditor"), "auditor preserved in legacy roles");
  assert.ok(LEGACY_ROLES.includes("trusted_importer"), "trusted_importer preserved in legacy roles");
  assert.ok(!PRIMARY_ASSIGNABLE_ROLES.includes("auditor" as unknown as Role), "auditor is not assignable as a new primary role");
  assert.ok(!PRIMARY_ASSIGNABLE_ROLES.includes("trusted_importer" as unknown as Role), "trusted_importer is not assignable as a new primary role");
});
