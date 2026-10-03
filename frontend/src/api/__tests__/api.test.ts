import test from "node:test";
import assert from "node:assert";
import { authTransport } from "../authTransport";
import { ApiError } from "../errors";
import { apiClient } from "../client";

// Mock fetch globally
globalThis.fetch = globalThis.fetch;

test("authTransport keeps token in memory", () => {
  assert.strictEqual(authTransport.getToken(), null);
  authTransport.setToken("fake_token");
  assert.strictEqual(authTransport.getToken(), "fake_token");
  authTransport.clearToken();
  assert.strictEqual(authTransport.getToken(), null);
});

test("ApiError formats correctly", () => {
  const err = new ApiError("Validation failed", 422, "VALIDATION_ERROR");
  assert.strictEqual(err.message, "Validation failed");
  assert.strictEqual(err.status, 422);
  assert.strictEqual(err.code, "VALIDATION_ERROR");
});

test("public requests can omit the in-memory bearer token", async () => {
  const originalFetch = globalThis.fetch;
  let authorization: string | null = null;
  authTransport.setToken("test-only-token");
  globalThis.fetch = async (_input, init) => {
    authorization = new Headers(init?.headers).get("Authorization");
    return Response.json({ valid: true });
  };

  try {
    await apiClient("/public-validation", { method: "GET", skipAuth: true });
    assert.strictEqual(authorization, null);
  } finally {
    authTransport.clearToken();
    globalThis.fetch = originalFetch;
  }
});

test("401 clears the token and notifies the authentication provider", async () => {
  const originalFetch = globalThis.fetch;
  let unauthorizedNotifications = 0;
  authTransport.setToken("test-only-token");
  const unsubscribe = authTransport.subscribeUnauthorized(() => unauthorizedNotifications++);
  globalThis.fetch = async () => Response.json({ detail: "Unauthorized" }, { status: 401 });

  try {
    await assert.rejects(apiClient("/private-resource"), (error: unknown) =>
      error instanceof ApiError && error.status === 401
    );
    assert.strictEqual(authTransport.getToken(), null);
    assert.strictEqual(unauthorizedNotifications, 1);
  } finally {
    unsubscribe();
    authTransport.clearToken();
    globalThis.fetch = originalFetch;
  }
});
