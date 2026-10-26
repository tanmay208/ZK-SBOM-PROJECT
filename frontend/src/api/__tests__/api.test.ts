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

test("API client normalizes 403, 404, 422, and 429 status codes", async () => {
  const originalFetch = globalThis.fetch;

  try {
    // 403 Forbidden
    globalThis.fetch = async () => Response.json({ detail: "Forbidden access" }, { status: 403 });
    await assert.rejects(apiClient("/forbidden"), (err: unknown) => {
      return err instanceof ApiError && err.status === 403 && err.code === "FORBIDDEN";
    });

    // 404 Not Found
    globalThis.fetch = async () => Response.json({ detail: "Resource not found" }, { status: 404 });
    await assert.rejects(apiClient("/missing"), (err: unknown) => {
      return err instanceof ApiError && err.status === 404 && err.code === "NOT_FOUND";
    });

    // 422 Unprocessable Entity
    globalThis.fetch = async () => Response.json({ detail: [{ msg: "field required", loc: ["body", "purl"] }] }, { status: 422 });
    await assert.rejects(apiClient("/invalid-schema"), (err: unknown) => {
      return err instanceof ApiError && err.status === 422 && (err.code === "VALIDATION_ERROR" || err.code === "UNPROCESSABLE_ENTITY");
    });

    // 429 Too Many Requests
    globalThis.fetch = async () => Response.json({ detail: "A proof job is already active for this user" }, { status: 429 });
    await assert.rejects(apiClient("/rate-limited"), (err: unknown) => {
      return err instanceof ApiError && err.status === 429 && err.code === "TOO_MANY_REQUESTS";
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("API client extracts Retry-After header and sets retryAfter property on 429", async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ detail: "Rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "30" },
      });

    await assert.rejects(apiClient("/rate-limited-retry"), (err: unknown) => {
      assert.ok(err instanceof ApiError);
      assert.strictEqual(err.status, 429);
      assert.strictEqual(err.retryAfter, 30);
      assert.ok(err.message.includes("30 seconds"));
      return true;
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("API Service Endpoints conform to consistent route contracts", async () => {
  const originalFetch = globalThis.fetch;
  const recordedCalls: { url: string; method: string; body?: unknown }[] = [];

  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    recordedCalls.push({
      url,
      method: init?.method || "GET",
      body: init?.body ? JSON.parse(init.body as string) : undefined
    });
    return Response.json({ status: "ok" });
  };

  try {
    const { vulnerabilityService } = await import("../services/vulnerabilityService");
    const { metricsService } = await import("../services/metricsService");
    const { proofService } = await import("../services/proofService");
    const { sbomService } = await import("../services/sbomService");

    // Test freeze snapshot endpoint
    await vulnerabilityService.freeze("test-uuid-1");
    assert.ok(recordedCalls.some(c => c.url.includes("/api/v1/vulnerability/snapshots/test-uuid-1/freeze") && c.method === "POST"));

    // Test revoke snapshot with optional reason
    await vulnerabilityService.revoke("test-uuid-2", "compromised feed");
    assert.ok(recordedCalls.some(c => c.url.includes("/api/v1/vulnerability/snapshots/test-uuid-2/revoke") && c.method === "POST" && (c.body as Record<string, unknown>)?.reason === "compromised feed"));

    // Test metrics service call
    await metricsService.getMetrics();
    assert.ok(recordedCalls.some(c => c.url.includes("/api/v1/metrics") && c.method === "GET"));

    // Test proof list service call
    await proofService.list();
    assert.ok(recordedCalls.some(c => c.url.includes("/api/v1/zkp") && c.method === "GET"));

    // Test sbom list service call
    await sbomService.list();
    assert.ok(recordedCalls.some(c => c.url.includes("/api/v1/sbom") && c.method === "GET"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
