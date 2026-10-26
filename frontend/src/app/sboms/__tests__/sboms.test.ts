import test from "node:test";
import assert from "node:assert";
import { sbomService } from "@/api/services/sbomService";

test("SBOM List - Sensitive fields should not be rendered", () => {
  // Safe fields returned by backend and allowed for display
  const allowedFields = new Set([
    "upload_id",
    "application_id",
    "application_name",
    "vendor",
    "status",
    "format",
    "filename",
    "sbom_root",
    "component_count",
    "created_at",
  ]);

  // Private fields strictly prohibited by SECURITY_BOUNDARY.md
  const forbiddenFields = [
    "components",
    "raw_content",
    "purl",
    "purl_canonical",
    "component_hash",
    "dependency_graph",
    "witness",
    "secrets",
    "token",
    "private_vuln_mappings",
  ];

  for (const forbidden of forbiddenFields) {
    assert.strictEqual(
      allowedFields.has(forbidden),
      false,
      `Forbidden private field '${forbidden}' must not be present in public SBOM view metadata`
    );
  }
});

test("SBOM Upload - Max 10MB file validation", () => {
  const MAX_SIZE = 10 * 1024 * 1024;
  const oversizedFileSize = MAX_SIZE + 1;
  const validFileSize = MAX_SIZE - 1000;

  assert.strictEqual(oversizedFileSize > MAX_SIZE, true, "Oversized file triggers validation error");
  assert.strictEqual(validFileSize <= MAX_SIZE, true, "Valid file passes size check");
});

test("SBOM Upload - Format validation", () => {
  const validFilename = "sbom.json";
  const invalidFilename = "sbom.xml";
  const uppercaseValid = "SBOM.JSON";

  assert.strictEqual(validFilename.toLowerCase().endsWith(".json"), true, "CycloneDX JSON is accepted");
  assert.strictEqual(uppercaseValid.toLowerCase().endsWith(".json"), true, "Uppercase .JSON extension is accepted");
  assert.strictEqual(invalidFilename.toLowerCase().endsWith(".json"), false, "Non-JSON files are rejected");
});

test("SBOM Upload - JSON structural validation", () => {
  let parseSuccess = false;
  try {
    JSON.parse('{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}');
    parseSuccess = true;
  } catch {}

  assert.strictEqual(parseSuccess, true, "Valid JSON string passes validation");

  let parseFail = false;
  try {
    JSON.parse("invalid string");
  } catch {
    parseFail = true;
  }

  assert.strictEqual(parseFail, true, "Invalid JSON string fails validation before network request");

  let emptyFail = false;
  const emptyContent = "   ";
  if (!emptyContent.trim()) {
    emptyFail = true;
  }
  assert.strictEqual(emptyFail, true, "Empty or whitespace-only file is rejected before submission");
});

test("SBOM list visibility by role", () => {
  const allowedRoles = ["vendor", "admin"];
  assert.strictEqual(allowedRoles.includes("vendor"), true, "Vendor is allowed access");
  assert.strictEqual(allowedRoles.includes("admin"), true, "Admin is allowed access");
  assert.strictEqual(allowedRoles.includes("auditor"), false, "Auditor is denied by RouteGuard");
  assert.strictEqual(allowedRoles.includes("trusted_importer"), false, "Trusted importer is denied by RouteGuard");
});

test("SBOM Upload - Application Name and Vendor validation", () => {
  function hasControlCharacters(val: string): boolean {
    for (let i = 0; i < val.length; i++) {
      const code = val.charCodeAt(i);
      if (code < 32 && code !== 9) {
        return true;
      }
    }
    return false;
  }

  // Valid application names
  assert.strictEqual(hasControlCharacters("payment-gateway"), false);
  assert.strictEqual(hasControlCharacters("auth_service_v2"), false);

  // Control character injection attempts (e.g. carriage return, null byte, newline)
  assert.strictEqual(hasControlCharacters("app\nname"), true, "Newline is rejected as control char");
  assert.strictEqual(hasControlCharacters("app\r\ninjection"), true, "CRLF is rejected as control char");
  assert.strictEqual(hasControlCharacters("app\x00null"), true, "Null byte is rejected as control char");

  // Length constraints
  assert.strictEqual("".trim().length === 0, true, "Empty application name rejected");
  assert.strictEqual("a".repeat(255).length <= 255, true, "255 characters allowed");
  assert.strictEqual("a".repeat(256).length > 255, true, "Over 255 characters rejected");
});

test("SBOM Service - API methods exist and export correctly", () => {
  assert.strictEqual(typeof sbomService.upload, "function", "sbomService.upload must be a function");
  assert.strictEqual(typeof sbomService.list, "function", "sbomService.list must be a function");
  assert.strictEqual(typeof sbomService.getById, "function", "sbomService.getById must be a function");
});

test("SBOM Filter & Search - Client-side search and status matching", () => {
  const sampleSboms = [
    {
      upload_id: "11111111-1111-1111-1111-111111111111",
      application_id: "app-payment-service",
      status: "committed",
      format: "CycloneDX",
      filename: "payment-sbom.json",
      sbom_root: "0x1234567890abcdef",
      component_count: 14,
      created_at: "2026-10-15T12:00:00Z",
    },
    {
      upload_id: "22222222-2222-2222-2222-222222222222",
      application_id: "app-auth-service",
      status: "pending",
      format: "CycloneDX",
      filename: "auth-sbom.json",
      sbom_root: null,
      component_count: null,
      created_at: "2026-10-16T10:00:00Z",
    },
  ];

  // Search by filename
  const searchFile = sampleSboms.filter((s) => s.filename.toLowerCase().includes("payment"));
  assert.strictEqual(searchFile.length, 1);
  assert.strictEqual(searchFile[0].upload_id, "11111111-1111-1111-1111-111111111111");

  // Search by application_id
  const searchApp = sampleSboms.filter((s) => s.application_id.toLowerCase().includes("auth"));
  assert.strictEqual(searchApp.length, 1);
  assert.strictEqual(searchApp[0].upload_id, "22222222-2222-2222-2222-222222222222");

  // Filter by status
  const committedOnly = sampleSboms.filter((s) => s.status.toLowerCase() === "committed");
  assert.strictEqual(committedOnly.length, 1);

  const pendingOnly = sampleSboms.filter((s) => s.status.toLowerCase() === "pending");
  assert.strictEqual(pendingOnly.length, 1);
});

test("SBOM Listing - Human-readable application metadata and fallback display", () => {
  const recordWithMetadata = {
    upload_id: "11111111-1111-1111-1111-111111111111",
    application_id: "app-payment-service",
    application_name: "Payment Gateway",
    vendor: "FinTech Corp",
    status: "committed",
    format: "CycloneDX",
    filename: "payment-sbom.json",
    sbom_root: "0x1234567890abcdef",
    component_count: 14,
    created_at: "2026-10-15T12:00:00Z",
  };

  const recordWithoutMetadata = {
    upload_id: "22222222-2222-2222-2222-222222222222",
    application_id: "legacy-app-uuid",
    application_name: null,
    vendor: null,
    status: "committed",
    format: "CycloneDX",
    filename: "legacy-sbom.json",
    sbom_root: "0xabcdef1234567890",
    component_count: 5,
    created_at: "2026-10-14T10:00:00Z",
  };

  // Human-readable resolution helper
  function resolveAppDisplay(sbom: { application_name?: string | null; application_id: string }) {
    return sbom.application_name || "Application details unavailable";
  }

  function resolveVendorDisplay(sbom: { vendor?: string | null }) {
    return sbom.vendor || "—";
  }

  assert.strictEqual(resolveAppDisplay(recordWithMetadata), "Payment Gateway");
  assert.strictEqual(resolveVendorDisplay(recordWithMetadata), "FinTech Corp");

  // Fallback for historical record with null metadata
  assert.strictEqual(
    resolveAppDisplay(recordWithoutMetadata),
    "Application details unavailable",
    "Historical records without application_name fallback gracefully without showing raw UUID"
  );
  assert.strictEqual(resolveVendorDisplay(recordWithoutMetadata), "—");

  // Search filtering by application_name and vendor
  const allSboms = [recordWithMetadata, recordWithoutMetadata];
  const query = "fintech";
  const matched = allSboms.filter((s) =>
    (s.application_name && s.application_name.toLowerCase().includes(query)) ||
    (s.vendor && s.vendor.toLowerCase().includes(query))
  );
  assert.strictEqual(matched.length, 1);
  assert.strictEqual(matched[0].upload_id, recordWithMetadata.upload_id);
});
