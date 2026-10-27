import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { formatTableTimestamp } from "../../lib/dateTime";

test("Forensic Remediation - Zero raw LaTeX math delimiters in frontend page sources", () => {
  const routesToCheck = [
    "src/app/page.tsx",
    "src/app/dashboard/page.tsx",
    "src/app/admin/page.tsx",
    "src/app/admin/policies/page.tsx",
    "src/app/sboms/upload/page.tsx",
  ];

  const frontendRoot = path.resolve(__dirname, "../../..");

  for (const relativePath of routesToCheck) {
    const fullPath = path.join(frontendRoot, relativePath);
    assert.ok(fs.existsSync(fullPath), `File should exist: ${relativePath}`);

    const content = fs.readFileSync(fullPath, "utf-8");

    // Must not contain escaped curly-brace LaTeX patterns like _{" or $_{
    assert.strictEqual(
      content.includes('_{"'),
      false,
      `File ${relativePath} contains raw LaTeX delimiter _{"`
    );

    // Must not contain raw LaTeX math wrappers like ($R_{ or ($H_{
    assert.strictEqual(
      content.includes("($R_{"),
      false,
      `File ${relativePath} contains raw LaTeX delimiter ($R_{`
    );
    assert.strictEqual(
      content.includes("($H_{"),
      false,
      `File ${relativePath} contains raw LaTeX delimiter ($H_{`
    );

    // Must not contain raw Poseidon parameter delimiters ($t=
    assert.strictEqual(
      content.includes("($t="),
      false,
      `File ${relativePath} contains raw LaTeX delimiter ($t=`
    );
  }
});

test("Forensic Remediation - Standardized table timestamp formatting across resources", () => {
  // Test certificate issued_at naive ISO
  const certIssuedAt = "2026-10-27T07:15:00.000000";
  const formattedCert = formatTableTimestamp(certIssuedAt);
  assert.ok(formattedCert.includes("IST"), "Formatted certificate timestamp must include IST");
  assert.ok(formattedCert.includes("12:45 PM"), "07:15 UTC must convert to 12:45 PM IST");

  // Test application created_at naive ISO
  const appCreatedAt = "2026-10-25T18:30:00";
  const formattedApp = formatTableTimestamp(appCreatedAt);
  assert.ok(formattedApp.includes("IST"), "Formatted application timestamp must include IST");
  assert.ok(formattedApp.includes("12:00 AM"), "18:30 UTC must convert to 12:00 AM IST (next day)");
  assert.ok(formattedApp.includes("Oct 26"), "18:30 UTC must roll over to Oct 26");

  // Test null / undefined / empty
  assert.strictEqual(formatTableTimestamp(null), "—");
  assert.strictEqual(formatTableTimestamp(undefined), "—");
  assert.strictEqual(formatTableTimestamp(""), "—");

  // Test malformed
  assert.strictEqual(formatTableTimestamp("invalid-iso-string"), "Invalid date");
});

test("Forensic Remediation - Centralized table UI component has overflow-x-auto safeguard", () => {
  const tableComponentPath = path.resolve(__dirname, "../../components/ui/table.tsx");
  assert.ok(fs.existsSync(tableComponentPath), "Table UI component must exist");

  const tableSource = fs.readFileSync(tableComponentPath, "utf-8");
  assert.ok(
    tableSource.includes("overflow-x-auto"),
    "Table component must wrap tables in overflow-x-auto container for responsive safety"
  );
  assert.ok(
    tableSource.includes('data-slot="table-container"'),
    "Table component must provide data-slot='table-container'"
  );
});
