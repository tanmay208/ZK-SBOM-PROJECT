import test from "node:test";
import assert from "node:assert";
import { parseUtcTimestamp, formatToIST, formatTableTimestamp } from "../dateTime";
import { calculateProofEta, formatRemainingDuration } from "../etaCalculator";
import { ProofJobResponse } from "@/api/types";

// ============================================================================
// 1. Timezone Parsing & Formatting Tests
// ============================================================================

test("parseUtcTimestamp correctly parses naive UTC ISO strings from backend", () => {
  const parsed = parseUtcTimestamp("2026-10-27T05:35:19.936489");
  assert.ok(parsed !== null, "Parsed date must not be null");
  assert.strictEqual(parsed.getUTCFullYear(), 2026);
  assert.strictEqual(parsed.getUTCMonth(), 9); // October is 9
  assert.strictEqual(parsed.getUTCDate(), 27);
  assert.strictEqual(parsed.getUTCHours(), 5);
  assert.strictEqual(parsed.getUTCMinutes(), 35);
  assert.strictEqual(parsed.getUTCSeconds(), 19);
  assert.strictEqual(parsed.getUTCMilliseconds(), 936);
});

test("parseUtcTimestamp correctly parses explicit UTC with Z suffix", () => {
  const parsed = parseUtcTimestamp("2026-10-27T05:35:19.936Z");
  assert.ok(parsed !== null);
  assert.strictEqual(parsed.getUTCHours(), 5);
  assert.strictEqual(parsed.getUTCMinutes(), 35);
});

test("parseUtcTimestamp correctly preserves explicit offsets", () => {
  const parsed = parseUtcTimestamp("2026-10-27T11:05:19+05:30");
  assert.ok(parsed !== null);
  // 11:05:19 +05:30 is 05:35:19 UTC
  assert.strictEqual(parsed.getUTCHours(), 5);
  assert.strictEqual(parsed.getUTCMinutes(), 35);
  assert.strictEqual(parsed.getUTCSeconds(), 19);
});

test("formatToIST converts UTC timestamp to Asia/Kolkata with IST label", () => {
  const formatted = formatToIST("2026-10-27T05:35:19.936489", { includeSeconds: true });
  // 05:35:19 UTC + 5h30m = 11:05:19 AM IST
  assert.match(formatted, /11:05:19/, "Time must reflect +05:30 offset");
  assert.match(formatted, /IST$/, "Must be explicitly labeled IST");
  assert.match(formatted, /Oct 27, 2026/, "Date must reflect Oct 27, 2026");
});

test("formatTableTimestamp formats compact table view with IST label", () => {
  const formatted = formatTableTimestamp("2026-10-27T05:35:19.936489");
  assert.match(formatted, /11:05 AM/, "Must format hour and minute in 12-hour format");
  assert.match(formatted, /IST$/, "Must be labeled IST");
});

test("Timezone handling around midnight rollovers", () => {
  // Case A: 23:45 UTC on Oct 26 -> 05:15 AM on Oct 27 in IST (Next day in IST)
  const midnightNextDay = formatToIST("2026-10-26T23:45:00", { includeSeconds: false });
  assert.match(midnightNextDay, /Oct 27, 2026/);
  assert.match(midnightNextDay, /05:15 AM IST/);

  // Case B: 18:30 UTC on Oct 26 -> 12:00 AM on Oct 27 in IST (Exact midnight rollover in IST)
  const exactMidnight = formatToIST("2026-10-26T18:30:00", { includeSeconds: true });
  assert.match(exactMidnight, /Oct 27, 2026/);
  assert.match(exactMidnight, /12:00:00 AM IST/);

  // Case C: 00:15 UTC on Oct 27 -> 05:45 AM on Oct 27 in IST
  const earlyMorning = formatToIST("2026-10-27T00:15:00", { includeSeconds: false });
  assert.match(earlyMorning, /Oct 27, 2026/);
  assert.match(earlyMorning, /05:45 AM IST/);
});

test("Missing and malformed timestamps handle gracefully", () => {
  assert.strictEqual(formatToIST(null), "—", "Null must format as em dash");
  assert.strictEqual(formatToIST(undefined), "—", "Undefined must format as em dash");
  assert.strictEqual(formatToIST(""), "—", "Empty string must format as em dash");
  assert.strictEqual(formatToIST("not-a-real-date"), "Invalid date", "Malformed string must format as Invalid date");
  assert.strictEqual(formatToIST("2026-99-99T99:99:99"), "Invalid date", "Out of bounds date must format as Invalid date");
  assert.strictEqual(parseUtcTimestamp(null), null);
  assert.strictEqual(parseUtcTimestamp("garbage"), null);
});

// ============================================================================
// 2. Truthful ETA Calculation Tests
// ============================================================================

function createMockJobWithSegments(completionTimestampsUtc: string[], status: "running" | "completed" | "failed" = "running"): ProofJobResponse {
  const segments = completionTimestampsUtc.map((ts, idx) => ({
    id: `seg-${idx}`,
    chunk_id: `chunk-0`,
    chunk_index: 0,
    total_chunks: 32,
    segment_index: idx % 8,
    status: "completed",
    created_at: "2026-10-27T05:35:19Z",
    completed_at: ts,
  }));

  return {
    id: "mock-job-id",
    sbom_upload_id: "mock-sbom-id",
    snapshot_id: "mock-snapshot-id",
    policy_id: "mock-policy-id",
    status,
    sbom_root: "0xroot",
    vulnerability_db_root: "0xvuln",
    policy_hash: "0xpolicy",
    proof_artifact: null,
    error_message: null,
    created_at: "2026-10-27T05:35:19Z",
    completed_at: status === "completed" ? completionTimestampsUtc[completionTimestampsUtc.length - 1] : null,
    chunks: [
      {
        id: "chunk-0",
        proof_job_id: "mock-job-id",
        chunk_index: 0,
        total_chunks: 32,
        component_start: 0,
        component_count: 32,
        components_commit: "0xcommit",
        status: status === "completed" ? "completed" : "running",
        created_at: "2026-10-27T05:35:19Z",
        segments,
      },
    ],
  };
}

test("calculateProofEta returns idle for null or empty job", () => {
  const eta = calculateProofEta(null);
  assert.strictEqual(eta.status, "idle");
  assert.strictEqual(eta.completedSegments, 0);
  assert.strictEqual(eta.totalSegments, 256);
  assert.strictEqual(eta.formattedRemainingTime, "—");
});

test("calculateProofEta requires at least 3 samples before estimating ETA", () => {
  // Only 2 completed segments
  const mockJob = createMockJobWithSegments([
    "2026-10-27T05:38:00Z",
    "2026-10-27T05:39:10Z",
  ]);

  const eta = calculateProofEta(mockJob, Date.parse("2026-10-27T05:39:30Z"));
  assert.strictEqual(eta.status, "calibrating");
  assert.strictEqual(eta.completedSegments, 2);
  assert.match(eta.formattedRemainingTime, /Calibrating ETA/);
  assert.strictEqual(eta.estimatedRemainingSeconds, null);
});

test("calculateProofEta computes truthful rolling-window ETA from valid samples", () => {
  // 5 segments, each spaced exactly 70 seconds apart
  const timestamps = [
    "2026-10-27T05:38:00Z",
    "2026-10-27T05:39:10Z", // +70s
    "2026-10-27T05:40:20Z", // +70s
    "2026-10-27T05:41:30Z", // +70s
    "2026-10-27T05:42:40Z", // +70s
  ];
  const mockJob = createMockJobWithSegments(timestamps);
  const currentTime = Date.parse("2026-10-27T05:42:50Z"); // 10s after last completion

  const eta = calculateProofEta(mockJob, currentTime);
  assert.strictEqual(eta.status, "progressing");
  assert.strictEqual(eta.completedSegments, 5);
  assert.strictEqual(eta.totalSegments, 256);
  assert.strictEqual(eta.remainingSegments, 251);
  assert.strictEqual(eta.rollingAvgSeconds, 70);

  // Remaining: 251 segments * 70s - 10s elapsed on current = 17560s = ~4h 52m
  assert.ok(eta.estimatedRemainingSeconds !== null);
  assert.strictEqual(eta.estimatedRemainingSeconds, 17560);
  assert.strictEqual(eta.formattedRemainingTime, "~4h 52m (approximate)");
  assert.ok(eta.formattedEstCompletionIST !== null);
  assert.match(eta.formattedEstCompletionIST, /IST$/);
  assert.strictEqual(eta.isStale, false);
});

test("calculateProofEta triggers stale warning when progress halts", () => {
  // Average segment duration: ~60s
  const timestamps = [
    "2026-10-27T05:38:00Z",
    "2026-10-27T05:39:00Z",
    "2026-10-27T05:40:00Z",
    "2026-10-27T05:41:00Z",
  ];
  const mockJob = createMockJobWithSegments(timestamps);
  // Stale threshold is max(300s, 60s * 3.5 = 210s) = 300s (5 minutes).
  // Simulate 12 minutes since last completed segment
  const stalledTime = Date.parse("2026-10-27T05:53:00Z"); // 12 minutes after 05:41:00

  const eta = calculateProofEta(mockJob, stalledTime);
  assert.strictEqual(eta.status, "stale");
  assert.strictEqual(eta.isStale, true);
  assert.strictEqual(eta.formattedRemainingTime, "Stalled (stale progress)");
  assert.ok(eta.staleWarning !== null);
  assert.match(eta.staleWarning, /Stale progress warning/);
  assert.match(eta.staleWarning, /12 min/);
});

test("calculateProofEta handles terminal states correctly", () => {
  const completedJob = createMockJobWithSegments([
    "2026-10-27T05:38:00Z",
    "2026-10-27T05:39:00Z",
    "2026-10-27T05:40:00Z",
  ], "completed");

  const completedEta = calculateProofEta(completedJob);
  assert.strictEqual(completedEta.status, "completed");
  assert.strictEqual(completedEta.progressPercent, 100);
  assert.strictEqual(completedEta.formattedRemainingTime, "Completed");
  assert.strictEqual(completedEta.estimatedRemainingSeconds, 0);

  const failedJob = createMockJobWithSegments([
    "2026-10-27T05:38:00Z",
  ], "failed");
  const failedEta = calculateProofEta(failedJob);
  assert.strictEqual(failedEta.status, "failed");
  assert.strictEqual(failedEta.formattedRemainingTime, "Failed");
});

test("formatRemainingDuration formats minutes and hours cleanly", () => {
  assert.strictEqual(formatRemainingDuration(20), "< 1 min (approximate)");
  assert.strictEqual(formatRemainingDuration(35), "~0m (approximate)");
  assert.strictEqual(formatRemainingDuration(180), "~3m (approximate)");
  assert.strictEqual(formatRemainingDuration(3660), "~1h 1m (approximate)");
  assert.strictEqual(formatRemainingDuration(17400), "~4h 50m (approximate)");
});
