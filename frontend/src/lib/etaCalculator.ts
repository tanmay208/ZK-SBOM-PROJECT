/**
 * Dynamic, truthful ETA calculation for Zero-Knowledge Proof Jobs.
 *
 * Invariants & Requirements:
 * 1. Progress is computed from persisted completed segments vs total segments (32 * 8 = 256).
 * 2. Time estimation is strictly derived from a rolling window of recent completed segment intervals.
 * 3. Never hardcode an assumed duration or assume segments are identical.
 * 4. Show an ETA only after sufficient valid progress samples exist (minimum 3 samples).
 * 5. Factors in elapsed time on the currently executing segment for smooth countdown.
 * 6. Detects stalled progress if no segment completes beyond the threshold (3.5x rolling avg or 300s).
 * 7. Explicitly marks projections as "(approximate)".
 */

import { ProofJobResponse } from "@/api/types";
import { parseUtcTimestamp, formatToIST } from "./dateTime";

export type EtaStatus = "idle" | "calibrating" | "progressing" | "stale" | "completed" | "failed";

export interface EtaCalculationResult {
  status: EtaStatus;
  completedSegments: number;
  totalSegments: number;
  remainingSegments: number;
  completedChunks: number;
  totalChunks: number;
  activeChunkIndex: number | null;
  progressPercent: number;
  rollingAvgSeconds: number | null;
  samplesCount: number;
  estimatedRemainingSeconds: number | null;
  formattedRemainingTime: string;
  formattedEstCompletionIST: string | null;
  isStale: boolean;
  secondsSinceLastProgress: number | null;
  staleWarning: string | null;
  lastProgressTimestamp: Date | null;
}

interface CompletedSample {
  chunkIndex: number;
  segmentIndex: number;
  completedAt: Date;
}

/**
 * Calculates a truthful, sample-backed ETA for a proof job.
 * @param job The proof job containing chunks and segments.
 * @param currentTimeMs Optional epoch timestamp in ms (defaults to Date.now(), useful for testing).
 */
export function calculateProofEta(
  job: ProofJobResponse | null | undefined,
  currentTimeMs: number = Date.now()
): EtaCalculationResult {
  if (!job) {
    return {
      status: "idle",
      completedSegments: 0,
      totalSegments: 256,
      remainingSegments: 256,
      completedChunks: 0,
      totalChunks: 32,
      activeChunkIndex: null,
      progressPercent: 0,
      rollingAvgSeconds: null,
      samplesCount: 0,
      estimatedRemainingSeconds: null,
      formattedRemainingTime: "—",
      formattedEstCompletionIST: null,
      isStale: false,
      secondsSinceLastProgress: null,
      staleWarning: null,
      lastProgressTimestamp: null,
    };
  }

  const firstChunkTotal = job.chunks?.[0]?.total_chunks;
  const totalChunks = firstChunkTotal || (job.chunks?.length && job.chunks.length > 1 ? job.chunks.length : 32);
  const totalSegments = totalChunks * 8;

  // Extract all valid completed segment timestamps
  const completedSamples: CompletedSample[] = [];
  let completedChunksCount = 0;
  let activeChunkIdx: number | null = null;

  if (job.chunks && job.chunks.length > 0) {
    for (const chunk of job.chunks) {
      if (chunk.status === "completed") {
        completedChunksCount++;
      } else if (chunk.status === "running" && activeChunkIdx === null) {
        activeChunkIdx = chunk.chunk_index;
      }

      if (chunk.segments && chunk.segments.length > 0) {
        for (const seg of chunk.segments) {
          if (seg.status === "completed" && seg.completed_at) {
            const parsed = parseUtcTimestamp(seg.completed_at);
            if (parsed) {
              completedSamples.push({
                chunkIndex: chunk.chunk_index,
                segmentIndex: seg.segment_index,
                completedAt: parsed,
              });
            }
          }
        }
      }
    }
  }

  // Sort completed samples chronologically
  completedSamples.sort((a, b) => a.completedAt.getTime() - b.completedAt.getTime());

  const completedSegments = completedSamples.length;
  const remainingSegments = Math.max(0, totalSegments - completedSegments);
  const progressPercent = totalSegments > 0 ? Math.min(100, Math.round((completedSegments / totalSegments) * 100)) : 0;
  const lastProgressDate = completedSamples.length > 0 ? completedSamples[completedSamples.length - 1].completedAt : null;

  // Terminal State: Completed
  if (job.status === "completed" || completedSegments >= totalSegments) {
    return {
      status: "completed",
      completedSegments,
      totalSegments,
      remainingSegments: 0,
      completedChunks: totalChunks,
      totalChunks,
      activeChunkIndex: null,
      progressPercent: 100,
      rollingAvgSeconds: null,
      samplesCount: completedSamples.length,
      estimatedRemainingSeconds: 0,
      formattedRemainingTime: "Completed",
      formattedEstCompletionIST: formatToIST(job.completed_at || lastProgressDate),
      isStale: false,
      secondsSinceLastProgress: null,
      staleWarning: null,
      lastProgressTimestamp: lastProgressDate,
    };
  }

  // Terminal State: Failed or Blocked
  if (job.status === "failed" || job.status === "execution_blocked") {
    return {
      status: "failed",
      completedSegments,
      totalSegments,
      remainingSegments,
      completedChunks: completedChunksCount,
      totalChunks,
      activeChunkIndex: null,
      progressPercent,
      rollingAvgSeconds: null,
      samplesCount: completedSamples.length,
      estimatedRemainingSeconds: null,
      formattedRemainingTime: "Failed",
      formattedEstCompletionIST: null,
      isStale: false,
      secondsSinceLastProgress: null,
      staleWarning: job.error_message || "Proof generation terminated",
      lastProgressTimestamp: lastProgressDate,
    };
  }

  // Minimum 3 progress samples required before presenting an ETA
  const MIN_SAMPLES_FOR_ETA = 3;
  if (completedSamples.length < MIN_SAMPLES_FOR_ETA) {
    return {
      status: "calibrating",
      completedSegments,
      totalSegments,
      remainingSegments,
      completedChunks: completedChunksCount,
      totalChunks,
      activeChunkIndex: activeChunkIdx,
      progressPercent,
      rollingAvgSeconds: null,
      samplesCount: completedSamples.length,
      estimatedRemainingSeconds: null,
      formattedRemainingTime: `Calibrating ETA (${completedSamples.length}/${MIN_SAMPLES_FOR_ETA} samples)...`,
      formattedEstCompletionIST: null,
      isStale: false,
      secondsSinceLastProgress: lastProgressDate ? Math.max(0, (currentTimeMs - lastProgressDate.getTime()) / 1000) : null,
      staleWarning: null,
      lastProgressTimestamp: lastProgressDate,
    };
  }

  // Compute rolling window of recent segment intervals (up to 10 intervals from the last 11 samples)
  const ROLLING_WINDOW_SIZE = 10;
  const recentSamples = completedSamples.slice(-(ROLLING_WINDOW_SIZE + 1));
  const validIntervalsSec: number[] = [];

  for (let i = 1; i < recentSamples.length; i++) {
    const intervalSec = (recentSamples[i].completedAt.getTime() - recentSamples[i - 1].completedAt.getTime()) / 1000;
    // Exclude anomalous negative intervals or gaps longer than 20 minutes (e.g. interrupted worker sessions)
    if (intervalSec > 5 && intervalSec < 1200) {
      validIntervalsSec.push(intervalSec);
    }
  }

  if (validIntervalsSec.length < 2) {
    return {
      status: "calibrating",
      completedSegments,
      totalSegments,
      remainingSegments,
      completedChunks: completedChunksCount,
      totalChunks,
      activeChunkIndex: activeChunkIdx,
      progressPercent,
      rollingAvgSeconds: null,
      samplesCount: completedSamples.length,
      estimatedRemainingSeconds: null,
      formattedRemainingTime: "Calibrating ETA (gathering interval consistency)...",
      formattedEstCompletionIST: null,
      isStale: false,
      secondsSinceLastProgress: lastProgressDate ? Math.max(0, (currentTimeMs - lastProgressDate.getTime()) / 1000) : null,
      staleWarning: null,
      lastProgressTimestamp: lastProgressDate,
    };
  }

  const rollingAvgSeconds = validIntervalsSec.reduce((a, b) => a + b, 0) / validIntervalsSec.length;

  // Stale progress detection: threshold is 3.5x the rolling average or at least 300s (5 minutes)
  const secondsSinceLastProgress = lastProgressDate
    ? Math.max(0, (currentTimeMs - lastProgressDate.getTime()) / 1000)
    : 0;
  const staleThresholdSec = Math.max(300, rollingAvgSeconds * 3.5);
  const isStale = secondsSinceLastProgress > staleThresholdSec;

  if (isStale) {
    const elapsedMinutes = Math.round(secondsSinceLastProgress / 60);
    return {
      status: "stale",
      completedSegments,
      totalSegments,
      remainingSegments,
      completedChunks: completedChunksCount,
      totalChunks,
      activeChunkIndex: activeChunkIdx,
      progressPercent,
      rollingAvgSeconds: Math.round(rollingAvgSeconds),
      samplesCount: validIntervalsSec.length,
      estimatedRemainingSeconds: null,
      formattedRemainingTime: "Stalled (stale progress)",
      formattedEstCompletionIST: null,
      isStale: true,
      secondsSinceLastProgress: Math.round(secondsSinceLastProgress),
      staleWarning: `Stale progress warning: No segment completed in ${elapsedMinutes} min (threshold: ${Math.round(staleThresholdSec / 60)} min). Worker may be interrupted or CPU constrained.`,
      lastProgressTimestamp: lastProgressDate,
    };
  }

  // Account for elapsed time on the currently running segment (up to 1 full segment duration)
  const currentSegmentProgress = Math.min(secondsSinceLastProgress, rollingAvgSeconds);
  const rawRemainingSec = remainingSegments * rollingAvgSeconds - currentSegmentProgress;
  const estimatedRemainingSeconds = Math.max(0, Math.round(rawRemainingSec));

  // Human-readable remaining time
  const formattedRemainingTime = formatRemainingDuration(estimatedRemainingSeconds);

  // Projected completion date in IST
  const estCompletionDate = new Date(currentTimeMs + estimatedRemainingSeconds * 1000);
  const formattedEstCompletionIST = formatToIST(estCompletionDate, { includeSeconds: false });

  return {
    status: "progressing",
    completedSegments,
    totalSegments,
    remainingSegments,
    completedChunks: completedChunksCount,
    totalChunks,
    activeChunkIndex: activeChunkIdx,
    progressPercent,
    rollingAvgSeconds: Math.round(rollingAvgSeconds * 10) / 10,
    samplesCount: validIntervalsSec.length,
    estimatedRemainingSeconds,
    formattedRemainingTime,
    formattedEstCompletionIST,
    isStale: false,
    secondsSinceLastProgress: Math.round(secondsSinceLastProgress),
    staleWarning: null,
    lastProgressTimestamp: lastProgressDate,
  };
}

/**
 * Formats duration in seconds into a clean human-readable approximate string.
 */
export function formatRemainingDuration(totalSeconds: number): string {
  if (totalSeconds <= 30) {
    return "< 1 min (approximate)";
  }
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);

  if (hours > 0) {
    return `~${hours}h ${minutes}m (approximate)`;
  }
  return `~${minutes}m (approximate)`;
}
