/**
 * Date and Time utilities for formatting and parsing timestamps with strict timezone safety.
 *
 * Invariants:
 * 1. Backend timestamps from PostgreSQL (timestamp without time zone) represent UTC.
 * 2. Naive ISO strings (e.g. "2026-10-27T05:35:19.936489") genuinely represent UTC.
 * 3. Timestamps are formatted in Asia/Kolkata and explicitly labeled "IST".
 * 4. Never append "Z" unless the input genuinely represents UTC.
 * 5. Missing (null/undefined) timestamps format as "—"; malformed strings format as "Invalid date".
 */

const NAIVE_ISO_REGEX = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;
const HAS_TIMEZONE_REGEX = /(?:Z|[+-]\d{2}(?::?\d{2})?)$/i;

/**
 * Parses an ISO timestamp string or Date object into a valid Date in UTC.
 * If the string has no timezone offset (naive), it is interpreted as UTC.
 * Returns null if the input is null, undefined, or invalid.
 */
export function parseUtcTimestamp(input: string | Date | null | undefined): Date | null {
  if (input == null) return null;

  if (input instanceof Date) {
    return isNaN(input.getTime()) ? null : input;
  }

  const str = String(input).trim();
  if (!str) return null;

  // 1. If string explicitly declares a timezone (e.g. ends with Z or +/-HH:MM), parse directly
  if (HAS_TIMEZONE_REGEX.test(str)) {
    const d = new Date(str);
    return isNaN(d.getTime()) ? null : d;
  }

  // 2. If string is a naive ISO date-time from backend, parse its components strictly as UTC
  const match = str.match(NAIVE_ISO_REGEX);
  if (match) {
    const year = parseInt(match[1], 10);
    const month = parseInt(match[2], 10) - 1; // 0-indexed
    const day = parseInt(match[3], 10);
    const hour = parseInt(match[4], 10);
    const minute = parseInt(match[5], 10);
    const second = parseInt(match[6], 10);
    // Parse millisecond fraction (up to 3 digits)
    const msFraction = match[7] ? match[7].slice(0, 3).padEnd(3, "0") : "0";
    const millisecond = parseInt(msFraction, 10);

    // Validate date/time bounds
    if (
      month < 0 || month > 11 ||
      day < 1 || day > 31 ||
      hour < 0 || hour > 23 ||
      minute < 0 || minute > 59 ||
      second < 0 || second > 59
    ) {
      return null;
    }

    const utcMs = Date.UTC(year, month, day, hour, minute, second, millisecond);
    const date = new Date(utcMs);
    return isNaN(date.getTime()) ? null : date;
  }

  // 3. Fallback standard parse
  const fallback = new Date(str);
  return isNaN(fallback.getTime()) ? null : fallback;
}

export interface FormatOptions {
  includeSeconds?: boolean;
  includeTime?: boolean;
  includeDate?: boolean;
  label?: boolean; // Appends "IST"
}

/**
 * Formats a timestamp into Indian Standard Time (Asia/Kolkata).
 * Gracefully returns "—" for missing values and "Invalid date" for malformed strings.
 */
export function formatToIST(
  input: string | Date | null | undefined,
  options: FormatOptions = {}
): string {
  if (input == null || input === "") {
    return "—";
  }

  const date = parseUtcTimestamp(input);
  if (!date) {
    return "Invalid date";
  }

  const {
    includeSeconds = false,
    includeTime = true,
    includeDate = true,
    label = true,
  } = options;

  try {
    const dateOptions: Intl.DateTimeFormatOptions = {
      timeZone: "Asia/Kolkata",
    };

    if (includeDate) {
      dateOptions.year = "numeric";
      dateOptions.month = "short";
      dateOptions.day = "2-digit";
    }

    if (includeTime) {
      dateOptions.hour = "2-digit";
      dateOptions.minute = "2-digit";
      if (includeSeconds) {
        dateOptions.second = "2-digit";
      }
      dateOptions.hour12 = true;
    }

    const formatter = new Intl.DateTimeFormat("en-US", dateOptions);
    const formatted = formatter.format(date);
    return label ? `${formatted} IST` : formatted;
  } catch {
    return "Invalid date";
  }
}

/**
 * Convenience formatter for table rows: e.g. "Oct 27, 2026, 11:05 AM IST"
 */
export function formatTableTimestamp(input: string | Date | null | undefined): string {
  return formatToIST(input, { includeSeconds: false, includeDate: true, includeTime: true, label: true });
}
