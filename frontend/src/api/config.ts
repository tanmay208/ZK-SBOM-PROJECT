export const API_CONFIG = {
  // Rely on NEXT_PUBLIC_API_URL or fallback to localhost during dev
  BASE_URL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  TIMEOUT_MS: 30000,
};
