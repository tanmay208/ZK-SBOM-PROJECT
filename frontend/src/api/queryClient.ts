import { QueryClient } from "@tanstack/react-query";

/**
 * Security-focused QueryClient configuration.
 * - Disables excessive retries which could trigger rate limits or security heuristics.
 * - Prevents sensitive queries from being held in memory indefinitely.
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: (failureCount: number, error: unknown) => {
        const err = error as { status?: number };
        // Never retry auth errors or validation errors
        if (err?.status === 401 || err?.status === 403 || err?.status === 422) {
          return false;
        }
        return failureCount < 1;
      },
      staleTime: 0,
      gcTime: 5 * 60 * 1000, // 5 minutes max garbage collection
    },
  },
});
