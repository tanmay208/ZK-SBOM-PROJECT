/**
 * Stage 5 Authentication Transport Boundary.
 * 
 * STRICT INVARIANT:
 * - Token is held in memory ONLY.
 * - Never written to localStorage, sessionStorage, or cookies.
 * - Cleared on logout or page refresh.
 */

let memoryToken: string | null = null;
const unauthorizedListeners = new Set<() => void>();

export const authTransport = {
  getToken: (): string | null => memoryToken,
  setToken: (token: string): void => {
    memoryToken = token;
  },
  clearToken: (): void => {
    memoryToken = null;
  },
  subscribeUnauthorized: (listener: () => void): (() => void) => {
    unauthorizedListeners.add(listener);
    return () => unauthorizedListeners.delete(listener);
  },
  handleUnauthorized: (): void => {
    memoryToken = null;
    unauthorizedListeners.forEach((listener) => listener());
  }
};
