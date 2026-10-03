"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { authService } from "@/api/services/authService";
import { authTransport } from "@/api/authTransport";
import { User } from "@/api/types";
import { useRouter } from "next/navigation";

export type AuthStatus = "initializing" | "unauthenticated" | "authenticated";

interface AuthContextValue {
  status: AuthStatus;
  user: User | null;
  logout: () => void;
  refetchUser: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("initializing");
  const queryClient = useQueryClient();
  const router = useRouter();

  const { data: user, error, isFetching, refetch } = useQuery({
    queryKey: ["auth-me"],
    queryFn: () => authService.me(),
    enabled: !!authTransport.getToken(), // Only run if we have a token in memory
    retry: false,
    staleTime: 0,
    gcTime: 5 * 60 * 1000,
  });

  useEffect(() => authTransport.subscribeUnauthorized(() => {
    queryClient.clear();
    setStatus("unauthenticated");
  }), [queryClient]);

  useEffect(() => {
    // If we have no token, we are immediately unauthenticated.
    if (!authTransport.getToken()) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setStatus("unauthenticated");
      return;
    }

    if (isFetching) {
       
      setStatus("initializing");
      return;
    }

    if (error) {
      // 401 or network failure clears the session
      authTransport.clearToken();
       
      setStatus("unauthenticated");
      return;
    }

    if (user) {
       
      setStatus("authenticated");
    }
  }, [user, error, isFetching]);

  const logout = () => {
    authTransport.clearToken();
    setStatus("unauthenticated");
    // Clear all sensitive queries from memory
    queryClient.clear();
    router.push("/login");
  };

  return (
    <AuthContext.Provider value={{ status, user: user || null, logout, refetchUser: refetch }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
