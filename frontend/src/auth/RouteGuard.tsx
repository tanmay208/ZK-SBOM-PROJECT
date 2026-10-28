"use client";

import { useAuth } from "./AuthProvider";
import { useRouter, usePathname } from "next/navigation";
import { useEffect, ReactNode } from "react";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Role } from "@/api/types";

interface RouteGuardProps {
  children: ReactNode;
  allowedRoles?: Role[];
}

const PUBLIC_ROUTES = ["/login", "/register", "/"];

export function RouteGuard({ children, allowedRoles }: RouteGuardProps) {
  const { status, user } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  const isPublicRoute = PUBLIC_ROUTES.includes(pathname) || pathname.startsWith("/certificates/");

  useEffect(() => {
    if (status === "unauthenticated" && !isPublicRoute) {
      router.push("/login");
    }
  }, [status, isPublicRoute, router]);

  if (status === "initializing") {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Handle unauthenticated trying to view private
  if (status === "unauthenticated" && !isPublicRoute) {
    return null; // Will redirect
  }

  // Handle 403 Forbidden checks for authenticated users
  if (status === "authenticated" && allowedRoles && user) {
    if (!allowedRoles.includes(user.role)) {
      return (
        <div className="flex flex-col items-center justify-center h-[50vh] space-y-4">
          <ShieldAlert className="h-16 w-16 text-destructive" />
          <h2 className="text-2xl font-bold tracking-tight">Access Denied</h2>
          <p className="text-muted-foreground max-w-md text-center">
            You do not have permission to view this resource. 
            Your role ({user.role}) is not authorized for this action.
          </p>
          <Button onClick={() => router.push("/dashboard")}>Return to Dashboard</Button>
        </div>
      );
    }
  }

  return <>{children}</>;
}
