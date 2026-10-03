"use client";

import { useQuery } from "@tanstack/react-query";
import { metricsService } from "@/api/services/metricsService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, FileCode, CheckCircle2, ShieldCheck, FileBadge } from "lucide-react";
import { ApiError } from "@/api/errors";
import { buttonVariants, Button } from "@/components/ui/button";
import Link from "next/link";
import { useAuth } from "@/auth/AuthProvider";

function Dashboard() {
  const { user } = useAuth();
  const { data: metrics, isLoading, error, refetch } = useQuery({
    queryKey: ["metrics"],
    queryFn: () => metricsService.getMetrics(),
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Overview of organizational Zero-Knowledge Proof activities.</p>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Failed to load metrics</AlertTitle>
          <AlertDescription className="flex flex-col gap-2">
            <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
            <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* SBOM Metrics */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">SBOM Uploads</CardTitle>
            <FileCode className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{metrics?.sbom_count ?? "—"}</div>
            )}
            <p className="text-xs text-muted-foreground mt-1">Total application manifests</p>
          </CardContent>
        </Card>

        {/* Proof Metrics */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Proof Jobs</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{metrics?.proof_count ?? "—"}</div>
            )}
            <p className="text-xs text-muted-foreground mt-1">Total ZKP generation requests</p>
          </CardContent>
        </Card>

        {/* Verification Metrics */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Verifications</CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{metrics?.verification_count ?? "—"}</div>
            )}
            <p className="text-xs text-muted-foreground mt-1">Total verification attempts</p>
          </CardContent>
        </Card>

        {/* Certificate Metrics */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Certificates</CardTitle>
            <FileBadge className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{metrics?.certificate_count ?? "—"}</div>
            )}
            <p className="text-xs text-muted-foreground mt-1">Total issued certificates</p>
          </CardContent>
        </Card>
      </div>

      {/* Security Context Notes */}
      <Alert className="bg-muted/50">
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Authoritative Metrics</AlertTitle>
        <AlertDescription>
          The metrics displayed above represent backend-authoritative counts tied to your current session ({user?.role}).
          No vulnerability totals or security status aggregations are computed locally.
        </AlertDescription>
      </Alert>

      {/* Quick Actions */}
      <div>
        <h2 className="text-xl font-semibold tracking-tight mb-4">Quick Actions</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Link href="/sboms/upload" className={buttonVariants({ variant: "outline", className: "h-auto py-4 flex flex-col gap-2" })}>
            <FileCode className="h-5 w-5" />
            Upload SBOM
          </Link>
          <Link href="/proofs/generate" className={buttonVariants({ variant: "outline", className: "h-auto py-4 flex flex-col gap-2" })}>
            <CheckCircle2 className="h-5 w-5" />
            Generate Proof
          </Link>
          <Link href="/verify" className={buttonVariants({ variant: "outline", className: "h-auto py-4 flex flex-col gap-2" })}>
            <ShieldCheck className="h-5 w-5" />
            Verify Proof
          </Link>
          <Link href="/certificates" className={buttonVariants({ variant: "outline", className: "h-auto py-4 flex flex-col gap-2" })}>
            <FileBadge className="h-5 w-5" />
            View Certificates
          </Link>
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor"]}>
      <Dashboard />
    </RouteGuard>
  );
}
