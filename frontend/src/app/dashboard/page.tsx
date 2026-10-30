"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { metricsService } from "@/api/services/metricsService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import {
  AlertCircle,
  FileText,
  CheckCircle2,
  ShieldCheck,
  Award,
  Cpu,
  FileUp,
  Zap,
  Scale,
  Database,
  ArrowRight,
  Lock,
  User,
  Users,
  AppWindow,
  AlertTriangle,
  RotateCw,
  Activity,
  ShieldAlert,
} from "lucide-react";
import { ApiError } from "@/api/errors";
import { buttonVariants, Button } from "@/components/ui/button";
import Link from "next/link";
import { useAuth } from "@/auth/AuthProvider";
import { cn } from "@/lib/utils";

function formatMetricCount(val: number | undefined): string {
  if (val === undefined || val === null) return "—";
  return String(val);
}

function getRoleBadgeVariant(role: string) {
  switch (role) {
    case "admin":
      return "default";
    case "vendor":
      return "info";
    case "buyer":
      return "info";
    default:
      return "secondary";
  }
}

function getRoleDescription(role: string): string {
  switch (role) {
    case "admin":
      return "Central security and governance authority: user access administration, security policies, vulnerability intelligence, and cross-platform proof telemetry.";
    case "vendor":
      return "Private SBOM repository management, Sparse Merkle Tree generation, and UltraPlonk proof compilation.";
    case "buyer":
    default:
      return "Procurement verifier: independent verification of software supply-chain cryptographic evidence, public commitments, and compliance certificates.";
  }
}

function Dashboard() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const isVendor = user?.role === "vendor";
  const isVerifier = user?.role === "buyer";

  // Standard metrics query (returns platform totals for Admin, tenant-scoped for Vendor/Buyer)
  const {
    data: metrics,
    isLoading: isLoadingMetrics,
    error: metricsError,
    refetch: refetchMetrics,
    isFetching: isFetchingMetrics,
  } = useQuery({
    queryKey: ["metrics"],
    queryFn: () => metricsService.getMetrics(),
  });

  // Comprehensive Admin Governance query across all 8 domains (Admin-only)
  const {
    data: govMetrics,
    isLoading: isLoadingGov,
    error: govError,
    refetch: refetchGov,
    isFetching: isFetchingGov,
  } = useQuery({
    queryKey: ["governance-metrics"],
    queryFn: () => metricsService.getGovernanceMetrics(),
    enabled: isAdmin,
    refetchInterval: (query) => {
      // Auto-refresh governance metrics every 5s if proof jobs are running
      if (query.state.error) return false;
      const runningCount = query.state.data?.proof_jobs?.running || 0;
      return runningCount > 0 ? 5000 : false;
    },
  });

  const isLoading = isAdmin ? isLoadingGov || isLoadingMetrics : isLoadingMetrics;
  const isFetching = isAdmin ? isFetchingGov || isFetchingMetrics : isFetchingMetrics;
  const error = isAdmin ? govError || metricsError : metricsError;

  const handleRefresh = () => {
    void refetchMetrics();
    if (isAdmin) void refetchGov();
  };

  const isZeroState =
    !isLoading &&
    !error &&
    metrics &&
    metrics.total_sboms === 0 &&
    metrics.total_jobs === 0 &&
    metrics.total_verifications === 0 &&
    metrics.total_certificates === 0;

  return (
    <div className="space-y-8">
      {/* C1 Standard Page Header */}
      <PageHeader
        title={isAdmin ? "Platform Governance Dashboard" : "Workspace Dashboard"}
        description={
          isAdmin
            ? "Authoritative platform-wide security governance, multi-tenant inventory, and cryptographic proof telemetry."
            : "Authoritative overview of software supply chain verification activity and cryptographic metrics."
        }
        badge={
          <Badge variant="outline" className="gap-1.5 py-0.5 text-xs font-medium">
            <ShieldCheck className="size-3 text-primary" aria-hidden="true" />
            <span>{isAdmin ? "Central Governance Node" : "Local Verification Node"}</span>
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={isLoading || isFetching}
              className="gap-1.5 shadow-xs"
            >
              <RotateCw className={cn("size-3.5", isFetching && "animate-spin")} />
              <span>Refresh</span>
            </Button>
            {isAdmin ? (
              <Link
                href="/admin/users"
                className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}
              >
                <Users className="size-3.5" aria-hidden="true" />
                <span>User Management</span>
              </Link>
            ) : isVendor ? (
              <Link
                href="/sboms/upload"
                className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}
              >
                <FileUp className="size-3.5" aria-hidden="true" />
                <span>Upload SBOM</span>
              </Link>
            ) : isVerifier ? (
              <Link
                href="/verify"
                className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}
              >
                <CheckCircle2 className="size-3.5" aria-hidden="true" />
                <span>Verify Proof</span>
              </Link>
            ) : null}
          </div>
        }
      />

      {/* Error Feedback */}
      {error && (
        <Alert variant="destructive" role="alert">
          <AlertCircle className="size-4" aria-hidden="true" />
          <AlertTitle className="text-sm font-semibold">Failed to load platform metrics</AlertTitle>
          <AlertDescription className="flex flex-col gap-2 text-xs mt-1">
            <p>
              {error instanceof ApiError
                ? error.message
                : "An unexpected network error occurred while loading dashboard metrics."}
            </p>
            <Button variant="outline" size="sm" className="w-fit" onClick={handleRefresh}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* ========================================================================= */}
      {/* ADMIN GOVERNANCE DASHBOARD VIEW (Phase 4)                                 */}
      {/* ========================================================================= */}
      {isAdmin && (
        <div className="space-y-6">
          {/* Operational Alerts Banner */}
          {!isLoading && govMetrics && (
            <div className="space-y-2">
              {govMetrics.proof_jobs?.running > 0 && (
                <Alert className="border-blue-500/40 bg-blue-500/5 text-blue-900 dark:text-blue-200">
                  <Activity className="size-4 text-blue-600 dark:text-blue-400 animate-pulse" />
                  <AlertTitle className="text-xs font-semibold">Active Prover Telemetry</AlertTitle>
                  <AlertDescription className="text-xs leading-relaxed">
                    {govMetrics.proof_jobs.running} UltraPlonk proof computation currently executing in the background runtime. Prover progress and witness constraints are being evaluated.
                  </AlertDescription>
                </Alert>
              )}

              {govMetrics.proof_jobs?.failed > 0 && (
                <Alert className="border-amber-500/40 bg-amber-500/5 text-amber-900 dark:text-amber-200">
                  <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" />
                  <AlertTitle className="text-xs font-semibold">Proof Telemetry Diagnostic Notice</AlertTitle>
                  <AlertDescription className="text-xs leading-relaxed">
                    {govMetrics.proof_jobs.failed} failed proof generation attempt(s) recorded in platform audit logs. Vendor input manifests or constraint limits may require inspection.
                  </AlertDescription>
                </Alert>
              )}

              {govMetrics.certificates?.revoked > 0 && (
                <Alert variant="destructive">
                  <ShieldAlert className="size-4" />
                  <AlertTitle className="text-xs font-semibold">Certificate Revocation Alert</AlertTitle>
                  <AlertDescription className="text-xs leading-relaxed">
                    {govMetrics.certificates.revoked} verification certificate(s) have been revoked. Revoked certificates are flagged non-disclosing during buyer inspection.
                  </AlertDescription>
                </Alert>
              )}
            </div>
          )}

          {/* 8 Required Platform Metric Domain Cards */}
          <div>
            <div className="flex items-center justify-between pb-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                Platform-Wide Governance Telemetry (8 Domains)
              </h2>
              <span className="text-[11px] text-muted-foreground">
                Live PostgreSQL State &bull; Multi-Tenant Scoped
              </span>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {/* Domain 1: Users & RBAC */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Users & RBAC
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Users className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.users?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.users
                      ? `${govMetrics.users.by_role?.vendor || 0} Vendors • ${govMetrics.users.by_role?.buyer || 0} Buyers • ${govMetrics.users.by_role?.admin || 0} Admin`
                      : "Platform accounts"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium">
                      {govMetrics?.users?.by_status?.active || 0} Active Accounts
                    </span>
                    <Link href="/admin/users" className="text-primary hover:underline font-medium">
                      Manage &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 2: Applications */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Applications
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <AppWindow className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.applications?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.applications
                      ? `${govMetrics.applications.active} Active across all vendors`
                      : "Registered applications"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">
                      {govMetrics?.applications?.archived || 0} Archived
                    </span>
                    <Link href="/applications" className="text-primary hover:underline font-medium">
                      Inspect &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 3: SBOM Uploads */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    SBOM Inventory
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <FileText className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.sboms?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.sboms
                      ? `${govMetrics.sboms.committed} Cryptographically Committed`
                      : "Platform SBOM uploads"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-primary font-medium">CycloneDX Format</span>
                    <Link href="/sboms" className="text-primary hover:underline font-medium">
                      Inventory &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 4: Proof Jobs Telemetry */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    ZK Proving Jobs
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Cpu className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.proof_jobs?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.proof_jobs
                      ? `${govMetrics.proof_jobs.completed} Completed • ${govMetrics.proof_jobs.running} Running`
                      : "UltraPlonk proof generations"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-amber-600 dark:text-amber-400 font-medium">
                      {govMetrics?.proof_jobs?.failed || 0} Failed Attempts
                    </span>
                    <Link href="/certificates" className="text-primary hover:underline font-medium">
                      Certificates &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 5: Independent Verifications */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Verifications
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <CheckCircle2 className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.verifications?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.verifications
                      ? `${govMetrics.verifications.verified} cryptographically verified`
                      : "Public commitment checks"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">
                      {govMetrics?.verifications?.unavailable || 0} Unavailable
                    </span>
                    <Link href="/certificates" className="text-primary hover:underline font-medium">
                      Registry &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 6: Certificates */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Certificates
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Award className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.certificates?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.certificates
                      ? `${govMetrics.certificates.active} Active tamper-evident certs`
                      : "Compliance records issued"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">
                      {govMetrics?.certificates?.revoked || 0} Revoked
                    </span>
                    <Link href="/certificates" className="text-primary hover:underline font-medium">
                      Registry &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 7: Security Policies */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Security Policies
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Scale className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.policies?.total)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    {govMetrics?.policies
                      ? `${govMetrics.policies.active} Active policy digest`
                      : "Governance rule sets"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="font-mono text-muted-foreground">H_Policy Hash</span>
                    <Link href="/admin/policies" className="text-primary hover:underline font-medium">
                      Configure &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Domain 8: Vulnerability Intelligence */}
              <Card className="border-border/80 shadow-xs hover:border-primary/40 transition-colors">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Vulnerability Intel
                  </CardTitle>
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Database className="size-4" aria-hidden="true" />
                  </div>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <Skeleton className="h-8 w-20" />
                  ) : (
                    <div className="text-2xl font-bold tracking-tight text-foreground">
                      {formatMetricCount(govMetrics?.vulnerabilities?.total_snapshots)}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1 truncate" title={govMetrics?.vulnerabilities?.latest_snapshot_root || ""}>
                    {govMetrics?.vulnerabilities?.latest_snapshot_root
                      ? `Root: ${govMetrics.vulnerabilities.latest_snapshot_root.slice(0, 14)}...`
                      : "Authoritative snapshots"}
                  </p>
                  <div className="mt-3 flex items-center justify-between text-[11px]">
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium">
                      {govMetrics?.vulnerabilities?.frozen || 0} Frozen SMT Root
                    </span>
                    <Link href="/admin/vulnerabilities" className="text-primary hover:underline font-medium">
                      Inspect &rarr;
                    </Link>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Admin Governance Actions */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold tracking-tight text-foreground">
                Administrative Governance Capabilities
              </h2>
              <span className="text-xs text-muted-foreground">
                Authority: <strong className="text-foreground capitalize">{user?.role}</strong>
              </span>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {/* Action 1: User Management */}
              <Link
                href="/admin/users"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Users className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">User & RBAC Administration</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Audit registered users, update role assignments (Vendor, Buyer, Admin), and enforce account activation status.
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Manage platform accounts</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* Action 2: Security Policies */}
              <Link
                href="/admin/policies"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Scale className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Security Policies & Rules</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Define and activate deterministic supply-chain policy rule sets, CVSS severity caps, and authoritative digests (H_Policy).
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Configure policies</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* Action 3: Vulnerability Intelligence */}
              <Link
                href="/admin/vulnerabilities"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Database className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Vulnerability Intelligence & SMT</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Review CVE snapshot databases, trigger NVD/OSV ingestion, and govern the frozen Sparse Merkle Tree roots (R_VulnDB).
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Audit threat snapshots</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* Action 4: Platform Applications */}
              <Link
                href="/applications"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <AppWindow className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Platform Applications</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Inspect all software applications registered across platform vendors, audit lifecycle states, and monitor archive status.
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Inspect applications</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* Action 5: Platform SBOM Inventory */}
              <Link
                href="/sboms"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <FileText className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Platform SBOM Inventory</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Audit software bills of materials committed across all vendors, verify Merkle root commitments (R_SBOM), and inspect components.
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Browse SBOM commitments</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* Action 6: Verification Certificates */}
              <Link
                href="/certificates"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Award className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Verification Certificates Registry</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Inspect tamper-evident verification certificates issued across all buyer verification workflows and manage revocation status.
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Browse certificate records</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VENDOR & BUYER WORKSPACE DASHBOARD VIEW                                   */}
      {/* ========================================================================= */}
      {!isAdmin && (
        <div className="space-y-8">
          {/* Authoritative Metric Cards (Vendor/Buyer Scoped) */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* Metric 1: SBOM Uploads */}
            <Card className="border-border/80 shadow-xs">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  SBOM Uploads
                </CardTitle>
                <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <FileText className="size-4" aria-hidden="true" />
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-8 w-20" />
                ) : (
                  <div className="text-2xl font-bold tracking-tight text-foreground">
                    {formatMetricCount(metrics?.total_sboms ?? metrics?.sbom_count)}
                  </div>
                )}
                <p className="text-xs text-muted-foreground mt-1">
                  {isVendor ? "Owned application manifests" : "Session manifest scope"}
                </p>
              </CardContent>
            </Card>

            {/* Metric 2: Proof Jobs */}
            <Card className="border-border/80 shadow-xs">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Proof Jobs
                </CardTitle>
                <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Cpu className="size-4" aria-hidden="true" />
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-8 w-20" />
                ) : (
                  <div className="text-2xl font-bold tracking-tight text-foreground">
                    {formatMetricCount(metrics?.total_jobs ?? metrics?.proof_count)}
                  </div>
                )}
                <p className="text-xs text-muted-foreground mt-1">
                  UltraPlonk proof generations
                </p>
              </CardContent>
            </Card>

            {/* Metric 3: Verifications */}
            <Card className="border-border/80 shadow-xs">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Verifications
                </CardTitle>
                <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <CheckCircle2 className="size-4" aria-hidden="true" />
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-8 w-20" />
                ) : (
                  <div className="text-2xl font-bold tracking-tight text-foreground">
                    {formatMetricCount(metrics?.total_verifications ?? metrics?.verification_count)}
                  </div>
                )}
                <p className="text-xs text-muted-foreground mt-1">
                  Public commitment checks
                </p>
              </CardContent>
            </Card>

            {/* Metric 4: Certificates */}
            <Card className="border-border/80 shadow-xs">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Certificates
                </CardTitle>
                <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Award className="size-4" aria-hidden="true" />
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-8 w-20" />
                ) : (
                  <div className="text-2xl font-bold tracking-tight text-foreground">
                    {formatMetricCount(metrics?.total_certificates ?? metrics?.certificate_count)}
                  </div>
                )}
                <p className="text-xs text-muted-foreground mt-1">
                  Tamper-evident records issued
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Role-Specific Zero State (if account has zero activity yet) */}
          {isZeroState && (
            <EmptyState
              icon={isVendor ? FileUp : ShieldCheck}
              title={isVendor ? "No SBOMs or Proofs Recorded" : "Welcome to the Verification Workspace"}
              description={
                isVendor
                  ? "Start by uploading a CycloneDX or SPDX JSON manifest to generate a private Sparse Merkle Tree commitment and compile UltraPlonk proofs."
                  : "Your Buyer account is equipped to independently verify vendor proof jobs, inspect cryptographic commitments, and validate tamper-evident compliance certificates."
              }
              action={
                isVendor ? (
                  <Link href="/sboms/upload" className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}>
                    <FileUp className="size-3.5" aria-hidden="true" />
                    <span>Upload First SBOM</span>
                  </Link>
                ) : (
                  <Link href="/verify" className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}>
                    <CheckCircle2 className="size-3.5" aria-hidden="true" />
                    <span>Verify a Proof</span>
                  </Link>
                )
              }
            />
          )}

          {/* Role-Aware Quick Workflows */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold tracking-tight text-foreground">
                Available Workflows
              </h2>
              <span className="text-xs text-muted-foreground">
                Scoped to role: <strong className="text-foreground capitalize">{user?.role}</strong>
              </span>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {/* Vendor Only: Upload SBOM */}
              {isVendor && (
                <Link
                  href="/sboms/upload"
                  className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <div className="space-y-2">
                    <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                      <FileUp className="size-5" aria-hidden="true" />
                    </div>
                    <h3 className="font-semibold text-sm text-foreground">Upload SBOM Manifest</h3>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Ingest CycloneDX or SPDX JSON files to generate deterministic CPE leaves and Sparse Merkle Tree roots.
                    </p>
                  </div>
                  <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                    <span>Upload manifest</span>
                    <ArrowRight className="size-3.5" aria-hidden="true" />
                  </div>
                </Link>
              )}

              {/* Vendor Only: Generate Proof */}
              {isVendor && (
                <Link
                  href="/proofs/generate"
                  className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <div className="space-y-2">
                    <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                      <Zap className="size-5" aria-hidden="true" />
                    </div>
                    <h3 className="font-semibold text-sm text-foreground">Generate ZK Proof</h3>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Execute Noir 0.32.0 ACIR circuits with Barretenberg native runtimes to prove non-membership in zero knowledge.
                    </p>
                  </div>
                  <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                    <span>Launch proving job</span>
                    <ArrowRight className="size-3.5" aria-hidden="true" />
                  </div>
                </Link>
              )}

              {/* Buyer Roles: Verify Proof */}
              {isVerifier && (
                <Link
                  href="/verify"
                  className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <div className="space-y-2">
                    <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                      <CheckCircle2 className="size-5" aria-hidden="true" />
                    </div>
                    <h3 className="font-semibold text-sm text-foreground">Verify Proof Artifact</h3>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Validate public-input commitments (R_SBOM, R_VulnDB, H_Policy) against recorded UltraPlonk proof packages.
                    </p>
                  </div>
                  <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                    <span>Execute verification</span>
                    <ArrowRight className="size-3.5" aria-hidden="true" />
                  </div>
                </Link>
              )}

              {/* Vendor Role: Manage Proof Pipeline & Verification Shares */}
              {isVendor && (
                <Link
                  href="/proofs"
                  className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <div className="space-y-2">
                    <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                      <Zap className="size-5" aria-hidden="true" />
                    </div>
                    <h3 className="font-semibold text-sm text-foreground">Proof Pipeline & Shares</h3>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Monitor active proving jobs, review completed cryptographic evidence, and manage verification shares.
                    </p>
                  </div>
                  <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                    <span>View proof records</span>
                    <ArrowRight className="size-3.5" aria-hidden="true" />
                  </div>
                </Link>
              )}

              {/* All Workspace Roles: Certificates */}
              <Link
                href="/certificates"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Award className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Verification Certificates</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Inspect tamper-evident verification certificates issued with durable UUIDs and public validation endpoints.
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Browse certificates</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* All Workspace Roles: Security Policies */}
              <Link
                href="/admin/policies"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Scale className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Security Policies</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Inspect deterministic rule sets, CVSS severity thresholds, and canonical SHA-256 policy digest bindings (H_Policy).
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Review policies</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>

              {/* All Workspace Roles: Vulnerability Intel */}
              <Link
                href="/admin/vulnerabilities"
                className="group flex flex-col justify-between rounded-xl border border-border/80 bg-card p-5 shadow-xs hover:border-primary/50 hover:shadow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="space-y-2">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Database className="size-5" aria-hidden="true" />
                  </div>
                  <h3 className="font-semibold text-sm text-foreground">Vulnerability Intelligence</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Explore frozen CVE snapshot databases (R_VulnDB) with four-state lifecycle provenance tracking.
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
                  <span>Inspect feeds</span>
                  <ArrowRight className="size-3.5" aria-hidden="true" />
                </div>
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* Role Context & Cryptographic Assurance Panel */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Panel 1: Session Authority */}
        <Card className="border-border/80 shadow-xs">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2 text-foreground font-semibold text-sm">
              <User className="size-4 text-primary" aria-hidden="true" />
              <span>Session Authorization</span>
            </div>
            <CardDescription className="text-xs">
              Backend-authoritative role privileges and tenancy isolation
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-border/70">
              <span className="text-muted-foreground">Authenticated User</span>
              <strong className="text-foreground font-medium">{user?.username}</strong>
            </div>
            <div className="flex items-center justify-between pb-2 border-b border-border/70">
              <span className="text-muted-foreground">Assigned Role</span>
              <Badge variant={getRoleBadgeVariant(user?.role || "buyer")} className="capitalize text-[11px]">
                {user?.role?.replace(/_/g, " ")}
              </Badge>
            </div>
            <p className="text-muted-foreground leading-relaxed pt-1">
              {getRoleDescription(user?.role || "buyer")}
            </p>
          </CardContent>
        </Card>

        {/* Panel 2: Cryptographic Guarantees */}
        <Card className="border-border/80 shadow-xs">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2 text-foreground font-semibold text-sm">
              <Lock className="size-4 text-primary" aria-hidden="true" />
              <span>Cryptographic Invariants</span>
            </div>
            <CardDescription className="text-xs">
              Authoritative parameters governing zero-knowledge supply chain verification
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            <div className="flex items-center justify-between pb-1.5 border-b border-border/70">
              <span className="text-muted-foreground">Circuit / Prover Engine</span>
              <span className="font-mono text-[11px] text-foreground">Noir 0.32.0 ACIR &bull; UltraPlonk</span>
            </div>
            <div className="flex items-center justify-between pb-1.5 border-b border-border/70">
              <span className="text-muted-foreground">Proof Body Size</span>
              <span className="font-mono text-[11px] text-foreground">2,144 Bytes (excl. public inputs)</span>
            </div>
            <div className="flex items-center justify-between pb-1.5 border-b border-border/70">
              <span className="text-muted-foreground">Commitment Scheme</span>
              <span className="font-mono text-[11px] text-foreground">Poseidon Sponge (t=2, t=3)</span>
            </div>
            <div className="flex items-center justify-between pt-0.5">
              <span className="text-muted-foreground">Witness Privacy</span>
              <Badge variant="secondary" className="text-[10px] font-mono">Zero Component Disclosure</Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Authoritative Metrics Callout */}
      <Alert className="bg-muted/30 border-border/80 text-muted-foreground">
        <AlertCircle className="size-4 text-primary" aria-hidden="true" />
        <AlertTitle className="text-xs font-semibold text-foreground">Authoritative Data Guarantee</AlertTitle>
        <AlertDescription className="text-xs leading-relaxed mt-0.5">
          All aggregate counts displayed above are retrieved directly from the backend metrics service (<code className="font-mono text-foreground">/api/v1/metrics</code> and <code className="font-mono text-foreground">/api/v1/admin/metrics</code>) tied to your active in-memory session. The application does not fabricate risk metrics, security scores, or unverified activity.
        </AlertDescription>
      </Alert>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "buyer"]}>
      <Dashboard />
    </RouteGuard>
  );
}
