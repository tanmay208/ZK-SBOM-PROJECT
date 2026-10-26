"use client";

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
} from "lucide-react";
import { ApiError } from "@/api/errors";
import { buttonVariants, Button } from "@/components/ui/button";
import Link from "next/link";
import { useAuth } from "@/auth/AuthProvider";

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
    case "trusted_importer":
      return "warning";
    case "auditor":
    default:
      return "secondary";
  }
}

function getRoleDescription(role: string): string {
  switch (role) {
    case "admin":
      return "Full administrative authority: user management, security policy definition, and proof oversight.";
    case "vendor":
      return "Private SBOM repository management, Sparse Merkle Tree generation, and UltraPlonk proof compilation.";
    case "trusted_importer":
      return "Authoritative vulnerability intelligence ingestion and CVE snapshot lifecycle management.";
    case "buyer":
      return "Procurement verifier: independent verification of software supply-chain cryptographic evidence, public commitments, and compliance certificates.";
    case "auditor":
    default:
      return "Read-only independent proof verification, public commitment validation, and certificate inspection.";
  }
}

function Dashboard() {
  const { user } = useAuth();
  const { data: metrics, isLoading, error, refetch } = useQuery({
    queryKey: ["metrics"],
    queryFn: () => metricsService.getMetrics(),
  });

  const isVendorOrAdmin = user?.role === "vendor" || user?.role === "admin";
  const isVerifier = user?.role === "auditor" || user?.role === "buyer";

  const isZeroState =
    !isLoading &&
    !error &&
    metrics &&
    (metrics.total_sboms === 0) &&
    (metrics.total_jobs === 0) &&
    (metrics.total_verifications === 0) &&
    (metrics.total_certificates === 0);

  return (
    <div className="space-y-8">
      {/* C1 Standard Page Header */}
      <PageHeader
        title="Workspace Dashboard"
        description="Authoritative overview of software supply chain verification activity and cryptographic metrics."
        badge={
          <Badge variant="outline" className="gap-1.5 py-0.5 text-xs font-medium">
            <ShieldCheck className="size-3 text-primary" aria-hidden="true" />
            <span>Local Verification Node</span>
          </Badge>
        }
        actions={
          isVendorOrAdmin ? (
            <Link href="/sboms/upload" className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}>
              <FileUp className="size-3.5" aria-hidden="true" />
              <span>Upload SBOM</span>
            </Link>
          ) : isVerifier ? (
            <Link href="/verify" className={buttonVariants({ size: "sm", className: "gap-1.5 shadow-xs" })}>
              <CheckCircle2 className="size-3.5" aria-hidden="true" />
              <span>Verify Proof</span>
            </Link>
          ) : null
        }
      />

      {/* Error Feedback */}
      {error && (
        <Alert variant="destructive" role="alert">
          <AlertCircle className="size-4" aria-hidden="true" />
          <AlertTitle className="text-sm font-semibold">Failed to load metrics</AlertTitle>
          <AlertDescription className="flex flex-col gap-2 text-xs mt-1">
            <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred while loading dashboard metrics."}</p>
            <Button variant="outline" size="sm" className="w-fit" onClick={() => void refetch()}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Authoritative Metric Cards */}
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
              {isVendorOrAdmin ? "Owned application manifests" : "Session manifest scope"}
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
          icon={isVendorOrAdmin ? FileUp : ShieldCheck}
          title={isVendorOrAdmin ? "No SBOMs or Proofs Recorded" : "Welcome to the Verification Workspace"}
          description={
            isVendorOrAdmin
              ? "Start by uploading a CycloneDX or SPDX JSON manifest to generate a private Sparse Merkle Tree commitment and compile UltraPlonk proofs."
              : user?.role === "buyer"
              ? "Your Buyer account is equipped to independently verify vendor proof jobs, inspect cryptographic commitments, and validate tamper-evident compliance certificates."
              : "Your Auditor account is equipped to independently verify vendor proof jobs and inspect tamper-evident compliance certificates."
          }
          action={
            isVendorOrAdmin ? (
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
          {/* Vendor & Admin Only: Upload SBOM */}
          {isVendorOrAdmin && (
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

          {/* Vendor & Admin Only: Generate Proof */}
          {isVendorOrAdmin && (
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

          {/* All Workspace Roles: Verify Proof */}
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
                Validate public-input commitments ($R_{"{SBOM}"}, R_{"{VulnDB}"}, H_{"{Policy}"}$) against recorded UltraPlonk proof packages.
              </p>
            </div>
            <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
              <span>Execute verification</span>
              <ArrowRight className="size-3.5" aria-hidden="true" />
            </div>
          </Link>

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
                Inspect deterministic rule sets, CVSS severity thresholds, and canonical SHA-256 policy digest bindings ($H_{"{Policy}"}$).
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
                Explore frozen CVE snapshot databases ($R_{"{VulnDB}"}$) with four-state lifecycle provenance tracking.
              </p>
            </div>
            <div className="mt-4 flex items-center gap-1 text-xs font-medium text-primary group-hover:translate-x-0.5 transition-transform">
              <span>Inspect feeds</span>
              <ArrowRight className="size-3.5" aria-hidden="true" />
            </div>
          </Link>
        </div>
      </div>

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
              <Badge variant={getRoleBadgeVariant(user?.role || "auditor")} className="capitalize text-[11px]">
                {user?.role?.replace(/_/g, " ")}
              </Badge>
            </div>
            <p className="text-muted-foreground leading-relaxed pt-1">
              {getRoleDescription(user?.role || "auditor")}
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
              <span className="font-mono text-[11px] text-foreground">Poseidon Sponge ($t=2, t=3$)</span>
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
          All aggregate counts displayed above are retrieved directly from the backend metrics service (<code className="font-mono text-foreground">/api/v1/metrics</code>) tied to your active in-memory session. The application does not fabricate risk metrics, security scores, or unverified activity.
        </AlertDescription>
      </Alert>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor", "buyer"]}>
      <Dashboard />
    </RouteGuard>
  );
}
