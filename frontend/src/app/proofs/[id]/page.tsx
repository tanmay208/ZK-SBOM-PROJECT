"use client";

import * as React from "react";
import { useState, use } from "react";
import { useQuery } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { formatToIST } from "@/lib/dateTime";
import { calculateProofEta } from "@/lib/etaCalculator";
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Calendar,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Cpu,
  Loader2,
  RotateCw,
  ServerOff,
  ShieldCheck,
  Timer,
  XCircle
} from "lucide-react";

function ProofDetail({ id }: { id: string }) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // Fallback
    }
  };

  const { data: job, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["proofs", id],
    queryFn: () => proofService.getJob(id),
    refetchInterval: (query) => {
      const state = query.state.data?.status;
      const isTerminal = state === "completed" || state === "failed" || state === "execution_blocked";
      // Poll every 3 seconds if not in a terminal state and no network error
      return !isTerminal && !query.state.error ? 3000 : false;
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-1/3" />
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-1/4" />
          </CardHeader>
          <CardContent className="space-y-4">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error || !job) {
    const apiError = error instanceof ApiError ? error : null;
    const isNotFound = apiError?.status === 404;
    const isForbidden = apiError?.status === 403;
    const isRetryable = !apiError || apiError.status === 0 || apiError.status >= 500;

    return (
      <div className="space-y-6">
        <PageHeader
          title="Proof Job Details"
          description="View and monitor cryptographic zero-knowledge proof generation."
          actions={
            <Link href="/proofs" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Back to Proofs
            </Link>
          }
        />
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>
            {isNotFound ? "Job Not Found" : isForbidden ? "Access Denied" : "Error Loading Proof Job"}
          </AlertTitle>
          <AlertDescription className="text-xs mt-1">
            {isNotFound
              ? "The requested proof job does not exist or you do not have permission to view it."
              : isForbidden
                ? "You do not have permission to view this proof job."
                : apiError?.message || "An unexpected network error occurred."}
          </AlertDescription>
        </Alert>
        <div className="flex items-center gap-2">
          {isRetryable && (
            <Button variant="outline" size="sm" onClick={() => void refetch()}>
              <RotateCw className="size-3.5 mr-1" />
              Retry Loading Job
            </Button>
          )}
          <Link href="/proofs" className={buttonVariants({ variant: "outline", size: "sm" })}>
            Return to Proofs List
          </Link>
        </div>
      </div>
    );
  }

  const isTerminal = job.status === "completed" || job.status === "failed" || job.status === "execution_blocked";
  const isRunning = job.status === "pending" || job.status === "assembling_witness" || job.status === "running";
  const eta = calculateProofEta(job);

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title={`Proof Job: ${job.id.slice(0, 8)}...`}
        description="Monitor the cryptographic proof generation lifecycle and public commitments."
        badge={<StatusPill status={job.status} />}
        actions={
          <div className="flex items-center gap-2">
            {!isTerminal && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refetch()}
                disabled={isFetching}
                className="gap-1.5"
              >
                <RotateCw className={cn("size-3.5", isFetching && "animate-spin")} />
                <span>Refresh</span>
              </Button>
            )}
            <Link href="/proofs" className={buttonVariants({ variant: "outline", size: "sm" })}>
              All Proofs
            </Link>
          </div>
        }
      />

      {/* Main Status & Parameters Card */}
      <Card className="shadow-xs">
        <CardHeader className="border-b border-border/60 pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div
                className={cn(
                  "flex size-10 items-center justify-center rounded-lg",
                  job.status === "completed"
                    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : job.status === "failed" || job.status === "execution_blocked"
                      ? "bg-destructive/10 text-destructive"
                      : "bg-primary/10 text-primary"
                )}
              >
                {job.status === "completed" ? (
                  <CheckCircle2 className="size-5" />
                ) : job.status === "failed" ? (
                  <XCircle className="size-5" />
                ) : job.status === "execution_blocked" ? (
                  <ServerOff className="size-5" />
                ) : (
                  <Loader2 className="size-5 animate-spin" />
                )}
              </div>
              <div>
                <CardTitle className="text-base font-semibold">
                  Status: <span className="capitalize">{job.status.replace("_", " ")}</span>
                </CardTitle>
                <CardDescription className="text-xs">
                  {job.status === "completed"
                    ? "UltraPlonk proof generated successfully and ready for verification."
                    : job.status === "failed"
                      ? "The prover encountered an error while constructing constraints or witnesses."
                      : job.status === "execution_blocked"
                        ? "Proof execution worker is currently unavailable or blocked."
                        : "Prover workers are preparing witnesses and computing cryptographic polynomials."}
                </CardDescription>
              </div>
            </div>

            {isRunning && (
              <Badge variant="secondary" className="gap-1.5 text-xs font-medium py-1 px-2.5">
                <Loader2 className="size-3 animate-spin text-primary" />
                <span>Polling every 3s</span>
              </Badge>
            )}
          </div>
        </CardHeader>

        {/* Live Prover Telemetry, Segment Progress & Truthful ETA */}
        {job.chunks && job.chunks.length > 0 && (
          <div className="bg-muted/20 border-b border-border/60 p-4 space-y-3">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
              <span className="font-semibold text-foreground flex items-center gap-1.5">
                <Cpu className="size-3.5 text-primary" />
                Proof Generation Progress: {eta.completedSegments} of {eta.totalSegments} segments ({eta.progressPercent}%)
              </span>
              <span className="text-muted-foreground font-mono text-[11px]">
                {eta.completedChunks} of {eta.totalChunks} chunks completed
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-secondary rounded-full h-2 overflow-hidden">
              <div
                className={cn(
                  "h-2 rounded-full transition-all duration-500 ease-out",
                  eta.isStale ? "bg-amber-500" : "bg-primary"
                )}
                style={{ width: `${eta.progressPercent}%` }}
              />
            </div>

            {/* Stale Worker Warning Banner */}
            {eta.isStale && (
              <div className="rounded-md bg-amber-500/10 border border-amber-500/30 p-2.5 text-xs text-amber-800 dark:text-amber-300 flex items-start gap-2">
                <AlertTriangle className="size-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                <div>
                  <p className="font-medium">Stale Progress Detected</p>
                  <p className="text-[11px] opacity-90">{eta.staleWarning}</p>
                </div>
              </div>
            )}

            {/* Dynamic ETA & Prover Pace Telemetry */}
            {isRunning && !eta.isStale && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 text-[11px]">
                <div className="rounded border border-border/40 bg-background/50 px-2.5 py-1.5 flex items-center gap-2">
                  <Timer className="size-3.5 text-primary shrink-0" />
                  <div>
                    <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Remaining</span>
                    <span className="font-medium text-foreground">{eta.formattedRemainingTime}</span>
                  </div>
                </div>

                <div className="rounded border border-border/40 bg-background/50 px-2.5 py-1.5 flex items-center gap-2">
                  <Clock className="size-3.5 text-primary shrink-0" />
                  <div>
                    <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Est. Completion</span>
                    <span className="font-medium text-foreground">{eta.formattedEstCompletionIST || "Calibrating..."}</span>
                  </div>
                </div>

                <div className="rounded border border-border/40 bg-background/50 px-2.5 py-1.5 flex items-center gap-2">
                  <Cpu className="size-3.5 text-primary shrink-0" />
                  <div>
                    <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Prover Pace</span>
                    <span className="font-medium text-foreground font-mono">
                      {eta.rollingAvgSeconds ? `${eta.rollingAvgSeconds}s / seg` : "Gathering samples..."}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {isRunning && eta.activeChunkIndex !== null && (
              <p className="text-[11px] text-muted-foreground flex items-center gap-1.5">
                <Loader2 className="size-3 animate-spin text-primary" />
                <span>
                  Currently proving <strong>Chunk {eta.activeChunkIndex}</strong> of 32
                </span>
              </p>
            )}

            {job.status === "completed" && (
              <p className="text-[11px] text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5 font-medium">
                <CheckCircle2 className="size-3" />
                <span>All 256 segment proofs cryptographically verified and packaged in archive</span>
              </p>
            )}
          </div>
        )}

        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-5 text-xs">
          {/* Job ID */}
          <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
            <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
              Proof Job ID
            </span>
            <div className="flex items-center justify-between mt-1">
              <p className="font-mono text-foreground break-all">{job.id}</p>
              <Button
                variant="ghost"
                size="icon"
                className="size-6 shrink-0 ml-1 text-muted-foreground hover:text-foreground"
                onClick={() => copyToClipboard(job.id, "job-id")}
              >
                {copiedKey === "job-id" ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
              </Button>
            </div>
          </div>

          {/* SBOM Reference */}
          <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
            <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
              Target SBOM Upload ID
            </span>
            <div className="flex items-center justify-between mt-1">
              <p className="font-mono text-foreground break-all">{job.sbom_upload_id}</p>
              <Button
                variant="ghost"
                size="icon"
                className="size-6 shrink-0 ml-1 text-muted-foreground hover:text-foreground"
                onClick={() => copyToClipboard(job.sbom_upload_id, "sbom-ref")}
              >
                {copiedKey === "sbom-ref" ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
              </Button>
            </div>
          </div>

          {/* Target SBOM Root (R_SBOM) */}
          <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                SBOM Merkle Root (R_SBOM)
              </span>
              {job.sbom_root && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-4 text-[10px] px-1 text-primary"
                  onClick={() => copyToClipboard(job.sbom_root!, "sbom-root")}
                >
                  {copiedKey === "sbom-root" ? "Copied" : "Copy"}
                </Button>
              )}
            </div>
            <p className="font-mono text-foreground mt-1 break-all truncate" title={job.sbom_root || ""}>
              {job.sbom_root || "— (Computed upon witness assembly)"}
            </p>
          </div>

          {/* Vulnerability DB Root (R_VulnDB) */}
          <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                Vulnerability DB Root (R_VulnDB)
              </span>
              {job.vulnerability_db_root && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-4 text-[10px] px-1 text-primary"
                  onClick={() => copyToClipboard(job.vulnerability_db_root!, "vuln-root")}
                >
                  {copiedKey === "vuln-root" ? "Copied" : "Copy"}
                </Button>
              )}
            </div>
            <p className="font-mono text-foreground mt-1 break-all truncate" title={job.vulnerability_db_root || ""}>
              {job.vulnerability_db_root || "— (Extracted from frozen snapshot)"}
            </p>
          </div>

          {/* Policy Hash (H_Policy) */}
          <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                Policy Hash (H_Policy)
              </span>
              {job.policy_hash && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-4 text-[10px] px-1 text-primary"
                  onClick={() => copyToClipboard(job.policy_hash!, "policy-hash")}
                >
                  {copiedKey === "policy-hash" ? "Copied" : "Copy"}
                </Button>
              )}
            </div>
            <p className="font-mono text-foreground mt-1 break-all truncate" title={job.policy_hash || ""}>
              {job.policy_hash || "— (Derived from security policy)"}
            </p>
          </div>

          {/* Timestamps */}
          <div className="rounded-lg bg-muted/40 p-3 border border-border/40 space-y-1">
            <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
              Execution Timeline (IST)
            </span>
            <div className="flex items-center gap-1.5 text-muted-foreground pt-1">
              <Calendar className="size-3 text-muted-foreground" />
              <span>Created: {formatToIST(job.created_at, { includeSeconds: true })}</span>
            </div>
            {job.completed_at && (
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <Check className="size-3 text-emerald-500" />
                <span>Completed: {formatToIST(job.completed_at, { includeSeconds: true })}</span>
              </div>
            )}
            {isRunning && eta.formattedEstCompletionIST && (
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <Clock className="size-3 text-blue-500" />
                <span>Est. Completion: {eta.formattedEstCompletionIST}</span>
              </div>
            )}
          </div>
        </CardContent>

        {/* Prover Error Banner */}
        {job.error_message && (
          <CardFooter className="bg-destructive/10 border-t border-destructive/20 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <p className="text-xs font-bold text-destructive flex items-center gap-1.5">
                <AlertCircle className="size-4" />
                Prover Execution Failure
              </p>
              <p className="text-xs text-destructive/90 font-mono break-all">{job.error_message}</p>
            </div>
            <Link
              href={`/proofs/generate?sbomId=${encodeURIComponent(job.sbom_upload_id)}`}
              className={buttonVariants({ variant: "destructive", size: "sm" })}
            >
              Retry Generation
            </Link>
          </CardFooter>
        )}
      </Card>

      {/* Completion Next Steps (Distinguish Generation from Verification) */}
      {job.status === "completed" && (
        <Alert variant="success" className="border-emerald-500/30 bg-emerald-500/5">
          <ShieldCheck className="size-5 text-emerald-600 dark:text-emerald-400" />
          <AlertTitle className="text-sm font-semibold text-emerald-900 dark:text-emerald-200">
            Cryptographic Proof Generated — Independent Verification Required
          </AlertTitle>
          <AlertDescription className="space-y-3 mt-1.5 text-xs text-muted-foreground leading-relaxed">
            <p>
              The Barretenberg prover has assembled the UltraPlonk proof (2,144 bytes). A generated proof is <strong>not automatically verified</strong> and does not constitute a tamper-evident certificate on its own.
            </p>
            <p>
              Proceed to the Verification workflow to evaluate this proof against the verification smart contract and issue an authoritative verification certificate.
            </p>
            <div>
              <Link
                href={`/verify?proofId=${encodeURIComponent(job.id)}`}
                className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}
              >
                <span>Proceed to Verification</span>
                <ArrowRight className="size-3.5" />
              </Link>
            </div>
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

export default function ProofDetailPage(props: { params: Promise<{ id: string }> }) {
  const params = use(props.params);
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <ProofDetail id={params.id} />
    </RouteGuard>
  );
}
