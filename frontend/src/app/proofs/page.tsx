"use client";

import * as React from "react";
import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/errors";
import { formatTableTimestamp } from "@/lib/dateTime";
import { calculateProofEta } from "@/lib/etaCalculator";
import Link from "next/link";
import {
  AlertCircle,
  Clock,
  Cpu,
  Eye,
  Plus,
  RotateCw,
  Search,
  ShieldCheck,
  X,
  XCircle
} from "lucide-react";

function ProofList() {
  const { data: proofs, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["proofs"],
    queryFn: () => proofService.list(),
    // Poll the list every 5 seconds if there are active background jobs
    refetchInterval: (query) => {
      if (query.state.error) return false;
      const hasActiveJobs = query.state.data?.some(
        (p) => p.status === "pending" || p.status === "assembling_witness" || p.status === "running"
      );
      return hasActiveJobs ? 5000 : false;
    },
  });

  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Metrics derived from live API payload
  const metrics = useMemo(() => {
    if (!proofs || proofs.length === 0) return null;
    const total = proofs.length;
    const completed = proofs.filter((p) => p.status === "completed").length;
    const inProgress = proofs.filter(
      (p) => p.status === "pending" || p.status === "assembling_witness" || p.status === "running"
    ).length;
    const failed = proofs.filter((p) => p.status === "failed" || p.status === "execution_blocked").length;
    return { total, completed, inProgress, failed };
  }, [proofs]);

  // Client-side filtering
  const filteredProofs = useMemo(() => {
    if (!proofs) return [];
    return proofs.filter((proof) => {
      const matchesSearch =
        searchTerm.trim() === "" ||
        proof.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        proof.sbom_upload_id.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "completed" && proof.status === "completed") ||
        (statusFilter === "in_progress" &&
          (proof.status === "pending" || proof.status === "assembling_witness" || proof.status === "running")) ||
        (statusFilter === "failed" && (proof.status === "failed" || proof.status === "execution_blocked"));

      return matchesSearch && matchesStatus;
    });
  }, [proofs, searchTerm, statusFilter]);

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Proof Generation Jobs"
        description="Manage and track UltraPlonk zero-knowledge proof computations."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-muted-foreground">
            UltraPlonk Prover
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void refetch()}
              disabled={isLoading || isFetching}
              className="gap-1.5"
            >
              <RotateCw className={cn("size-3.5", (isLoading || isFetching) && "animate-spin")} />
              <span>Refresh</span>
            </Button>
            <Link href="/proofs/generate" className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}>
              <Plus className="size-4" />
              <span>Generate Proof</span>
            </Link>
          </div>
        }
      />

      {/* Metrics Strip */}
      {!isLoading && !error && metrics && metrics.total > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Cpu className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total Jobs</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.total}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <ShieldCheck className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Completed</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.completed}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400">
                <Clock className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">In Progress</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.inProgress}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
                <XCircle className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Failed / Blocked</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.failed}</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Main Jobs Card */}
      <Card>
        <CardHeader className="border-b border-border/60 pb-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-lg font-semibold">Prover Workloads</CardTitle>
              <CardDescription className="text-xs mt-0.5">
                Asynchronous UltraPlonk proving jobs executed by local Barretenberg workers.
              </CardDescription>
            </div>

            {/* Filter and Search Bar */}
            {!isLoading && !error && proofs && proofs.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[200px] sm:w-64">
                  <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search by Job ID or SBOM Ref..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="h-8 pl-8 text-xs"
                  />
                  {searchTerm && (
                    <button
                      type="button"
                      onClick={() => setSearchTerm("")}
                      className="absolute right-2 top-2 text-muted-foreground hover:text-foreground"
                    >
                      <X className="size-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-lg border border-border/50 text-xs">
                  <button
                    type="button"
                    onClick={() => setStatusFilter("all")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "all"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    All
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("completed")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "completed"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Completed
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("in_progress")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "in_progress"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    In Progress
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("failed")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "failed"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Failed
                  </button>
                </div>
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="pt-4">
          {/* Loading Skeleton */}
          {isLoading && (
            <div className="space-y-3 py-2">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          )}

          {/* Network Error Alert */}
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="size-4" />
              <AlertTitle>Error loading proof jobs</AlertTitle>
              <AlertDescription className="flex flex-col gap-2 mt-1">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => void refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {/* Empty State: Zero jobs in account */}
          {!isLoading && !error && proofs && proofs.length === 0 && (
            <EmptyState
              icon={Cpu}
              title="No proof jobs found"
              description="You have not generated any zero-knowledge proofs yet. Select an uploaded SBOM to launch a proof job."
              action={
                <Link href="/proofs/generate" className={cn(buttonVariants(), "gap-2")}>
                  <Plus className="size-4" />
                  Generate First Proof
                </Link>
              }
            />
          )}

          {/* Empty Search Filter State */}
          {!isLoading && !error && proofs && proofs.length > 0 && filteredProofs.length === 0 && (
            <EmptyState
              icon={Search}
              title="No matching proof jobs"
              description="No proof jobs matched your query or filter criteria. Adjust your search or clear filters."
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearchTerm("");
                    setStatusFilter("all");
                  }}
                >
                  Clear Filters
                </Button>
              }
            />
          )}

          {/* Populated Table */}
          {!isLoading && !error && filteredProofs.length > 0 && (
            <div className="space-y-3">
              <div className="rounded-lg border border-border/70 overflow-hidden">
                <Table>
                  <TableHeader className="bg-muted/40">
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="font-semibold text-xs">Job ID</TableHead>
                      <TableHead className="font-semibold text-xs">SBOM Reference</TableHead>
                      <TableHead className="font-semibold text-xs">Status & Progress</TableHead>
                      <TableHead className="font-semibold text-xs">Created At (IST)</TableHead>
                      <TableHead className="font-semibold text-xs text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredProofs.map((proof) => {
                      const proofEta = calculateProofEta(proof);
                      return (
                        <TableRow key={proof.id} className="transition-colors hover:bg-muted/30">
                          <TableCell className="font-mono text-xs">
                            <span title={proof.id}>{proof.id.slice(0, 8)}...</span>
                          </TableCell>

                          <TableCell className="font-mono text-xs text-muted-foreground">
                            <span title={proof.sbom_upload_id}>{proof.sbom_upload_id.slice(0, 8)}...</span>
                          </TableCell>

                          <TableCell>
                            <div className="flex flex-col gap-1">
                              <div className="flex items-center gap-1.5">
                                <StatusPill status={proof.status} />
                                {proofEta.isStale && (
                                  <Badge variant="destructive" className="text-[9px] px-1.5 py-0 h-4">
                                    Stale
                                  </Badge>
                                )}
                              </div>
                              {proof.chunks && proof.chunks.length > 0 && proof.status !== "failed" && (
                                <div className="flex flex-col gap-0.5">
                                  <span className="text-[10px] font-mono text-muted-foreground">
                                    {proofEta.completedSegments} / {proofEta.totalSegments} segs ({proofEta.progressPercent}%)
                                  </span>
                                  {proof.status === "running" && (
                                    <span className="text-[10px] text-primary/90 font-medium">
                                      ETA: {proofEta.formattedRemainingTime}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                          </TableCell>

                          <TableCell className="text-xs text-muted-foreground whitespace-nowrap font-mono">
                            {formatTableTimestamp(proof.created_at)}
                          </TableCell>

                          <TableCell className="text-right">
                            <Link
                              href={`/proofs/${proof.id}`}
                              className={cn(buttonVariants({ variant: "outline", size: "sm" }), "h-7 text-xs px-2.5 gap-1")}
                            >
                              <Eye className="size-3" />
                              <span>View</span>
                            </Link>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>

              {/* Transparency Notice */}
              <div className="flex flex-col sm:flex-row items-center justify-between text-[11px] text-muted-foreground px-1 gap-1">
                <span>
                  Showing {filteredProofs.length} of {proofs?.length || 0} proof jobs (filtered client-side).
                </span>
                <span className="flex items-center gap-1">
                  <ShieldCheck className="size-3 text-primary" />
                  Barretenberg 0.46.1 UltraPlonk Prover • Zero witness disclosure
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function ProofsPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <ProofList />
    </RouteGuard>
  );
}
