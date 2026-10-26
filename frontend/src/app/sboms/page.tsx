"use client";

import * as React from "react";
import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { sbomService } from "@/api/services/sbomService";
import { SBOMUploadResponse } from "@/api/types";
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
import Link from "next/link";
import {
  AlertCircle,
  Plus,
  RotateCw,
  Search,
  FileBox,
  ShieldCheck,
  Copy,
  Check,
  FileCode,
  Layers,
  Calendar,
  X,
  ArrowRight,
  Info
} from "lucide-react";

function SbomList() {
  const { data: sboms, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => sbomService.list(),
  });

  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedSbom, setSelectedSbom] = useState<SBOMUploadResponse | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const copyToClipboard = async (text: string, fieldKey: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(fieldKey);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // Fallback
    }
  };

  // Metrics derived from verified API payload
  const metrics = useMemo(() => {
    if (!sboms || sboms.length === 0) return null;
    const total = sboms.length;
    const committed = sboms.filter((s) => s.status.toLowerCase() === "committed").length;
    const uniqueApps = new Set(sboms.map((s) => s.application_name || s.application_id)).size;
    const totalComponents = sboms.reduce((acc, s) => acc + (s.component_count || 0), 0);
    return { total, committed, uniqueApps, totalComponents };
  }, [sboms]);

  // Client-side filtering
  const filteredSboms = useMemo(() => {
    if (!sboms) return [];
    return sboms.filter((sbom) => {
      const matchesSearch =
        searchTerm.trim() === "" ||
        (sbom.filename && sbom.filename.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (sbom.application_name && sbom.application_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (sbom.vendor && sbom.vendor.toLowerCase().includes(searchTerm.toLowerCase())) ||
        sbom.application_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        sbom.upload_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (sbom.sbom_root && sbom.sbom_root.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesStatus =
        statusFilter === "all" || sbom.status.toLowerCase() === statusFilter.toLowerCase();

      return matchesSearch && matchesStatus;
    });
  }, [sboms, searchTerm, statusFilter]);

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="SBOM Workspace"
        description="Cryptographic software bill of materials commitments for vendor applications."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-muted-foreground">
            CycloneDX JSON
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isLoading || isFetching}
              className="gap-1.5"
            >
              <RotateCw className={cn("size-3.5", (isLoading || isFetching) && "animate-spin")} />
              <span>Refresh</span>
            </Button>
            <Link href="/sboms/upload" className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}>
              <Plus className="size-4" />
              <span>Upload SBOM</span>
            </Link>
          </div>
        }
      />

      {/* Metrics Overview Strip - Only rendered from live API data */}
      {!isLoading && !error && metrics && metrics.total > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <FileBox className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total SBOMs</p>
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
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Committed</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.committed}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400">
                <Layers className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Applications</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.uniqueApps}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-purple-500/10 text-purple-600 dark:text-purple-400">
                <FileCode className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Components</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.totalComponents}</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Main Workspace Card */}
      <Card>
        <CardHeader className="border-b border-border/60 pb-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-lg font-semibold">Registered Commitments</CardTitle>
              <CardDescription className="text-xs mt-0.5">
                Authentic sparse Merkle tree commitments (R_SBOM) computed from vendor SBOMs.
              </CardDescription>
            </div>

            {/* Filter and Search Bar */}
            {!isLoading && !error && sboms && sboms.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[200px] sm:w-64">
                  <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search by file, app, or hash..."
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
                    onClick={() => setStatusFilter("committed")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "committed"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Committed
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("pending")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "pending"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Pending
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

          {/* Network Error State */}
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="size-4" />
              <AlertTitle>Error loading SBOMs</AlertTitle>
              <AlertDescription className="flex flex-col gap-2 mt-1">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {/* Empty State: No SBOMs uploaded at all */}
          {!isLoading && !error && sboms && sboms.length === 0 && (
            <EmptyState
              icon={FileBox}
              title="No SBOM commitments found"
              description="You haven't uploaded any software bills of materials yet. Upload a CycloneDX JSON document to generate cryptographic commitments."
              action={
                <Link href="/sboms/upload" className={cn(buttonVariants(), "gap-2")}>
                  <Plus className="size-4" />
                  Upload First SBOM
                </Link>
              }
            />
          )}

          {/* Empty Filter State: SBOMs exist, but search returned 0 */}
          {!isLoading && !error && sboms && sboms.length > 0 && filteredSboms.length === 0 && (
            <EmptyState
              icon={Search}
              title="No matching SBOM commitments"
              description="No SBOMs matched your search and filter criteria. Adjust your search or clear filters."
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
          {!isLoading && !error && filteredSboms.length > 0 && (
            <div className="space-y-3">
              <div className="rounded-lg border border-border/70 overflow-hidden">
                <Table>
                  <TableHeader className="bg-muted/40">
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="font-semibold text-xs">Application</TableHead>
                      <TableHead className="font-semibold text-xs">Filename</TableHead>
                      <TableHead className="font-semibold text-xs">Format</TableHead>
                      <TableHead className="font-semibold text-xs text-center">Components</TableHead>
                      <TableHead className="font-semibold text-xs">Status</TableHead>
                      <TableHead className="font-semibold text-xs">Commitment (R_SBOM)</TableHead>
                      <TableHead className="font-semibold text-xs">Uploaded</TableHead>
                      <TableHead className="font-semibold text-xs text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSboms.map((sbom) => {
                      const rootDisplay = sbom.sbom_root
                        ? `${sbom.sbom_root.slice(0, 10)}...${sbom.sbom_root.slice(-8)}`
                        : "—";

                      return (
                        <TableRow key={sbom.upload_id} className="transition-colors hover:bg-muted/30">
                          {/* Application Name & Vendor */}
                          <TableCell className="text-xs">
                            {sbom.application_name ? (
                              <div className="flex flex-col">
                                <span className="font-medium text-foreground">
                                  {sbom.application_name}
                                </span>
                                {sbom.vendor && (
                                  <span className="text-[11px] text-muted-foreground">
                                    {sbom.vendor}
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span
                                className="text-muted-foreground italic text-[11px]"
                                title={sbom.application_id}
                              >
                                Application details unavailable
                              </span>
                            )}
                          </TableCell>

                          {/* Filename (Untrusted input safely rendered) */}
                          <TableCell className="font-medium text-xs max-w-[160px] truncate">
                            <span title={sbom.filename || "No filename recorded"}>
                              {sbom.filename || "—"}
                            </span>
                          </TableCell>

                          {/* Format */}
                          <TableCell>
                            <Badge variant="outline" className="text-[11px] font-mono px-1.5 py-0">
                              {sbom.format}
                            </Badge>
                          </TableCell>

                          {/* Component Count */}
                          <TableCell className="text-center font-mono text-xs">
                            {sbom.component_count !== null && sbom.component_count !== undefined ? (
                              <span className="font-medium text-foreground">{sbom.component_count}</span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>

                          {/* Status Pill */}
                          <TableCell>
                            <StatusPill status={sbom.status} />
                          </TableCell>

                          {/* Merkle Root Commitment */}
                          <TableCell className="font-mono text-xs">
                            {sbom.sbom_root ? (
                              <div className="flex items-center gap-1.5">
                                <span className="text-muted-foreground truncate max-w-[140px]" title={sbom.sbom_root}>
                                  {rootDisplay}
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="size-6 text-muted-foreground hover:text-foreground"
                                  onClick={() => copyToClipboard(sbom.sbom_root!, `root-${sbom.upload_id}`)}
                                  title="Copy Merkle Root"
                                >
                                  {copiedField === `root-${sbom.upload_id}` ? (
                                    <Check className="size-3 text-emerald-500" />
                                  ) : (
                                    <Copy className="size-3" />
                                  )}
                                </Button>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>

                          {/* Created Date */}
                          <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                            {new Date(sbom.created_at).toLocaleDateString(undefined, {
                              year: "numeric",
                              month: "short",
                              day: "numeric",
                            })}
                          </TableCell>

                          {/* Row Actions */}
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-7 text-xs px-2"
                                onClick={() => setSelectedSbom(sbom)}
                              >
                                Details
                              </Button>
                              <Link
                                href={`/proofs/generate?sbomId=${encodeURIComponent(sbom.upload_id)}`}
                                className={cn(
                                  buttonVariants({ variant: "default", size: "sm" }),
                                  "h-7 text-xs px-2 gap-1"
                                )}
                              >
                                <span>Proof</span>
                                <ArrowRight className="size-3" />
                              </Link>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>

              {/* Subtitle / Transparency note */}
              <div className="flex flex-col sm:flex-row items-center justify-between text-[11px] text-muted-foreground px-1 gap-1">
                <span>
                  Showing {filteredSboms.length} of {sboms?.length || 0} commitments (filtered client-side).
                </span>
                <span className="flex items-center gap-1">
                  <ShieldCheck className="size-3 text-primary" />
                  Zero Component Disclosure: raw components are never returned by the API.
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Details Modal / Drawer overlay */}
      {selectedSbom && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in-50"
          role="dialog"
          aria-modal="true"
          aria-labelledby="detail-title"
        >
          <Card className="w-full max-w-xl shadow-xl border-border bg-card">
            <CardHeader className="border-b border-border/70 pb-3 flex flex-row items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <CardTitle id="detail-title" className="text-lg font-semibold">
                    SBOM Commitment Details
                  </CardTitle>
                  <StatusPill status={selectedSbom.status} />
                </div>
                <CardDescription className="text-xs">
                  Cryptographic metadata for upload {selectedSbom.upload_id.slice(0, 8)}...
                </CardDescription>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="size-7 text-muted-foreground hover:text-foreground"
                onClick={() => setSelectedSbom(null)}
              >
                <X className="size-4" />
                <span className="sr-only">Close</span>
              </Button>
            </CardHeader>

            <CardContent className="space-y-4 pt-4 text-xs">
              {/* Properties Grid */}
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
                  <p className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                    Application
                  </p>
                  <p className="font-medium text-foreground mt-1 truncate">
                    {selectedSbom.application_name || "Application details unavailable"}
                  </p>
                  {selectedSbom.vendor && (
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      Vendor: {selectedSbom.vendor}
                    </p>
                  )}
                  <div className="flex items-center justify-between mt-1 text-[10px] text-muted-foreground font-mono">
                    <span title={selectedSbom.application_id}>ID: {selectedSbom.application_id.slice(0, 8)}...</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-5 shrink-0 text-muted-foreground hover:text-foreground"
                      onClick={() => copyToClipboard(selectedSbom.application_id, "modal-appid")}
                    >
                      {copiedField === "modal-appid" ? (
                        <Check className="size-2.5 text-emerald-500" />
                      ) : (
                        <Copy className="size-2.5" />
                      )}
                    </Button>
                  </div>
                </div>

                <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
                  <p className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                    Upload ID
                  </p>
                  <div className="flex items-center justify-between mt-1">
                    <p className="font-mono text-foreground break-all">{selectedSbom.upload_id}</p>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-6 shrink-0 ml-1 text-muted-foreground hover:text-foreground"
                      onClick={() => copyToClipboard(selectedSbom.upload_id, "modal-uploadid")}
                    >
                      {copiedField === "modal-uploadid" ? (
                        <Check className="size-3 text-emerald-500" />
                      ) : (
                        <Copy className="size-3" />
                      )}
                    </Button>
                  </div>
                </div>

                <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
                  <p className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                    Filename
                  </p>
                  <p className="font-medium text-foreground mt-1 truncate" title={selectedSbom.filename || ""}>
                    {selectedSbom.filename || "—"}
                  </p>
                </div>

                <div className="rounded-lg bg-muted/40 p-3 border border-border/40">
                  <p className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                    Format & Count
                  </p>
                  <p className="font-medium text-foreground mt-1">
                    {selectedSbom.format} • {selectedSbom.component_count ?? "—"} components
                  </p>
                </div>
              </div>

              {/* Cryptographic Commitment Root */}
              <div className="rounded-lg bg-muted/50 p-3 border border-border/60">
                <div className="flex items-center justify-between">
                  <p className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                    Poseidon Merkle Root Commitment (R_SBOM)
                  </p>
                  {selectedSbom.sbom_root && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-5 text-[10px] px-1.5 gap-1 text-primary"
                      onClick={() => copyToClipboard(selectedSbom.sbom_root!, "modal-root")}
                    >
                      {copiedField === "modal-root" ? (
                        <>
                          <Check className="size-2.5 text-emerald-500" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="size-2.5" />
                          <span>Copy</span>
                        </>
                      )}
                    </Button>
                  )}
                </div>
                <p className="font-mono text-[11px] text-foreground mt-1.5 break-all select-all bg-background/80 p-2 rounded border border-border/50">
                  {selectedSbom.sbom_root || "Commitment computation pending."}
                </p>
              </div>

              {/* Timestamp */}
              <div className="flex items-center gap-1.5 text-muted-foreground text-[11px]">
                <Calendar className="size-3.5" />
                <span>Uploaded: {new Date(selectedSbom.created_at).toLocaleString()}</span>
              </div>

              {/* Privacy Notice */}
              <div className="flex items-start gap-2 rounded-lg bg-primary/5 p-3 text-[11px] text-muted-foreground border border-primary/10">
                <Info className="size-4 text-primary shrink-0 mt-0.5" />
                <p>
                  <strong className="text-foreground">Zero Component Disclosure:</strong> Raw component names, versions, and dependency graphs remain strictly confidential within the vendor domain. Only the Poseidon SMT root commitment is published for zero-knowledge verification.
                </p>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-border/60">
                <Button variant="outline" size="sm" onClick={() => setSelectedSbom(null)}>
                  Close
                </Button>
                <Link
                  href={`/proofs/generate?sbomId=${encodeURIComponent(selectedSbom.upload_id)}`}
                  className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}
                >
                  <span>Generate ZK Proof</span>
                  <ArrowRight className="size-3.5" />
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

export default function SbomsPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <SbomList />
    </RouteGuard>
  );
}
