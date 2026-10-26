"use client";

import * as React from "react";
import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { certificateService } from "@/api/services/certificateService";
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
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  AlertCircle,
  Check,
  Copy,
  Eye,
  FileBadge,
  RotateCw,
  Search,
  ShieldCheck,
  X,
  XCircle,
} from "lucide-react";

function CertificateList() {
  const {
    data: certificates,
    isLoading,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["certificates"],
    queryFn: () => certificateService.list(),
  });

  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
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

  // Derived metrics from live API payload
  const metrics = useMemo(() => {
    if (!certificates || certificates.length === 0) return null;
    const total = certificates.length;
    const active = certificates.filter((c) => !c.is_revoked).length;
    const revoked = certificates.filter((c) => c.is_revoked).length;
    return { total, active, revoked };
  }, [certificates]);

  // Client-side filtering
  const filteredCertificates = useMemo(() => {
    if (!certificates) return [];
    return certificates.filter((cert) => {
      const matchesSearch =
        searchTerm.trim() === "" ||
        cert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        cert.verification_request_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        cert.sbom_root.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "active" && !cert.is_revoked) ||
        (statusFilter === "revoked" && cert.is_revoked);

      return matchesSearch && matchesStatus;
    });
  }, [certificates, searchTerm, statusFilter]);

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Verification Certificates"
        description="Tamper-evident cryptographic attestations issued by the backend upon successful zero-knowledge proof verification."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            Attestation Registry
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
            <Link href="/verify" className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}>
              <ShieldCheck className="size-4" />
              <span>Verify a Proof</span>
            </Link>
          </div>
        }
      />

      {/* Metrics Strip */}
      {!isLoading && !error && metrics && metrics.total > 0 && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <FileBadge className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total Certificates</p>
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
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Active Attestations</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.active}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
                <XCircle className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Revoked</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.revoked}</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Main Certificates Card */}
      <Card>
        <CardHeader className="border-b border-border/60 pb-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-lg font-semibold">Attestation Records</CardTitle>
              <CardDescription className="text-xs mt-0.5">
                Authoritative verification certificates. Certificates are tamper-evident but can be revoked if underlying security assumptions or vulnerability disclosures change.
              </CardDescription>
            </div>

            {/* Filter and Search Bar */}
            {!isLoading && !error && certificates && certificates.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[200px] sm:w-64">
                  <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search by Cert ID or SBOM Root..."
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
                    onClick={() => setStatusFilter("active")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "active"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Active
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("revoked")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "revoked"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Revoked
                  </button>
                </div>
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="pt-6">
          {/* Loading Skeleton */}
          {isLoading && (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          )}

          {/* Network Error Alert */}
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="size-4" />
              <AlertTitle>Error Loading Certificates</AlertTitle>
              <AlertDescription className="flex flex-col gap-2 mt-1 text-xs">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => void refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {/* Empty State: Zero certificates in account */}
          {!isLoading && !error && certificates && certificates.length === 0 && (
            <EmptyState
              icon={FileBadge}
              title="No certificates issued"
              description="Certificates are automatically minted when an UltraPlonk proof is successfully verified against authoritative roots."
              action={
                <Link href="/verify" className={cn(buttonVariants(), "gap-2")}>
                  <ShieldCheck className="size-4" />
                  Go to Verification
                </Link>
              }
            />
          )}

          {/* Empty Search Filter State */}
          {!isLoading && !error && certificates && certificates.length > 0 && filteredCertificates.length === 0 && (
            <EmptyState
              icon={Search}
              title="No matching certificates"
              description="No certificates matched your filter or search criteria."
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
          {!isLoading && !error && filteredCertificates.length > 0 && (
            <div className="space-y-3">
              <div className="rounded-lg border border-border/70 overflow-hidden">
                <Table>
                  <TableHeader className="bg-muted/40">
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="font-semibold text-xs">Certificate ID</TableHead>
                      <TableHead className="font-semibold text-xs">Status</TableHead>
                      <TableHead className="font-semibold text-xs">Verification Ref</TableHead>
                      <TableHead className="font-semibold text-xs">SBOM Merkle Root</TableHead>
                      <TableHead className="font-semibold text-xs">Issued At</TableHead>
                      <TableHead className="font-semibold text-xs text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredCertificates.map((cert) => (
                      <TableRow key={cert.id} className="transition-colors hover:bg-muted/30">
                        {/* Certificate ID */}
                        <TableCell className="font-mono text-xs">
                          <div className="flex items-center gap-1.5">
                            <span title={cert.id}>{cert.id.slice(0, 8)}...</span>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="size-5 shrink-0 text-muted-foreground hover:text-foreground"
                              onClick={() => copyToClipboard(cert.id, cert.id)}
                            >
                              {copiedKey === cert.id ? (
                                <Check className="size-3 text-emerald-500" />
                              ) : (
                                <Copy className="size-3" />
                              )}
                            </Button>
                          </div>
                        </TableCell>

                        {/* Status */}
                        <TableCell>
                          <StatusPill status={cert.is_revoked ? "revoked" : "active"} />
                        </TableCell>

                        {/* Verification Request Reference */}
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          <span title={cert.verification_request_id}>
                            {cert.verification_request_id.slice(0, 8)}...
                          </span>
                        </TableCell>

                        {/* SBOM Root */}
                        <TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[140px]" title={cert.sbom_root}>
                          {cert.sbom_root}
                        </TableCell>

                        {/* Issued Timestamp */}
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {new Date(cert.issued_at).toLocaleString(undefined, {
                            year: "numeric",
                            month: "short",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </TableCell>

                        {/* Action Link */}
                        <TableCell className="text-right">
                          <Link
                            href={`/certificates/${encodeURIComponent(cert.id)}`}
                            className={cn(buttonVariants({ variant: "outline", size: "sm" }), "h-7 text-xs px-2.5 gap-1")}
                          >
                            <Eye className="size-3" />
                            <span>View Public Record</span>
                          </Link>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>

              {/* Informational footer note */}
              <div className="flex flex-col sm:flex-row items-center justify-between text-[11px] text-muted-foreground px-1 gap-1">
                <span>
                  Showing {filteredCertificates.length} of {certificates?.length || 0} certificates.
                </span>
                <span className="flex items-center gap-1">
                  <ShieldCheck className="size-3 text-primary" />
                  Public certificate validation does not require active session authentication.
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function CertificatesPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor", "buyer"]}>
      <CertificateList />
    </RouteGuard>
  );
}
