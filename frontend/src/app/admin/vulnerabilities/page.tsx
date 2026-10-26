"use client";

import * as React from "react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { vulnerabilityService } from "@/api/services/vulnerabilityService";
import { RouteGuard } from "@/auth/RouteGuard";
import { useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import {
  AlertCircle,
  CheckCircle2,
  Database,
  DatabaseBackup,
  Loader2,
  RotateCw,
  Shield,
  ShieldAlert,
  Snowflake,
  XCircle,
} from "lucide-react";
import {
  TRUSTED_VULNERABILITY_SOURCES,
  TrustedVulnerabilitySource,
} from "@/api/types";

function VulnerabilityManagement() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const isImporter = user?.role === "trusted_importer";
  const canIngest = isAdmin || isImporter;

  const [sourceIdentity, setSourceIdentity] = useState<TrustedVulnerabilitySource>("NVD");
  const [provenanceJson, setProvenanceJson] = useState('{\n  "feed_version": "1.0",\n  "collector": "authoritative_feed"\n}');
  const [ingestPayload, setIngestPayload] = useState("");
  const [ingestError, setIngestError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Revocation state modal / inline control
  const [revokingSnapshotId, setRevokingSnapshotId] = useState<string | null>(null);
  const [revocationReason, setRevocationReason] = useState("");

  const { data: snapshots, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["vuln-snapshots"],
    queryFn: () => vulnerabilityService.listSnapshots(),
  });

  const ingestMutation = useMutation({
    mutationFn: async () => {
      let parsedVulns;
      let parsedProvenance;
      try {
        parsedVulns = JSON.parse(ingestPayload);
        if (!Array.isArray(parsedVulns)) throw new Error("Payload must be an array of vulnerability objects");
        if (parsedVulns.length === 0) throw new Error("Vulnerability list must not be empty");
      } catch (e) {
        throw new Error(e instanceof Error ? e.message : "Invalid JSON payload format");
      }

      try {
        parsedProvenance = JSON.parse(provenanceJson);
        if (typeof parsedProvenance !== "object" || parsedProvenance === null || Array.isArray(parsedProvenance)) {
          throw new Error("Provenance must be a non-empty JSON object");
        }
        if (Object.keys(parsedProvenance).length === 0) {
          throw new Error("Provenance must contain at least one metadata key");
        }
      } catch (e) {
        throw new Error(e instanceof Error ? e.message : "Invalid provenance format");
      }

      return vulnerabilityService.ingest({
        source_identity: sourceIdentity,
        provenance: parsedProvenance,
        vulnerabilities: parsedVulns,
      });
    },
    onSuccess: () => {
      setIngestPayload("");
      setIngestError(null);
      queryClient.invalidateQueries({ queryKey: ["vuln-snapshots"] });
    },
    onError: (err) => {
      setIngestError(err instanceof Error ? err.message : "Ingestion failed");
    },
  });

  const actionMutation = useMutation({
    mutationFn: async ({ id, action, reason }: { id: string; action: "approve" | "freeze" | "revoke"; reason?: string }) => {
      if (action === "approve") return vulnerabilityService.approve(id);
      if (action === "freeze") return vulnerabilityService.freeze(id);
      return vulnerabilityService.revoke(id, reason);
    },
    onSuccess: () => {
      setRevokingSnapshotId(null);
      setRevocationReason("");
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ["vuln-snapshots"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Lifecycle action failed";
      setActionError(msg);
    },
  });

  const handleIngest = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canIngest) return;
    setIngestError(null);
    ingestMutation.mutate();
  };

  const handleConfirmRevoke = () => {
    if (!revokingSnapshotId) return;
    setActionError(null);
    actionMutation.mutate({
      id: revokingSnapshotId,
      action: "revoke",
      reason: revocationReason.trim() || undefined,
    });
  };

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Vulnerability Intelligence"
        description="Authoritative threat intelligence state repositories and Sparse Merkle Tree (SMT) snapshot lifecycle."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            {snapshots ? `${snapshots.length} Snapshots` : "Intelligence Feeds"}
          </Badge>
        }
        actions={
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
        }
      />

      {/* Revocation Confirmation Banner (Replaces window.prompt) */}
      {revokingSnapshotId && (
        <Card className="border-destructive/40 bg-destructive/5 shadow-xs">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2 text-destructive">
              <ShieldAlert className="size-4" />
              <CardTitle className="text-sm font-semibold">Confirm Snapshot Revocation</CardTitle>
            </div>
            <CardDescription className="text-xs">
              Revoking a snapshot (<code className="font-mono text-foreground">{revokingSnapshotId.slice(0, 8)}...</code>) is permanent. Revoked snapshots are disqualified from future zero-knowledge proof evaluations.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="space-y-1.5 max-w-lg">
              <Label htmlFor="revocation-reason" className="text-xs font-semibold">
                Revocation Reason (Optional audit record)
              </Label>
              <Input
                id="revocation-reason"
                placeholder="e.g. Upstream feed disclosure retracted by NVD"
                value={revocationReason}
                onChange={(e) => setRevocationReason(e.target.value)}
                className="h-8 text-xs"
                disabled={actionMutation.isPending}
              />
            </div>
          </CardContent>
          <CardFooter className="pt-2 border-t border-destructive/20 flex items-center justify-between">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setRevokingSnapshotId(null);
                setRevocationReason("");
              }}
              disabled={actionMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleConfirmRevoke}
              disabled={actionMutation.isPending}
              className="gap-1.5"
            >
              {actionMutation.isPending ? (
                <>
                  <Loader2 className="size-3.5 animate-spin" />
                  <span>Revoking...</span>
                </>
              ) : (
                <>
                  <XCircle className="size-3.5" />
                  <span>Confirm Revocation</span>
                </>
              )}
            </Button>
          </CardFooter>
        </Card>
      )}

      <div className={cn("grid grid-cols-1 gap-6 items-start", canIngest && "lg:grid-cols-3")}>
        {/* Left Column: Snapshot Catalog */}
        <div className={cn("space-y-6", canIngest ? "lg:col-span-2" : "col-span-1")}>
          <Card className="shadow-xs">
            <CardHeader className="border-b border-border/60 pb-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <CardTitle className="text-base font-semibold">Vulnerability Snapshots</CardTitle>
                  <CardDescription className="text-xs">
                    {isAdmin
                      ? "Administrative view: pending, approved, frozen, and revoked snapshots."
                      : "Authoritative catalog view: approved and frozen vulnerability snapshots."}
                  </CardDescription>
                </div>
                {isAdmin && (
                  <Badge variant="outline" className="text-[10px] w-fit">
                    Admin Oversight Active
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              {isLoading && (
                <div className="space-y-2">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-14 w-full" />
                  <Skeleton className="h-14 w-full" />
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Error loading snapshots</AlertTitle>
                  <AlertDescription className="flex flex-col gap-2 text-xs mt-1">
                    <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                    <Button variant="outline" size="sm" className="w-fit" onClick={() => void refetch()}>
                      Retry
                    </Button>
                  </AlertDescription>
                </Alert>
              )}

              {Boolean(actionError || actionMutation.error) && (
                <Alert variant="destructive" className="mb-4">
                  <AlertCircle className="size-4" />
                  <AlertTitle className="text-xs font-semibold">Administrative Action Failed</AlertTitle>
                  <AlertDescription className="text-[11px] mt-0.5">
                    {actionError || (actionMutation.error instanceof ApiError
                      ? actionMutation.error.message
                      : "The administrative action could not be completed.")}
                  </AlertDescription>
                </Alert>
              )}

              {!isLoading && !error && snapshots && snapshots.length === 0 && (
                <EmptyState
                  icon={Database}
                  title="No vulnerability snapshots available"
                  description={
                    canIngest
                      ? "Submit a threat intelligence payload on the right to initialize a snapshot."
                      : "Snapshots will appear once ingested and approved by administrators."
                  }
                />
              )}

              {!isLoading && !error && snapshots && snapshots.length > 0 && (
                <div className="rounded-lg border border-border/70 overflow-hidden">
                  <Table>
                    <TableHeader className="bg-muted/40">
                      <TableRow>
                        <TableHead className="font-semibold text-xs">ID</TableHead>
                        <TableHead className="font-semibold text-xs">Feed Label</TableHead>
                        <TableHead className="font-semibold text-xs">Records</TableHead>
                        <TableHead className="font-semibold text-xs">Status</TableHead>
                        <TableHead className="font-semibold text-xs">SMT Root (R_VulnDB)</TableHead>
                        {isAdmin && <TableHead className="font-semibold text-xs text-right">Actions</TableHead>}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {snapshots.map((snap) => (
                        <TableRow key={snap.id} className="transition-colors hover:bg-muted/30">
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {snap.id.slice(0, 8)}...
                          </TableCell>
                          <TableCell className="font-medium text-xs text-foreground">
                            {snap.snapshot_label}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {snap.record_count}
                          </TableCell>
                          <TableCell>
                            <StatusPill status={snap.status} />
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground max-w-[150px] truncate" title={snap.authoritative_smt_root || "Not yet frozen"}>
                            {snap.authoritative_smt_root
                              ? `${snap.authoritative_smt_root.slice(0, 8)}...${snap.authoritative_smt_root.slice(-6)}`
                              : "—"}
                          </TableCell>

                          {isAdmin && (
                            <TableCell className="text-right space-x-1.5 whitespace-nowrap">
                              {snap.status === "pending" && (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="h-7 text-xs px-2 gap-1"
                                  onClick={() => {
                                    setActionError(null);
                                    actionMutation.mutate({ id: snap.id, action: "approve" });
                                  }}
                                  disabled={actionMutation.isPending}
                                >
                                  <CheckCircle2 className="size-3 text-emerald-600" />
                                  <span>Approve</span>
                                </Button>
                              )}
                              {snap.status === "approved" && (
                                <Button
                                  variant="default"
                                  size="sm"
                                  className="h-7 text-xs px-2 gap-1"
                                  onClick={() => {
                                    setActionError(null);
                                    actionMutation.mutate({ id: snap.id, action: "freeze" });
                                  }}
                                  disabled={actionMutation.isPending}
                                >
                                  <Snowflake className="size-3" />
                                  <span>Freeze</span>
                                </Button>
                              )}
                              {(snap.status === "pending" || snap.status === "approved" || snap.status === "frozen") && (
                                <Button
                                  variant="destructive"
                                  size="sm"
                                  className="h-7 text-xs px-2 gap-1"
                                  onClick={() => {
                                    setActionError(null);
                                    setRevokingSnapshotId(snap.id);
                                    setRevocationReason("");
                                  }}
                                  disabled={actionMutation.isPending || revokingSnapshotId === snap.id}
                                >
                                  <XCircle className="size-3" />
                                  <span>Revoke</span>
                                </Button>
                              )}
                            </TableCell>
                          )}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Ingestion Panel (Admin or Trusted Importer) */}
        {canIngest && (
          <div className="lg:col-span-1">
            <Card className="shadow-xs">
              <form onSubmit={handleIngest}>
                <CardHeader className="border-b border-border/60 pb-3">
                  <CardTitle className="text-sm font-semibold">Ingest Vulnerability Feed</CardTitle>
                  <CardDescription className="text-xs">
                    Submit authoritative threat intelligence with cryptographic provenance.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4 text-xs">
                  {isAdmin && (
                    <Alert className="bg-primary/5 border-primary/20">
                      <Shield className="size-4 text-primary" />
                      <AlertTitle className="text-xs font-semibold">Two-Person Integrity Rule</AlertTitle>
                      <AlertDescription className="text-[11px] mt-0.5 text-muted-foreground leading-relaxed">
                        Feed ingestion is authorized for Administrators. Snapshots you create must be reviewed and approved by a distinct Administrator before freezing. Creator cannot approve own snapshot.
                      </AlertDescription>
                    </Alert>
                  )}
                  {isImporter && !isAdmin && (
                    <Alert className="bg-muted/40 border-border/70">
                      <Shield className="size-4 text-primary" />
                      <AlertTitle className="text-xs font-semibold">Separation of Duties Notice</AlertTitle>
                      <AlertDescription className="text-[11px] mt-0.5 text-muted-foreground leading-relaxed">
                        Feed ingestion is restricted to authorized importers (<code>trusted_importer</code>). Administrators hold approval and freezing authority.
                      </AlertDescription>
                    </Alert>
                  )}

                  {Boolean(ingestError || ingestMutation.error) && (
                    <Alert variant="destructive">
                      <AlertCircle className="size-4" />
                      <AlertTitle className="text-xs font-semibold">Ingestion Failed</AlertTitle>
                      <AlertDescription className="text-[11px] mt-0.5">
                        {ingestError || (ingestMutation.error instanceof ApiError ? ingestMutation.error.message : "Network error")}
                      </AlertDescription>
                    </Alert>
                  )}

                  {ingestMutation.isSuccess && (
                    <Alert className="border-emerald-500/30 bg-emerald-500/10 text-emerald-900 dark:text-emerald-200">
                      <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
                      <AlertTitle className="text-xs font-semibold">Ingestion Successful</AlertTitle>
                      <AlertDescription className="text-[11px] mt-0.5">
                        Snapshot created and submitted for administrative review (<code className="font-mono">pending</code> status).
                      </AlertDescription>
                    </Alert>
                  )}

                  <div className="space-y-1.5">
                    <Label htmlFor="sourceIdentity" className="text-xs font-semibold">
                      Source Identity <span className="text-destructive">*</span>
                    </Label>
                    <select
                      id="sourceIdentity"
                      className="flex h-8 w-full rounded-md border border-input bg-background px-2 py-1 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      value={sourceIdentity}
                      onChange={(e) => setSourceIdentity(e.target.value as TrustedVulnerabilitySource)}
                      disabled={!canIngest || ingestMutation.isPending}
                      required
                    >
                      {TRUSTED_VULNERABILITY_SOURCES.map((source) => (
                        <option key={source} value={source}>
                          {source}
                        </option>
                      ))}
                    </select>
                    <p className="text-[11px] text-muted-foreground">Recognized authoritative provider identity.</p>
                  </div>

                  <div className="space-y-1.5">
                    <Label htmlFor="provenance" className="text-xs font-semibold">
                      Feed Provenance (JSON) <span className="text-destructive">*</span>
                    </Label>
                    <Textarea
                      id="provenance"
                      className="font-mono text-xs h-20"
                      value={provenanceJson}
                      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setProvenanceJson(e.target.value)}
                      disabled={!canIngest || ingestMutation.isPending}
                      required
                    />
                    <p className="text-[11px] text-muted-foreground">Audit metadata (feed version, collector signature).</p>
                  </div>

                  <div className="space-y-1.5">
                    <Label htmlFor="payload" className="text-xs font-semibold">
                      Vulnerabilities (JSON Array) <span className="text-destructive">*</span>
                    </Label>
                    <Textarea
                      id="payload"
                      className="font-mono text-xs h-28"
                      placeholder={`[\n  { "purl": "pkg:npm/express@4.17.1", "cvss_score": 8.5 }\n]`}
                      value={ingestPayload}
                      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setIngestPayload(e.target.value)}
                      disabled={!canIngest || ingestMutation.isPending}
                      required
                    />
                    <p className="text-[11px] text-muted-foreground">Array adhering to VulnerabilityIngestionItem schema.</p>
                  </div>
                </CardContent>
                <CardFooter className="pt-2 border-t border-border/50 bg-muted/10">
                  <Button
                    type="submit"
                    size="sm"
                    className="w-full gap-1.5"
                    disabled={!canIngest || ingestMutation.isPending || !ingestPayload.trim() || !provenanceJson.trim()}
                  >
                    {ingestMutation.isPending ? (
                      <>
                        <Loader2 className="size-3.5 animate-spin" />
                        <span>Ingesting Snapshot...</span>
                      </>
                    ) : (
                      <>
                        <DatabaseBackup className="size-3.5" />
                        <span>Submit Ingestion</span>
                      </>
                    )}
                  </Button>
                </CardFooter>
              </form>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

export default function AdminVulnerabilitiesPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor", "buyer", "trusted_importer"]}>
      <VulnerabilityManagement />
    </RouteGuard>
  );
}
