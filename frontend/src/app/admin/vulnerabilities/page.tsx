"use client";

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
import { Label } from "@/components/ui/label";
import { AlertCircle, CheckCircle2, ShieldAlert, Loader2, DatabaseBackup } from "lucide-react";
import { ApiError } from "@/api/errors";
import { Badge } from "@/components/ui/badge";
import { VulnerabilitySnapshotStatus } from "@/api/types";

function getStatusBadge(status: VulnerabilitySnapshotStatus) {
  switch (status) {
    case "approved":
      return <Badge className="bg-success text-success-foreground hover:bg-success/90">Approved</Badge>;
    case "revoked":
      return <Badge variant="destructive">Revoked</Badge>;
    case "pending":
      return <Badge variant="secondary">Pending</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function VulnerabilityManagement() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [ingestPayload, setIngestPayload] = useState("");
  const [ingestError, setIngestError] = useState<string | null>(null);

  const { data: snapshots, isLoading, error, refetch } = useQuery({
    queryKey: ["vuln-snapshots"],
    queryFn: () => vulnerabilityService.listSnapshots(),
  });

  const ingestMutation = useMutation({
    mutationFn: async () => {
      let parsed;
      try {
        parsed = JSON.parse(ingestPayload);
        if (!Array.isArray(parsed)) throw new Error("Payload must be an array of vulnerability objects");
      } catch {
        throw new Error("Invalid JSON payload format");
      }
      return vulnerabilityService.ingest({ vulnerabilities: parsed });
    },
    onSuccess: () => {
      setIngestPayload("");
      setIngestError(null);
      queryClient.invalidateQueries({ queryKey: ["vuln-snapshots"] });
    },
    onError: (err) => {
      setIngestError(err instanceof Error ? err.message : "Ingestion failed");
    }
  });

  const actionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: string, action: "approve" | "revoke" }) => {
      if (action === "approve") return vulnerabilityService.approve(id);
      return vulnerabilityService.revoke(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vuln-snapshots"] });
    }
  });

  const handleIngest = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdmin) return;
    setIngestError(null);
    ingestMutation.mutate();
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Vulnerability Intelligence</h1>
        <p className="text-muted-foreground">Manage and authorize vulnerability snapshots for Zero-Knowledge Proof verifications.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Vulnerability Snapshots</CardTitle>
              <CardDescription>Authoritative threat state repositories.</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading && (
                <div className="space-y-2">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Error loading snapshots</AlertTitle>
                  <AlertDescription className="flex flex-col gap-2">
                    <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                    <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
                      Retry
                    </Button>
                  </AlertDescription>
                </Alert>
              )}

              {actionMutation.error && (
                <Alert variant="destructive" className="mb-4">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Action Failed</AlertTitle>
                  <AlertDescription>
                    {actionMutation.error instanceof ApiError ? actionMutation.error.message : "The administrative action failed."}
                  </AlertDescription>
                </Alert>
              )}

              {!isLoading && !error && snapshots && snapshots.length === 0 && (
                <div className="flex flex-col items-center justify-center rounded-md border border-dashed p-8 text-center bg-muted/50">
                  <h3 className="mt-4 text-sm font-semibold">No snapshots found</h3>
                  <p className="mb-4 mt-2 text-sm text-muted-foreground">
                    No vulnerability snapshots are currently available.
                  </p>
                </div>
              )}

              {!isLoading && !error && snapshots && snapshots.length > 0 && (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>ID</TableHead>
                        <TableHead>Label</TableHead>
                        <TableHead>Records</TableHead>
                        <TableHead>Status</TableHead>
                        {isAdmin && <TableHead className="text-right">Actions</TableHead>}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {snapshots.map((snap) => (
                        <TableRow key={snap.id}>
                          <TableCell className="font-mono text-xs">{snap.id.slice(0, 8)}...</TableCell>
                          <TableCell className="font-medium">{snap.snapshot_label}</TableCell>
                          <TableCell>{snap.record_count}</TableCell>
                          <TableCell>{getStatusBadge(snap.status)}</TableCell>
                          {isAdmin && (
                            <TableCell className="text-right space-x-2">
                              {snap.status === "pending" && (
                                <Button 
                                  variant="outline" 
                                  size="sm"
                                  onClick={() => actionMutation.mutate({ id: snap.id, action: "approve" })}
                                  disabled={actionMutation.isPending}
                                >
                                  Approve
                                </Button>
                              )}
                              {(snap.status === "pending" || snap.status === "approved") && (
                                <Button 
                                  variant="destructive" 
                                  size="sm"
                                  onClick={() => {
                                    if (window.confirm("Are you sure you want to revoke this snapshot? This action is irreversible and stops its use in new verifications.")) {
                                      actionMutation.mutate({ id: snap.id, action: "revoke" })
                                    }
                                  }}
                                  disabled={actionMutation.isPending}
                                >
                                  Revoke
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

        <div className="lg:col-span-1">
          <Card>
            <form onSubmit={handleIngest}>
              <CardHeader>
                <CardTitle>Ingest Vulnerabilities</CardTitle>
                <CardDescription>Provide a raw JSON array of CVE/PURL mappings. (Admin Only)</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                
                {!isAdmin && (
                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Read Only</AlertTitle>
                    <AlertDescription>
                      Your current role does not permit vulnerability ingestion.
                    </AlertDescription>
                  </Alert>
                )}

                {(ingestError || ingestMutation.error) && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Ingestion Failed</AlertTitle>
                    <AlertDescription>
                      {ingestError || (ingestMutation.error instanceof ApiError ? ingestMutation.error.message : "Network error")}
                    </AlertDescription>
                  </Alert>
                )}

                {ingestMutation.isSuccess && (
                  <Alert className="border-success/30 bg-success/10 text-success">
                    <CheckCircle2 className="h-4 w-4 !text-success" />
                    <AlertTitle>Ingestion Successful</AlertTitle>
                    <AlertDescription>
                      The snapshot was created and is pending approval.
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-2">
                  <Label htmlFor="payload">JSON Payload</Label>
                  <Textarea
                    id="payload"
                    className="font-mono text-xs h-40"
                    placeholder={`[\n  { "purl": "pkg:npm/express@4.17.1", "cvss_score": 8.5 }\n]`}
                    value={ingestPayload}
                    onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setIngestPayload(e.target.value)}
                    disabled={!isAdmin || ingestMutation.isPending}
                    required
                  />
                  <p className="text-xs text-muted-foreground">The array must strictly match the VulnerabilityIngestionItem schema.</p>
                </div>

              </CardContent>
              <CardFooter>
                <Button type="submit" className="w-full" disabled={!isAdmin || ingestMutation.isPending || !ingestPayload.trim()}>
                  {ingestMutation.isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Ingesting...
                    </>
                  ) : (
                    <>
                      <DatabaseBackup className="mr-2 h-4 w-4" />
                      Ingest Snapshot
                    </>
                  )}
                </Button>
              </CardFooter>
            </form>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function AdminVulnerabilitiesPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor"]}>
      <VulnerabilityManagement />
    </RouteGuard>
  );
}
