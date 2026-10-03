"use client";

import { useQuery } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, Plus, Eye, Loader2 } from "lucide-react";
import Link from "next/link";
import { ApiError } from "@/api/errors";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ProofJobStatus } from "@/api/types";

function getStatusBadge(status: ProofJobStatus) {
  switch (status) {
    case "completed":
      return <Badge className="bg-green-600 hover:bg-green-700">Completed</Badge>;
    case "failed":
    case "execution_blocked":
      return <Badge variant="destructive">{status.replace("_", " ")}</Badge>;
    case "assembling_witness":
    case "pending":
      return <Badge variant="secondary" className="flex gap-1 items-center"><Loader2 className="h-3 w-3 animate-spin"/> {status.replace("_", " ")}</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function ProofList() {
  const { data: proofs, isLoading, error, refetch } = useQuery({
    queryKey: ["proofs"],
    queryFn: () => proofService.list(),
    // Poll the list every 5 seconds if there are any active jobs
    refetchInterval: (query) => {
      if (query.state.error) return false;
      const hasActiveJobs = query.state.data?.some(p => p.status === "pending" || p.status === "assembling_witness");
      return hasActiveJobs ? 5000 : false;
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Proof Generation Jobs</h1>
          <p className="text-muted-foreground">Manage and track Zero-Knowledge Proof computations.</p>
        </div>
        <Link href="/proofs/generate" className={cn(buttonVariants(), "flex items-center gap-2")}>
          <Plus className="h-4 w-4" />
          Generate Proof
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Your Proof Jobs</CardTitle>
          <CardDescription>A list of all cryptographic proofs generated or currently running.</CardDescription>
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
              <AlertTitle>Error loading Proofs</AlertTitle>
              <AlertDescription className="flex flex-col gap-2">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {!isLoading && !error && proofs && proofs.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-md border border-dashed p-8 text-center animate-in fade-in-50">
              <div className="mx-auto flex max-w-[420px] flex-col items-center justify-center text-center">
                <h3 className="mt-4 text-lg font-semibold">No Proof Jobs found</h3>
                <p className="mb-4 mt-2 text-sm text-muted-foreground">
                  You haven&apos;t generated any proofs yet. Start by selecting an SBOM and generating a new proof.
                </p>
                <Link href="/proofs/generate" className={buttonVariants({ variant: "outline" })}>Generate Proof</Link>
              </div>
            </div>
          )}

          {!isLoading && !error && proofs && proofs.length > 0 && (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Job ID</TableHead>
                    <TableHead>SBOM Ref</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {proofs.map((proof) => (
                    <TableRow key={proof.id}>
                      <TableCell className="font-mono text-xs">{proof.id.slice(0, 8)}...</TableCell>
                      <TableCell className="font-mono text-xs">{proof.sbom_upload_id.slice(0, 8)}...</TableCell>
                      <TableCell className="capitalize">{getStatusBadge(proof.status)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(proof.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <Link href={`/proofs/${proof.id}`} className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "text-muted-foreground")}>
                          <Eye className="h-4 w-4 mr-2" />
                          View
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
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
