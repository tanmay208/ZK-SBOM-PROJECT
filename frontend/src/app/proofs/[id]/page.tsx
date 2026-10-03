"use client";

import { useQuery } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, CheckCircle2, XCircle, Clock, Loader2, ServerOff } from "lucide-react";
import { ApiError } from "@/api/errors";
import { Button, buttonVariants } from "@/components/ui/button";
import Link from "next/link";
import { ProofJobStatus } from "@/api/types";
import { use } from "react";

function getStatusIcon(status: ProofJobStatus) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-6 w-6 text-success" />;
    case "failed":
      return <XCircle className="h-6 w-6 text-destructive" />;
    case "execution_blocked":
      return <ServerOff className="h-6 w-6 text-destructive" />;
    case "assembling_witness":
    case "pending":
      return <Loader2 className="h-6 w-6 text-primary animate-spin" />;
    default:
      return <Clock className="h-6 w-6 text-muted-foreground" />;
  }
}

function ProofDetail({ id }: { id: string }) {
  const { data: job, isLoading, error, refetch } = useQuery({
    queryKey: ["proofs", id],
    queryFn: () => proofService.getJob(id),
    refetchInterval: (query) => {
      const state = query.state.data?.status;
      const isTerminal = state === "completed" || state === "failed" || state === "execution_blocked";
      // Poll every 3 seconds if not terminal and not in error
      return !isTerminal && !query.state.error ? 3000 : false;
    }
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-1/3" />
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
        <h1 className="text-3xl font-bold tracking-tight">Proof Job Details</h1>
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{isNotFound ? "Job Not Found" : isForbidden ? "Access Denied" : "Error Loading Job"}</AlertTitle>
          <AlertDescription>
            {isNotFound 
              ? "The requested proof job does not exist or you do not have permission to view it." 
              : isForbidden
                ? "You do not have permission to view this proof job."
                : apiError?.message || "An unexpected network error occurred."}
          </AlertDescription>
        </Alert>
        {isRetryable && (
          <Button variant="outline" onClick={() => void refetch()}>Retry loading job</Button>
        )}
        <Link href="/proofs" className={buttonVariants({ variant: "outline" })}>Return to Proofs</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Proof Job: <span className="font-mono text-xl text-muted-foreground">{job.id.slice(0, 8)}</span></h1>
          <p className="text-muted-foreground">Track cryptographic generation execution and status.</p>
        </div>
        <Link href="/proofs" className={buttonVariants({ variant: "outline" })}>Back to List</Link>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center gap-4">
          <div className="p-2 bg-muted rounded-full">
            {getStatusIcon(job.status)}
          </div>
          <div>
            <CardTitle className="capitalize">{job.status.replace("_", " ")}</CardTitle>
            <CardDescription>
              {job.status === "completed" ? "Proof generation completed successfully." : 
               job.status === "failed" ? "The backend failed to generate a proof." :
               job.status === "execution_blocked" ? "Proof execution is currently unavailable." :
               "The backend is currently processing this job."}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Job ID</p>
            <p className="font-mono text-sm">{job.id}</p>
          </div>
          
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">SBOM Reference</p>
            <p className="font-mono text-sm">{job.sbom_upload_id}</p>
          </div>
          
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Policy Hash</p>
            <p className="font-mono text-sm truncate" title={job.policy_hash || ""}>{job.policy_hash || "—"}</p>
          </div>

          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">SBOM Root Hash</p>
            <p className="font-mono text-sm truncate" title={job.sbom_root || ""}>{job.sbom_root || "—"}</p>
          </div>

          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Vulnerability DB Hash</p>
            <p className="font-mono text-sm truncate" title={job.vulnerability_db_root || ""}>{job.vulnerability_db_root || "—"}</p>
          </div>

          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Created At</p>
            <p className="text-sm">{new Date(job.created_at).toLocaleString()}</p>
          </div>

          {job.completed_at && (
            <div className="space-y-1">
              <p className="text-sm font-medium text-muted-foreground">Completed At</p>
              <p className="text-sm">{new Date(job.completed_at).toLocaleString()}</p>
            </div>
          )}
        </CardContent>
        
        {job.error_message && (
          <CardFooter className="bg-destructive/10 border-t border-destructive/20 p-6 flex flex-col items-start gap-4">
            <div className="space-y-2">
              <p className="text-sm font-bold text-destructive flex items-center gap-2">
                <AlertCircle className="h-4 w-4"/>
                Failure Reason
              </p>
              <p className="text-sm text-destructive/80 font-mono">
                {job.error_message}
              </p>
            </div>
            <Link href={`/proofs/generate?sbomId=${encodeURIComponent(job.sbom_upload_id)}`} className={buttonVariants({ variant: "destructive", size: "sm" })}>
              Retry Generation
            </Link>
          </CardFooter>
        )}
      </Card>
      
      {job.status === "completed" && (
        <Alert>
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Next Steps</AlertTitle>
          <AlertDescription className="space-y-4">
            <p>
              Proof generation is complete. This does <strong>not</strong> mean the proof has been verified or a certificate has been issued. Proceed to the Verification workflow to evaluate this proof.
            </p>
            <div>
              <Link href={`/verify?proofId=${encodeURIComponent(job.id)}`} className={buttonVariants({ variant: "outline", size: "sm" })}>
                Proceed to Verification
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
