"use client";

import { useQuery } from "@tanstack/react-query";
import { certificateService } from "@/api/services/certificateService";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, FileBadge, ShieldCheck, XCircle } from "lucide-react";
import { ApiError } from "@/api/errors";
import { Button, buttonVariants } from "@/components/ui/button";
import Link from "next/link";
import { use } from "react";

function PublicCertificateDetail({ id }: { id: string }) {
  const { data: cert, isLoading, error, refetch } = useQuery({
    queryKey: ["certificates", "public-validate", id],
    queryFn: () => certificateService.validateCertificate(id),
    retry: false // Don't retry 404s
  });

  if (isLoading) {
    return (
      <div className="container max-w-4xl py-10 space-y-6">
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

  if (error || !cert || cert.reason === "certificate_not_found") {
    const apiError = error instanceof ApiError ? error : null;
    const isNotFound = apiError?.status === 404 || cert?.reason === "certificate_not_found";
    const isRetryable = !isNotFound && (!apiError || apiError.status === 0 || apiError.status >= 500);

    return (
      <div className="container max-w-4xl py-10 space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">Public Certificate Record</h1>
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{isNotFound ? "Certificate Not Found" : "Error Loading Certificate"}</AlertTitle>
          <AlertDescription>
            {isNotFound 
              ? "The requested certificate record does not exist or has been removed." 
              : apiError?.message || "An unexpected network error occurred while fetching the public certificate."}
          </AlertDescription>
        </Alert>
        {isRetryable && (
          <Button variant="outline" onClick={() => void refetch()}>Retry validation</Button>
        )}
        <Link href="/" className={buttonVariants({ variant: "outline" })}>Return to Home</Link>
      </div>
    );
  }

  const isRevoked = cert.is_revoked;
  const isCurrentlyValid = cert.valid && !isRevoked;
  const statusIsDestructive = isRevoked || !isCurrentlyValid;

  return (
    <div className="container max-w-4xl py-10 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Public Certificate Record</h1>
          <p className="text-muted-foreground">Authoritative Proof-of-Verification Validation.</p>
        </div>
      </div>

      <Card className={statusIsDestructive ? "border-destructive/30 shadow-sm" : "border-success/30 shadow-sm"}>
        <CardHeader className={statusIsDestructive ? "bg-destructive/10 border-b border-destructive/20 flex flex-row items-center gap-4" : "bg-success/10 border-b border-success/20 flex flex-row items-center gap-4"}>
          <div className={statusIsDestructive ? "p-3 bg-destructive/20 rounded-full" : "p-3 bg-success/20 rounded-full"}>
            {isCurrentlyValid ? (
              <FileBadge className="h-8 w-8 text-success" aria-hidden="true" />
            ) : isRevoked ? (
              <AlertCircle className="h-8 w-8 text-destructive" />
            ) : (
              <XCircle className="h-8 w-8 text-destructive" />
            )}
          </div>
          <div>
            <CardTitle className={statusIsDestructive ? "text-destructive" : "text-success"}>
              {isRevoked ? "Certificate Revoked" : isCurrentlyValid ? "Verified Application State" : "Certificate Invalid"}
            </CardTitle>
            <CardDescription className={statusIsDestructive ? "text-destructive/80" : "text-success/80"}>
              {isRevoked 
                ? "This certificate has been explicitly revoked by the authoritative backend and is no longer valid."
                : isCurrentlyValid
                  ? "This certificate is currently active and attests a successful zero-knowledge verification."
                  : "The authoritative backend reports that this certificate is not currently valid."}
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-6 p-6">
          <div className="col-span-1 md:col-span-2 space-y-4">
            <h3 className="text-lg font-semibold tracking-tight border-b pb-2">Certificate Status</h3>
            <div className="grid grid-cols-1 gap-4">
              <div className="space-y-1">
                <p className="text-sm font-medium text-muted-foreground">Certificate ID</p>
                <p className="font-mono text-sm break-all">{cert.certificate_id}</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                  <ShieldCheck className="h-4 w-4" />
                  Status Reason
                </p>
                <p className="text-sm font-mono">{cert.reason}</p>
              </div>
              
              {isRevoked && (
                <div className="space-y-1">
                  <p className="text-sm font-medium text-muted-foreground">Revoked At</p>
                  <p className="text-sm font-medium text-destructive">{cert.revoked_at ? new Date(cert.revoked_at).toLocaleString() : "Unknown"}</p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
        <CardFooter className="bg-muted/30 border-t p-6 text-sm text-muted-foreground">
          This authoritative validation record reflects the current state of the certificate. It is retrieved directly from the public validation endpoint.
        </CardFooter>
      </Card>
    </div>
  );
}

export default function PublicCertificatePage(props: { params: Promise<{ id: string }> }) {
  const params = use(props.params);
  
  // NOTE: This route does NOT use RouteGuard. It is deliberately accessible without authentication.
  return <PublicCertificateDetail id={params.id} />;
}
