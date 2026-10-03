"use client";

import { useQuery } from "@tanstack/react-query";
import { certificateService } from "@/api/services/certificateService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, Eye } from "lucide-react";
import Link from "next/link";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";

function CertificateList() {
  const { data: certificates, isLoading, error, refetch } = useQuery({
    queryKey: ["certificates"],
    queryFn: () => certificateService.list(),
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certificates</h1>
          <p className="text-muted-foreground">Manage and view backend-issued verification certificates.</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Your Certificates</CardTitle>
          <CardDescription>Immutable records of successfully verified Zero-Knowledge Proofs.</CardDescription>
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
              <AlertTitle>Error loading Certificates</AlertTitle>
              <AlertDescription className="flex flex-col gap-2">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {!isLoading && !error && certificates && certificates.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-md border border-dashed p-8 text-center bg-muted/50">
              <div className="mx-auto flex max-w-[420px] flex-col items-center justify-center text-center">
                <h3 className="mt-4 text-lg font-semibold">No certificates found</h3>
                <p className="mb-4 mt-2 text-sm text-muted-foreground">
                  No certificates are currently available. Certificates are automatically issued when a proof is successfully verified.
                </p>
                <Link href="/verify" className={buttonVariants({ variant: "outline" })}>
                  Go to Verification
                </Link>
              </div>
            </div>
          )}

          {!isLoading && !error && certificates && certificates.length > 0 && (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Certificate ID</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Verification Ref</TableHead>
                    <TableHead>SBOM Root</TableHead>
                    <TableHead>Issued At</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {certificates.map((cert) => (
                    <TableRow key={cert.id}>
                      <TableCell className="font-mono text-xs">{cert.id.slice(0, 8)}...</TableCell>
                      <TableCell>
                        {cert.is_revoked ? (
                          <Badge variant="destructive">Revoked</Badge>
                        ) : (
                          <Badge className="bg-success hover:bg-success/90">Active</Badge>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{cert.verification_request_id.slice(0, 8)}...</TableCell>
                      <TableCell className="font-mono text-xs truncate max-w-[150px]" title={cert.sbom_root}>{cert.sbom_root}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(cert.issued_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <Link href={`/certificates/${encodeURIComponent(cert.id)}`} className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "text-muted-foreground")}>
                          <Eye className="h-4 w-4 mr-2" />
                          View Public Record
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

export default function CertificatesPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor"]}>
      <CertificateList />
    </RouteGuard>
  );
}
