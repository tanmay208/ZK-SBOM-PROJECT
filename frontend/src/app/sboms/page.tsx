"use client";

import { useQuery } from "@tanstack/react-query";
import { sbomService } from "@/api/services/sbomService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, Plus } from "lucide-react";
import Link from "next/link";
import { ApiError } from "@/api/errors";
import { Badge } from "@/components/ui/badge";

function SbomList() {
  const { data: sboms, isLoading, error, refetch } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => sbomService.list(),
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SBOM Management</h1>
          <p className="text-muted-foreground">Manage and review uploaded Software Bill of Materials.</p>
        </div>
        <Link href="/sboms/upload" className={cn(buttonVariants(), "flex items-center gap-2")}>
          <Plus className="h-4 w-4" />
          Upload SBOM
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Your SBOMs</CardTitle>
          <CardDescription>A list of all SBOMs associated with your account.</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading && (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error loading SBOMs</AlertTitle>
              <AlertDescription className="flex flex-col gap-2">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {!isLoading && !error && sboms && sboms.length === 0 && (
            <div className="flex flex-col items-center justify-center rounded-md border border-dashed p-8 text-center animate-in fade-in-50">
              <div className="mx-auto flex max-w-[420px] flex-col items-center justify-center text-center">
                <h3 className="mt-4 text-lg font-semibold">No SBOMs found</h3>
                <p className="mb-4 mt-2 text-sm text-muted-foreground">
                  You haven&apos;t uploaded any SBOMs yet. Start by uploading a CycloneDX JSON file.
                </p>
                <Link href="/sboms/upload" className={buttonVariants({ variant: "outline" })}>Upload SBOM</Link>
              </div>
            </div>
          )}

          {!isLoading && !error && sboms && sboms.length > 0 && (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Upload ID</TableHead>
                    <TableHead>Application</TableHead>
                    <TableHead>Filename</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Root Hash</TableHead>
                    <TableHead className="text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sboms.map((sbom) => (
                    <TableRow key={sbom.upload_id}>
                      <TableCell className="font-mono text-xs">{sbom.upload_id.slice(0, 8)}...</TableCell>
                      <TableCell className="font-medium">{sbom.application_id}</TableCell>
                      <TableCell>{sbom.filename || "—"}</TableCell>
                      <TableCell>
                        <Badge variant={sbom.status === "processed" ? "default" : "secondary"}>
                          {sbom.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[150px] truncate" title={sbom.sbom_root || ""}>
                        {sbom.sbom_root || "—"}
                      </TableCell>
                      <TableCell className="text-right text-sm text-muted-foreground">
                        {new Date(sbom.created_at).toLocaleDateString()}
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

export default function SbomsPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <SbomList />
    </RouteGuard>
  );
}
