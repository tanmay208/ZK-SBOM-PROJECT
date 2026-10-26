"use client";

import * as React from "react";
import { useState, use } from "react";
import { useQuery } from "@tanstack/react-query";
import { certificateService } from "@/api/services/certificateService";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  AlertCircle,
  Check,
  Copy,
  FileBadge,
  Lock,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

function PublicCertificateDetail({ id }: { id: string }) {
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

  const {
    data: cert,
    isLoading,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["certificates", "public-validate", id],
    queryFn: () => certificateService.validateCertificate(id),
    retry: false, // Don't retry 404s
  });

  if (isLoading) {
    return (
      <div className="container max-w-4xl py-8 space-y-6">
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
      <div className="container max-w-4xl py-8 space-y-6">
        <PageHeader
          title="Public Certificate Record"
          description="Authoritative proof-of-verification validation record."
          actions={
            <Link href="/" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Return to Home
            </Link>
          }
        />
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>{isNotFound ? "Certificate Not Found" : "Error Validating Certificate"}</AlertTitle>
          <AlertDescription className="text-xs mt-1">
            {isNotFound
              ? "The requested certificate record does not exist in the authoritative database registry, or the identifier is invalid."
              : apiError?.message || "An unexpected network error occurred while querying the public certificate."}
          </AlertDescription>
        </Alert>
        <div className="flex items-center gap-2">
          {isRetryable && (
            <Button variant="outline" size="sm" onClick={() => void refetch()}>
              <RotateCw className="size-3.5 mr-1" />
              Retry Validation
            </Button>
          )}
          <Link href="/" className={buttonVariants({ variant: "outline", size: "sm" })}>
            Return to Home
          </Link>
        </div>
      </div>
    );
  }

  const isRevoked = cert.is_revoked === true || cert.reason === "certificate_revoked";
  const isCurrentlyValid = cert.valid && !isRevoked;

  return (
    <div className="container max-w-4xl py-8 space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Public Certificate Record"
        description="Real-time proof-of-verification attestation evaluated directly against the authoritative backend registry."
        badge={
          <Badge
            variant="outline"
            className={cn(
              "font-mono text-xs",
              isCurrentlyValid
                ? "text-emerald-700 dark:text-emerald-300 border-emerald-500/30"
                : "text-destructive border-destructive/30"
            )}
          >
            {isCurrentlyValid ? "Authoritative Pass" : "Authoritative Revoked"}
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void refetch()}
              disabled={isFetching}
              className="gap-1.5"
            >
              <RotateCw className={cn("size-3.5", isFetching && "animate-spin")} />
              <span>Re-check Validity</span>
            </Button>
            <Link href="/verify" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Verify Another
            </Link>
          </div>
        }
      />

      {/* Main Attestation Status Card */}
      <Card
        className={cn(
          "shadow-xs border",
          isCurrentlyValid
            ? "border-emerald-500/30 bg-emerald-500/[0.02]"
            : "border-destructive/30 bg-destructive/[0.02]"
        )}
      >
        <CardHeader
          className={cn(
            "border-b pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4",
            isCurrentlyValid
              ? "bg-emerald-500/10 border-emerald-500/20"
              : "bg-destructive/10 border-destructive/20"
          )}
        >
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "flex size-11 items-center justify-center rounded-lg",
                isCurrentlyValid
                  ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400"
                  : "bg-destructive/20 text-destructive"
              )}
            >
              {isCurrentlyValid ? (
                <FileBadge className="size-6 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <AlertCircle className="size-6 text-destructive" />
              )}
            </div>
            <div>
              <CardTitle
                className={cn(
                  "text-lg font-semibold",
                  isCurrentlyValid ? "text-emerald-950 dark:text-emerald-200" : "text-destructive"
                )}
              >
                {isRevoked
                  ? "Certificate Authoritatively Revoked"
                  : isCurrentlyValid
                    ? "Verified Application State — Active"
                    : "Certificate Not Accepted as Valid"}
              </CardTitle>
              <CardDescription
                className={cn(
                  "text-xs mt-0.5",
                  isCurrentlyValid ? "text-emerald-800/80 dark:text-emerald-300/80" : "text-destructive/80"
                )}
              >
                {isRevoked
                  ? "This certificate has been explicitly revoked in the authoritative database registry and is no longer valid for compliance."
                  : isCurrentlyValid
                    ? "This certificate is currently active and attests that a zero-knowledge supply chain proof was cryptographically verified."
                    : "The authoritative backend reports that this certificate does not satisfy current validity criteria."}
              </CardDescription>
            </div>
          </div>

          <StatusPill status={isCurrentlyValid ? "valid" : "revoked"} />
        </CardHeader>

        <CardContent className="space-y-6 pt-6 text-xs">
          {/* Certificate Identification & Reason */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Certificate ID */}
            <div className="rounded-lg bg-muted/40 p-3.5 border border-border/50">
              <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                Certificate Identifier (UUID)
              </span>
              <div className="flex items-center justify-between mt-1">
                <p className="font-mono text-xs text-foreground break-all">{cert.certificate_id}</p>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-6 shrink-0 ml-1 text-muted-foreground hover:text-foreground"
                  onClick={() => copyToClipboard(cert.certificate_id, "cert-id")}
                >
                  {copiedKey === "cert-id" ? (
                    <Check className="size-3 text-emerald-500" />
                  ) : (
                    <Copy className="size-3" />
                  )}
                </Button>
              </div>
            </div>

            {/* Authoritative Status Reason */}
            <div className="rounded-lg bg-muted/40 p-3.5 border border-border/50">
              <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                Authoritative Validation Decision
              </span>
              <div className="flex items-center gap-2 mt-1.5">
                <ShieldCheck className="size-4 text-primary" />
                <span className="font-mono text-xs text-foreground font-medium">{cert.reason}</span>
              </div>
            </div>

            {/* Revocation Metadata (if revoked) */}
            {isRevoked && (
              <div className="col-span-1 md:col-span-2 rounded-lg bg-destructive/10 p-3.5 border border-destructive/20 text-destructive space-y-1">
                <span className="font-semibold uppercase text-[10px] tracking-wider flex items-center gap-1.5">
                  <ShieldAlert className="size-3.5" />
                  Revocation Recorded
                </span>
                <p className="text-xs">
                  Revoked At:{" "}
                  <span className="font-medium">
                    {cert.revoked_at ? new Date(cert.revoked_at).toLocaleString() : "Timestamp not recorded"}
                  </span>
                </p>
                <p className="text-[11px] text-destructive/80">
                  Any previously exported certificate JWT or signature token associated with this ID is rejected by authoritative verification checks.
                </p>
              </div>
            )}
          </div>

          {/* Cryptographic Proof Bounds & Invariants */}
          <div className="rounded-lg bg-card border border-border/60 p-4 space-y-2.5 text-muted-foreground text-[11px] leading-relaxed">
            <div className="flex items-center gap-2 text-foreground font-semibold text-xs">
              <Lock className="size-3.5 text-primary" />
              <span>Zero-Knowledge Verification Scope</span>
            </div>
            <p>
              This certificate attests that an UltraPlonk zero-knowledge proof satisfied all polynomial constraints under Barretenberg 0.46.1. The proof verifies that third-party dependencies committed in the vendor&apos;s Sparse Merkle Tree do not exceed the configured policy vulnerability threshold under the specified vulnerability intelligence snapshot.
            </p>
            <p>
              <strong>Tamper-Evidence & Revocation:</strong> Certificates are tamper-evident and cryptographically anchored, but revocable. If newly disclosed CVEs impact the application, or if the underlying proof job is deprecated, the certificate is authoritatively revoked in real-time.
            </p>
          </div>
        </CardContent>

        <CardFooter className="bg-muted/20 border-t border-border/50 p-4 flex flex-col sm:flex-row items-center justify-between text-[11px] text-muted-foreground gap-2">
          <span>Authoritative verification service query via /api/v1/verification/certificates/{id.slice(0, 8)}.../validate</span>
          <span className="text-primary font-medium">Public Access • No Bearer Token Required</span>
        </CardFooter>
      </Card>
    </div>
  );
}

export default function PublicCertificatePage(props: { params: Promise<{ id: string }> }) {
  const params = use(props.params);

  // NOTE: This route deliberately omits RouteGuard so external buyers and auditors can validate certificates without authentication.
  return <PublicCertificateDetail id={params.id} />;
}
