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
import { formatTableTimestamp } from "@/lib/dateTime";
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
      <div className="w-full min-h-[calc(100vh-4rem)] flex flex-col justify-start py-8 sm:py-12">
        <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8">
          <div className="space-y-2">
            <Skeleton className="h-8 sm:h-10 w-1/3" />
            <Skeleton className="h-4 w-2/3 max-w-xl" />
          </div>
          <Card className="shadow-xs border border-border/60">
            <CardHeader className="p-6 sm:p-8 border-b">
              <Skeleton className="h-7 w-1/4" />
            </CardHeader>
            <CardContent className="p-6 sm:p-8 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                <Skeleton className="h-24 w-full rounded-xl" />
                <Skeleton className="h-24 w-full rounded-xl" />
              </div>
              <Skeleton className="h-32 w-full rounded-xl" />
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (error || !cert || cert.reason === "certificate_not_found") {
    const apiError = error instanceof ApiError ? error : null;
    const isMalformed = apiError?.status === 422;
    const isNotFound = apiError?.status === 404 || cert?.reason === "certificate_not_found" || isMalformed;
    const isRetryable = !isNotFound && (!apiError || apiError.status === 0 || apiError.status >= 500);

    return (
      <div className="w-full min-h-[calc(100vh-4rem)] flex flex-col justify-start py-8 sm:py-12">
        <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8">
          <PageHeader
            title="Public Certificate Record"
            description="Authoritative proof-of-verification validation record."
            actions={
              <Link href="/" className={buttonVariants({ variant: "outline", size: "sm" })}>
                Return to Home
              </Link>
            }
          />
          <Alert variant="destructive" className="border-destructive/30 shadow-xs">
            <AlertCircle className="size-4" />
            <AlertTitle className="text-sm font-semibold">
              {isMalformed
                ? "Invalid Certificate Identifier"
                : isNotFound
                  ? "Certificate Not Found"
                  : "Error Validating Certificate"}
            </AlertTitle>
            <AlertDescription className="text-xs mt-1.5 leading-relaxed">
              {isMalformed
                ? "The provided certificate identifier is not a valid UUID format. Please verify the URL and try again."
                : isNotFound
                  ? "The requested certificate record does not exist in the authoritative database registry, or the identifier is invalid."
                  : apiError?.message || "An unexpected network error occurred while querying the public certificate."}
            </AlertDescription>
          </Alert>
          <div className="flex flex-wrap items-center gap-2.5">
            {isRetryable && (
              <Button variant="outline" size="sm" onClick={() => void refetch()} className="gap-1.5">
                <RotateCw className="size-3.5" />
                <span>Retry Validation</span>
              </Button>
            )}
            <Link href="/" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Return to Home
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const isRevoked = cert.is_revoked === true || cert.reason === "certificate_revoked";
  const isCurrentlyValid = cert.valid && !isRevoked;

  return (
    <div className="w-full min-h-[calc(100vh-4rem)] flex flex-col justify-start py-8 sm:py-12">
      <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8">
        {/* C1 Design System PageHeader - Centered and Aligned with Certificate Card */}
        <PageHeader
          title="Public Certificate Record"
          description="Real-time proof-of-verification attestation evaluated directly against the authoritative backend registry."
          badge={
            <Badge
              variant="outline"
              className={cn(
                "font-mono text-xs px-2.5 py-0.5 font-medium border shadow-2xs",
                isCurrentlyValid
                  ? "text-emerald-700 dark:text-emerald-300 border-emerald-500/30 bg-emerald-500/10"
                  : "text-destructive border-destructive/30 bg-destructive/10"
              )}
            >
              {isCurrentlyValid ? "Authoritative Pass" : "Authoritative Revoked"}
            </Badge>
          }
          actions={
            <div className="flex flex-wrap items-center gap-2.5">
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refetch()}
                disabled={isFetching}
                className="gap-1.5 shadow-2xs hover:bg-muted"
              >
                <RotateCw className={cn("size-3.5", isFetching && "animate-spin")} />
                <span>Re-check Validity</span>
              </Button>
              <Link
                href="/verify"
                className={cn(buttonVariants({ variant: "outline", size: "sm" }), "gap-1.5 shadow-2xs")}
              >
                <span>Verify Another</span>
              </Link>
            </div>
          }
        />

        {/* Main Attestation Status Card - Professional Visual Focal Point */}
        <Card
          className={cn(
            "rounded-xl border shadow-sm transition-all duration-200 overflow-hidden",
            isCurrentlyValid
              ? "border-emerald-500/30 bg-gradient-to-b from-card via-card to-emerald-500/[0.02]"
              : "border-destructive/30 bg-gradient-to-b from-card via-card to-destructive/[0.02]"
          )}
        >
          {/* Status Banner / Card Header */}
          <CardHeader
            className={cn(
              "p-6 sm:p-8 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-6",
              isCurrentlyValid
                ? "bg-gradient-to-r from-emerald-500/10 via-emerald-500/5 to-transparent border-emerald-500/20"
                : "bg-gradient-to-r from-destructive/10 via-destructive/5 to-transparent border-destructive/20"
            )}
          >
            <div className="flex items-start sm:items-center gap-4">
              <div
                className={cn(
                  "flex size-14 shrink-0 items-center justify-center rounded-xl border shadow-xs",
                  isCurrentlyValid
                    ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 shadow-emerald-500/10"
                    : "bg-destructive/20 text-destructive border-destructive/30"
                )}
              >
                {isCurrentlyValid ? (
                  <FileBadge className="size-7 text-emerald-600 dark:text-emerald-400" />
                ) : (
                  <AlertCircle className="size-7 text-destructive" />
                )}
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] sm:text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Cryptographic Supply-Chain Attestation
                  </span>
                </div>
                <CardTitle
                  className={cn(
                    "text-xl sm:text-2xl font-bold tracking-tight",
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
                    "text-xs sm:text-sm max-w-2xl leading-relaxed",
                    isCurrentlyValid ? "text-emerald-900/80 dark:text-emerald-300/80" : "text-destructive/80"
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

            <div className="shrink-0 self-start sm:self-center">
              <StatusPill status={isCurrentlyValid ? "valid" : "revoked"} />
            </div>
          </CardHeader>

          <CardContent className="p-6 sm:p-8 space-y-8 text-xs">
            {/* 1. Certificate Identification & Authoritative Validation Decision */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
              {/* Certificate ID */}
              <div className="rounded-xl bg-muted/40 p-5 border border-border/60 shadow-2xs space-y-2">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                  Certificate Identifier (UUID)
                </span>
                <div className="flex items-center justify-between gap-2">
                  <p className="font-mono text-xs sm:text-sm text-foreground font-semibold break-all select-all">
                    {cert.certificate_id}
                  </p>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-8 shrink-0 text-muted-foreground hover:text-foreground hover:bg-muted"
                    onClick={() => copyToClipboard(cert.certificate_id, "cert-id")}
                    title="Copy Certificate UUID"
                  >
                    {copiedKey === "cert-id" ? (
                      <Check className="size-4 text-emerald-500" />
                    ) : (
                      <Copy className="size-4" />
                    )}
                    <span className="sr-only">Copy Certificate ID</span>
                  </Button>
                </div>
              </div>

              {/* Authoritative Status Reason */}
              <div className="rounded-xl bg-muted/40 p-5 border border-border/60 shadow-2xs space-y-2">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                  Authoritative Validation Decision
                </span>
                <div className="flex items-center gap-2.5 pt-1">
                  <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                    <ShieldCheck className="size-4" />
                  </div>
                  <div className="flex flex-col">
                    <span className="font-mono text-xs sm:text-sm text-foreground font-semibold">
                      {cert.reason}
                    </span>
                    <span className="text-[11px] text-muted-foreground">
                      Direct cryptographic evaluation from backend verifier
                    </span>
                  </div>
                </div>
              </div>

              {/* Revocation Metadata (if revoked) */}
              {isRevoked && (
                <div className="col-span-1 md:col-span-2 rounded-xl bg-destructive/10 p-5 border border-destructive/20 text-destructive space-y-2">
                  <span className="font-semibold uppercase text-[11px] tracking-wider flex items-center gap-2">
                    <ShieldAlert className="size-4" />
                    Revocation Recorded in Authoritative Registry
                  </span>
                  <p className="text-xs sm:text-sm">
                    Revoked At:{" "}
                    <span className="font-mono font-medium">
                      {cert.revoked_at ? formatTableTimestamp(cert.revoked_at) : "Timestamp not recorded"}
                    </span>
                  </p>
                  <p className="text-xs text-destructive/80 leading-relaxed">
                    Any previously exported certificate JWT or signature token associated with this ID is rejected by authoritative verification checks.
                  </p>
                </div>
              )}
            </div>

            {/* 2. Cryptographic Proof Bounds & Invariants */}
            <div className="rounded-xl bg-card border border-border/70 p-6 shadow-2xs space-y-4">
              <div className="flex items-center gap-2 text-foreground font-semibold text-sm">
                <Lock className="size-4 text-primary" />
                <span>Zero-Knowledge Verification Scope</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-muted-foreground text-xs leading-relaxed">
                <div className="rounded-lg bg-muted/30 p-4 border border-border/40 space-y-1.5">
                  <p className="font-medium text-foreground text-xs flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-primary" />
                    UltraPlonk Polynomial Proof
                  </p>
                  <p>
                    This certificate attests that an UltraPlonk zero-knowledge proof satisfied all polynomial constraints under Barretenberg 0.46.1. The proof verifies that third-party dependencies committed in the vendor&apos;s Sparse Merkle Tree do not exceed the configured policy vulnerability threshold under the specified vulnerability intelligence snapshot.
                  </p>
                </div>

                <div className="rounded-lg bg-muted/30 p-4 border border-border/40 space-y-1.5">
                  <p className="font-medium text-foreground text-xs flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-emerald-500" />
                    Tamper-Evidence & Revocation
                  </p>
                  <p>
                    Certificates are tamper-evident and cryptographically anchored, but revocable. If newly disclosed CVEs impact the application, or if the underlying proof job is deprecated, the certificate is authoritatively revoked in real-time.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>

          {/* 3. Verification Authority & Public Access Footer */}
          <CardFooter className="bg-muted/30 border-t border-border/60 p-5 sm:p-6 flex flex-col sm:flex-row items-center justify-between text-xs text-muted-foreground gap-3">
            <div className="flex items-center gap-2 text-center sm:text-left">
              <span className="hidden sm:inline">Authoritative verification query:</span>
              <code className="font-mono text-[11px] bg-muted/80 px-2.5 py-1 rounded-md border border-border/60 text-foreground break-all">
                /api/v1/verification/certificates/{id.slice(0, 8)}.../validate
              </code>
            </div>
            <div className="flex items-center gap-1.5 text-primary font-medium text-xs">
              <ShieldCheck className="size-3.5" />
              <span>Public Access • No Bearer Token Required</span>
            </div>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

export default function PublicCertificatePage(props: { params: Promise<{ id: string }> }) {
  const params = use(props.params);

  // NOTE: This route deliberately omits RouteGuard so external buyers and verifiers can validate certificates without authentication.
  return <PublicCertificateDetail id={params.id} />;
}
