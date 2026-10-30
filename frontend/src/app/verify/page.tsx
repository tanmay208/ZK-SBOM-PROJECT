"use client";

import * as React from "react";
import { Suspense, useState, useMemo, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { verificationService } from "@/api/services/verificationService";
import { useAuth } from "@/auth/AuthProvider";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { EmptyState } from "@/components/ui/empty-state";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import { formatTableTimestamp } from "@/lib/dateTime";
import Link from "next/link";
import { VerificationResponse, ProofShareResponse } from "@/api/types";
import {
  AlertCircle,
  ArrowRight,
  Check,
  Copy,
  ExternalLink,
  FileBadge,
  Info,
  KeyRound,
  Loader2,
  Lock,
  RotateCw,
  SearchX,
  ServerOff,
  Share2,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Zap,
} from "lucide-react";

export interface VerificationOutcomeConfig {
  pillStatus: string;
  variant: "default" | "destructive" | "warning" | "success" | "info";
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
}

export function getVerificationOutcomeConfig(result: string | null | undefined): VerificationOutcomeConfig {
  const normalized = (result || "").toLowerCase().replace(/[\s-]/g, "_");

  switch (normalized) {
    case "verified":
      return {
        pillStatus: "verified",
        variant: "success",
        title: "Cryptographic Proof Verified",
        description:
          "The Barretenberg verifier successfully evaluated all UltraPlonk proof segments against the authoritative public commitments.",
        icon: ShieldCheck,
      };
    case "invalid":
    case "invalid_proof":
    case "cryptographic_false":
      return {
        pillStatus: "invalid",
        variant: "destructive",
        title: "Cryptographic Proof Invalid",
        description:
          "The verifier rejected the proof artifact. One or more chunk polynomial constraints failed evaluation.",
        icon: XCircle,
      };
    case "structural_rejection":
      return {
        pillStatus: "invalid",
        variant: "destructive",
        title: "Proof Structural Rejection",
        description:
          "The proof artifact is malformed, truncated, or contains non-canonical field encodings.",
        icon: AlertCircle,
      };
    case "public_input_mismatch":
      return {
        pillStatus: "non_compliant",
        variant: "warning",
        title: "Public Input Mismatch",
        description:
          "The public input commitments in the proof do not match the expected Merkle roots or policy hash.",
        icon: SearchX,
      };
    case "record_mismatch":
    case "authoritative_record_mismatch":
      return {
        pillStatus: "warning",
        variant: "warning",
        title: "Authoritative Record Mismatch",
        description:
          "The requested cryptographic roots do not correspond to approved/frozen records in the authoritative registry.",
        icon: ShieldAlert,
      };
    case "runtime_failure":
      return {
        pillStatus: "execution_blocked",
        variant: "destructive",
        title: "Verifier Runtime Failure",
        description:
          "The proof verifier encountered a process timeout, memory exhaustion, or communication crash.",
        icon: ServerOff,
      };
    case "environment_failure":
    case "unavailable":
    case "verification_unavailable":
      return {
        pillStatus: "execution_blocked",
        variant: "destructive",
        title: "Verification Unavailable",
        description:
          "The verifier runtime environment is unavailable, or the submitted proof job is not authorized for verification.",
        icon: ServerOff,
      };
    default:
      return {
        pillStatus: "pending",
        variant: "info",
        title: "Verification Pending",
        description: "Awaiting evaluation by the authoritative verification service.",
        icon: Loader2,
      };
  }
}

function VerificationForm() {
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const { user } = useAuth();

  const isBuyer = user?.role === "buyer";
  const isVendor = user?.role === "vendor";
  const isAdmin = user?.role === "admin";

  // URL Query Parameters
  const requestedProofId = searchParams.get("proofId") || "";
  const requestedToken = searchParams.get("token") || "";

  // Component state
  const [selectedProofId, setSelectedProofId] = useState<string | null>(requestedProofId || null);
  const [selectedShareToken, setSelectedShareToken] = useState<string>(requestedToken);
  const [manualTokenInput, setManualTokenInput] = useState<string>(requestedToken);
  const [manualShare, setManualShare] = useState<ProofShareResponse | null>(null);
  const [manualTokenError, setManualTokenError] = useState<string | null>(null);
  const [isLookingUpToken, setIsLookingUpToken] = useState<boolean>(Boolean(requestedToken && isBuyer));

  const [verificationResult, setVerificationResult] = useState<VerificationResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // Clipboard fallback
    }
  };

  // Query authorized completed proof jobs (for vendor / admin)
  const {
    data: proofs,
    isLoading: isLoadingProofs,
    isError: proofsError,
    refetch: refetchProofs,
  } = useQuery({
    queryKey: ["proofs"],
    queryFn: () => proofService.list(),
    enabled: !isBuyer, // Buyers don't own proof jobs directly
  });

  const completedProofs = useMemo(() => {
    return proofs?.filter((p) => p.status === "completed") || [];
  }, [proofs]);

  // Query authorized verification shares (for buyer / admin)
  const {
    data: shares,
    isLoading: isLoadingShares,
    isError: sharesError,
    refetch: refetchShares,
  } = useQuery({
    queryKey: ["verification-shares"],
    queryFn: () => verificationService.listShares(),
    enabled: !isVendor, // Vendors manage shares from proof details; on verify page they verify their jobs directly
  });

  const activeShares = useMemo(() => {
    return shares?.filter((s) => s.is_active && !s.is_revoked) || [];
  }, [shares]);

  // Lookup token if requested via URL
  useEffect(() => {
    let ignore = false;
    if (requestedToken && !manualShare && isBuyer) {
      verificationService
        .getShare(requestedToken)
        .then((s) => {
          if (!ignore) {
            setManualShare(s);
            setSelectedShareToken(s.share_token);
          }
        })
        .catch((err) => {
          if (!ignore) {
            setManualTokenError(err instanceof ApiError ? err.message : "Invalid or expired share token.");
          }
        })
        .finally(() => {
          if (!ignore) {
            setIsLookingUpToken(false);
          }
        });
    }
    return () => {
      ignore = true;
    };
  }, [requestedToken, manualShare, isBuyer]);

  // Determine current active target proof or share
  const activeProof = useMemo(() => {
    if (selectedProofId) {
      return completedProofs.find((p) => p.id === selectedProofId) || null;
    }
    if (requestedProofId) {
      return completedProofs.find((p) => p.id === requestedProofId) || null;
    }
    return null;
  }, [completedProofs, selectedProofId, requestedProofId]);

  const activeShare = useMemo(() => {
    if (selectedShareToken) {
      if (manualShare && manualShare.share_token === selectedShareToken) {
        return manualShare;
      }
      return activeShares.find((s) => s.share_token === selectedShareToken) || manualShare;
    }
    return null;
  }, [activeShares, selectedShareToken, manualShare]);

  // Active public commitments to display and verify
  const activeCommitments = useMemo(() => {
    if (!isVendor && activeShare) {
      return {
        sbom_root: activeShare.sbom_root || "",
        vulnerability_db_root: activeShare.vulnerability_db_root || "",
        policy_hash: activeShare.policy_hash || "",
        proof_job_id: activeShare.proof_job_id,
        share_token: activeShare.share_token,
      };
    }
    if (activeProof) {
      return {
        sbom_root: activeProof.sbom_root || "",
        vulnerability_db_root: activeProof.vulnerability_db_root || "",
        policy_hash: activeProof.policy_hash || "",
        proof_job_id: activeProof.id,
        share_token: null,
      };
    }
    return null;
  }, [activeShare, activeProof, isVendor]);

  // Handle manual token lookup (Buyer / Admin)
  const handleLookupToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualTokenInput.trim()) return;
    setManualTokenError(null);
    setIsLookingUpToken(true);
    try {
      const share = await verificationService.getShare(manualTokenInput.trim());
      setManualShare(share);
      setSelectedShareToken(share.share_token);
      setSelectedProofId(null);
      setVerificationResult(null);
    } catch (err) {
      setManualTokenError(
        err instanceof ApiError ? err.message : "Verification reference token not found or expired."
      );
    } finally {
      setIsLookingUpToken(false);
    }
  };

  // Verify mutation
  const verifyMutation = useMutation({
    mutationFn: async () => {
      if (!activeCommitments) {
        throw new Error("No verifiable target selected.");
      }
      return verificationService.verify({
        sbom_root: activeCommitments.sbom_root,
        vulnerability_db_root: activeCommitments.vulnerability_db_root,
        policy_hash: activeCommitments.policy_hash,
        proof_job_id: activeCommitments.proof_job_id,
        share_token: activeCommitments.share_token,
      });
    },
    onSuccess: (data) => {
      setVerificationResult(data);
      queryClient.invalidateQueries({ queryKey: ["certificates"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isAdmin || !activeCommitments || verifyMutation.isPending) return;
    setVerificationResult(null);
    verifyMutation.mutate();
  };

  const outcomeConfig = verificationResult ? getVerificationOutcomeConfig(verificationResult.result) : null;
  const OutcomeIcon = outcomeConfig?.icon || ShieldCheck;

  // Header content depending on role
  const pageTitle = isVendor
    ? "Proof Verification"
    : isBuyer
    ? "Independent Proof Verification"
    : "Proof Verification & Oversight";

  const pageBadge = isVendor
    ? "Vendor Self-Verification"
    : isBuyer
    ? "UltraPlonk Verifier"
    : "UltraPlonk Verifier (Admin)";

  const pageDescription = isVendor
    ? "Verify your completed UltraPlonk proof artifacts against native Barretenberg verifier contracts and authoritative public commitments."
    : isBuyer
    ? "Verify UltraPlonk zero-knowledge proof artifacts against native Barretenberg verifier contracts and authoritative public commitments using an authorized verification reference."
    : "Evaluate proof artifacts and shares against native verifier contracts and authoritative public commitments.";

  return (
    <div className="space-y-6">
      <PageHeader
        title={pageTitle}
        description={pageDescription}
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            {pageBadge}
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            {!isBuyer && (
              <Link href="/proofs" className={buttonVariants({ variant: "outline", size: "sm" })}>
                Proof Jobs
              </Link>
            )}
            <Link href="/certificates" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Certificates
            </Link>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Left Column: Verification Target Selection */}
        <Card className="shadow-xs">
          <form onSubmit={handleSubmit}>
            <CardHeader className="border-b border-border/60 pb-4">
              <CardTitle className="text-lg font-semibold">
                {isVendor ? "Select Completed Proof Job" : "Verification Target"}
              </CardTitle>
              <CardDescription className="text-xs">
                {isVendor
                  ? "Select one of your completed proof jobs to execute cryptographic self-verification."
                  : isBuyer
                  ? "Select an authorized vendor share or enter a verification reference token to evaluate."
                  : "Select a completed proof job or authorized verification share to evaluate."}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-5 pt-5">
              {/* Mutation Error Alert */}
              {verifyMutation.error && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Verification Request Failed</AlertTitle>
                  <AlertDescription className="text-xs mt-0.5">
                    {verifyMutation.error instanceof ApiError
                      ? verifyMutation.error.message
                      : verifyMutation.error.message || "An unexpected error occurred while submitting for verification."}
                  </AlertDescription>
                </Alert>
              )}

              {/* Vendor & Admin View: Completed Proof Jobs Selector */}
              {!isBuyer && (
                <div className="space-y-2">
                  <Label htmlFor="proofSelect" className="text-xs font-semibold flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Zap className="size-3.5 text-primary" />
                      {isVendor ? "Your Completed Proof Jobs" : "Proof Job (Administrative Evaluation)"}
                    </span>
                    <Badge variant="outline" className="text-[10px]">
                      {completedProofs.length} Available
                    </Badge>
                  </Label>
                  {completedProofs.length > 0 ? (
                    <select
                      id="proofSelect"
                      className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      value={selectedProofId || ""}
                      onChange={(e) => {
                        setSelectedProofId(e.target.value || null);
                        setSelectedShareToken("");
                        setVerificationResult(null);
                        verifyMutation.reset();
                      }}
                      disabled={verifyMutation.isPending}
                    >
                      <option value="">-- Select Completed Proof Job --</option>
                      {completedProofs.map((p) => (
                        <option key={p.id} value={p.id}>
                          Job: {p.id.slice(0, 8)}... — SBOM: {p.sbom_upload_id.slice(0, 8)}... (Completed)
                        </option>
                      ))}
                    </select>
                  ) : (
                    <div className="rounded-md border border-border/60 bg-muted/20 p-4 text-xs text-muted-foreground space-y-2">
                      <p>No completed proof jobs found in your account.</p>
                      <Link href="/proofs/generate" className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}>
                        <span>Generate a Proof</span>
                        <ArrowRight className="size-3.5" />
                      </Link>
                    </div>
                  )}
                </div>
              )}

              {/* Buyer & Admin View: Manual Token Lookup Box */}
              {!isVendor && (
                <div className="rounded-lg border border-border/60 bg-muted/20 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <Label htmlFor="tokenInput" className="font-semibold flex items-center gap-1.5">
                      <KeyRound className="size-3.5 text-primary" />
                      Enter Verification Reference
                    </Label>
                    <span className="text-[11px] text-muted-foreground">e.g. vref_...</span>
                  </div>
                  <div className="flex gap-2">
                    <input
                      id="tokenInput"
                      type="text"
                      value={manualTokenInput}
                      onChange={(e) => setManualTokenInput(e.target.value)}
                      placeholder="vref_..."
                      className="flex h-9 flex-1 rounded-md border border-input bg-background px-3 py-1 text-xs font-mono shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      disabled={isLookingUpToken || verifyMutation.isPending}
                    />
                    <Button
                      type="button"
                      size="sm"
                      variant="secondary"
                      onClick={handleLookupToken}
                      disabled={isLookingUpToken || !manualTokenInput.trim() || verifyMutation.isPending}
                    >
                      {isLookingUpToken ? <Loader2 className="size-3.5 animate-spin" /> : "Load Reference"}
                    </Button>
                  </div>
                  {manualTokenError && (
                    <p className="text-[11px] text-destructive flex items-center gap-1">
                      <AlertCircle className="size-3" />
                      {manualTokenError}
                    </p>
                  )}
                  {activeShare && (
                    <p className="text-[11px] text-emerald-600 dark:text-emerald-400 flex items-center gap-1 font-mono">
                      <Check className="size-3" />
                      Loaded share: {activeShare.share_token.slice(0, 16)}...
                    </p>
                  )}
                </div>
              )}

              {/* Buyer & Admin View: Authorized Shares Selection */}
              {!isVendor && activeShares.length > 0 && (
                <div className="space-y-2">
                  <Label htmlFor="shareSelect" className="text-xs font-semibold flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Share2 className="size-3.5 text-primary" />
                      Authorized Vendor Shares
                    </span>
                    <Badge variant="outline" className="text-[10px]">
                      {activeShares.length} Available
                    </Badge>
                  </Label>
                  <select
                    id="shareSelect"
                    className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    value={selectedShareToken}
                    onChange={(e) => {
                      setSelectedShareToken(e.target.value);
                      setSelectedProofId(null);
                      setVerificationResult(null);
                      verifyMutation.reset();
                    }}
                    disabled={verifyMutation.isPending}
                  >
                    <option value="">-- Select an Authorized Share --</option>
                    {activeShares.map((s) => (
                      <option key={s.id} value={s.share_token}>
                        Ref: {s.share_token.slice(0, 14)}... — Job: {s.proof_job_id.slice(0, 8)}... (Role: {s.recipient_role})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Empty State for Buyer when no shares or references */}
              {isBuyer && !activeCommitments && activeShares.length === 0 && (
                <EmptyState
                  icon={ShieldCheck}
                  title="No Verification Shares Found"
                  description="You do not have any shared proof jobs yet. Enter a verification reference token provided by your vendor above to verify their compliance."
                />
              )}

              {/* Public Commitments Card */}
              {activeCommitments && (
                <div className="rounded-lg bg-muted/40 p-4 border border-border/50 space-y-3 text-xs">
                  <div className="flex items-center justify-between border-b border-border/50 pb-2">
                    <span className="font-semibold text-foreground text-xs">Public Inputs for Verification</span>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      ZK-002 Bound
                    </Badge>
                  </div>

                  <div className="space-y-2 font-mono text-[11px]">
                    <div>
                      <span className="text-muted-foreground block text-[10px] uppercase font-sans font-semibold">
                        SBOM Merkle Root (R_SBOM)
                      </span>
                      <p className="text-foreground truncate select-all" title={activeCommitments.sbom_root}>
                        {activeCommitments.sbom_root || "—"}
                      </p>
                    </div>

                    <div>
                      <span className="text-muted-foreground block text-[10px] uppercase font-sans font-semibold">
                        Vulnerability DB Root (R_VulnDB)
                      </span>
                      <p className="text-foreground truncate select-all" title={activeCommitments.vulnerability_db_root}>
                        {activeCommitments.vulnerability_db_root || "—"}
                      </p>
                    </div>

                    <div>
                      <span className="text-muted-foreground block text-[10px] uppercase font-sans font-semibold">
                        Policy Hash (H_Policy)
                      </span>
                      <p className="text-foreground truncate select-all" title={activeCommitments.policy_hash}>
                        {activeCommitments.policy_hash || "—"}
                      </p>
                    </div>

                    {activeCommitments.proof_job_id && (
                      <div className="pt-1 border-t border-border/40 text-[10px]">
                        <span className="text-muted-foreground font-sans font-medium">Job Reference: </span>
                        <span className="text-muted-foreground select-all">{activeCommitments.proof_job_id}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CardContent>

            <CardFooter className="border-t border-border/60 pt-4 flex items-center justify-between">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSelectedProofId(null);
                  setSelectedShareToken("");
                  setManualTokenInput("");
                  setManualShare(null);
                  setManualTokenError(null);
                  setVerificationResult(null);
                  verifyMutation.reset();
                }}
                disabled={!activeCommitments || verifyMutation.isPending}
              >
                Reset Target
              </Button>

              <Button
                type="submit"
                size="sm"
                disabled={isAdmin || !activeCommitments || verifyMutation.isPending}
                className="gap-2"
              >
                {verifyMutation.isPending ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    <span>Evaluating Proof...</span>
                  </>
                ) : isAdmin ? (
                  <>
                    <ShieldCheck className="size-4" />
                    <span>Verification Restricted (Admin Oversight)</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="size-4" />
                    <span>Verify Proof Artifact</span>
                  </>
                )}
              </Button>
            </CardFooter>
          </form>
        </Card>

        {/* Right Column: Verification Outcome & Protocol Walkthrough */}
        <div className="space-y-6">
          {verificationResult && outcomeConfig && (
            <Card className="shadow-xs border-primary/20">
              <CardHeader className="border-b border-border/60 pb-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <OutcomeIcon className="size-5 text-primary" />
                    <CardTitle className="text-base font-semibold">{outcomeConfig.title}</CardTitle>
                  </div>
                  <StatusPill status={outcomeConfig.pillStatus} />
                </div>
                <CardDescription className="text-xs pt-1">{outcomeConfig.description}</CardDescription>
              </CardHeader>

              <CardContent className="space-y-4 pt-4 text-xs">
                {/* Result Metadata */}
                <div className="rounded-lg bg-muted/40 p-3 border border-border/40 space-y-2 font-mono text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground font-sans text-[10px] uppercase font-semibold">
                      Verification Request ID
                    </span>
                    <span className="truncate select-all">{verificationResult.id}</span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground font-sans text-[10px] uppercase font-semibold">
                      Evaluated At
                    </span>
                    <span className="font-sans">
                      {formatTableTimestamp(verificationResult.verified_at || verificationResult.created_at)}
                    </span>
                  </div>
                </div>

                {/* Issued Certificate Section */}
                {verificationResult.certificate ? (
                  <Alert variant="success" className="border-emerald-500/30 bg-emerald-500/5">
                    <FileBadge className="size-4 text-emerald-600 dark:text-emerald-400" />
                    <AlertTitle className="text-xs font-semibold text-emerald-900 dark:text-emerald-200">
                      Tamper-Evident Certificate Issued
                    </AlertTitle>
                    <AlertDescription className="space-y-2 mt-1.5">
                      <p className="text-[11px] text-muted-foreground">
                        An authoritative verification certificate was successfully recorded and signed by the local authority.
                      </p>

                      <div className="flex items-center justify-between pt-1 border-t border-emerald-500/20 text-[11px]">
                        <span className="font-mono text-xs select-all truncate">
                          ID: {verificationResult.certificate.id}
                        </span>
                        <Link
                          href={`/certificates/${encodeURIComponent(verificationResult.certificate.id)}`}
                          className={cn(buttonVariants({ size: "xs", variant: "default" }), "gap-1 shrink-0 ml-2")}
                        >
                          <span>Open Certificate</span>
                          <ExternalLink className="size-3" />
                        </Link>
                      </div>

                      {verificationResult.certificate.sha256_fingerprint && (
                        <div className="text-[10px] font-mono text-muted-foreground pt-1 truncate">
                          SHA-256: {verificationResult.certificate.sha256_fingerprint}
                        </div>
                      )}
                    </AlertDescription>
                  </Alert>
                ) : (
                  <Alert variant="warning" className="text-xs">
                    <AlertCircle className="size-4" />
                    <AlertTitle className="text-xs font-semibold">No Certificate Issued</AlertTitle>
                    <AlertDescription className="text-[11px] mt-0.5">
                      {verificationResult.result === "verified"
                        ? "Verification succeeded, but certificate issuance was deferred or existing."
                        : "A verification certificate is minted strictly when the UltraPlonk proof satisfies all constraints and commitments."}
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}

          {/* Protocol Architecture Walkthrough Card */}
          {(!verificationResult || isVendor) && (
            <Card className="shadow-xs border-border/80">
              <CardHeader className="border-b border-border/60 pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Lock className="size-4 text-primary" />
                  {isVendor ? "Vendor Verification Lifecycle" : "Independent Verification Protocol"}
                </CardTitle>
                <CardDescription className="text-xs">
                  {isVendor
                    ? "Verify your completed zero-knowledge proofs before generating buyer references."
                    : "Zero-knowledge verification ensures cryptographic certainty without revealing private dependencies."}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3.5 pt-4 text-xs text-muted-foreground">
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <div className="size-5 rounded-full bg-primary/10 text-primary flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                      1
                    </div>
                    <p>
                      <strong>{isVendor ? "Completed Proof Selection" : "Reference Token Resolution"}:</strong>{" "}
                      {isVendor
                        ? "Select your completed UltraPlonk proof job. The Merkle root commitments are loaded directly from your verified job."
                        : "The buyer inputs a high-entropy reference token (vref_...) to load the vendor's public commitments without inspecting private data."}
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <div className="size-5 rounded-full bg-primary/10 text-primary flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                      2
                    </div>
                    <p>
                      <strong>Cryptographic Public Inputs:</strong> Commitments for the SBOM Merkle root (
                      <code>R_SBOM</code>), Vulnerability SMT root (<code>R_VulnDB</code>), and policy digest (
                      <code>H_Policy</code>) are cryptographically bound via ZK-002.
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <div className="size-5 rounded-full bg-primary/10 text-primary flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                      3
                    </div>
                    <p>
                      <strong>Native Verifier Evaluation:</strong> The native Barretenberg contract evaluates polynomial segment constraints. If compliant, an authoritative certificate is recorded.
                    </p>
                  </div>
                </div>

                <div className="rounded-md bg-muted/40 p-3 border border-border/40 mt-4 text-[11px]">
                  <p className="font-semibold text-foreground flex items-center gap-1.5 mb-1">
                    <ShieldCheck className="size-3.5 text-emerald-600 dark:text-emerald-400" />
                    Zero-Knowledge Privacy Guarantee
                  </p>
                  <p>
                    Verification operates strictly on public Merkle roots. Private dependency manifests, vendor source components, and internal build metadata remain strictly confidential.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "buyer"]}>
      <Suspense
        fallback={
          <div className="flex items-center justify-center py-20 text-muted-foreground gap-3">
            <Loader2 className="size-6 animate-spin text-primary" />
            <span className="text-xs">Loading verification console...</span>
          </div>
        }
      >
        <VerificationForm />
      </Suspense>
    </RouteGuard>
  );
}
