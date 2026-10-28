"use client";

import * as React from "react";
import { Suspense, useState, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { verificationService } from "@/api/services/verificationService";
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
import { VerificationResponse } from "@/api/types";
import {
  AlertCircle,
  ArrowRight,
  Check,
  Copy,
  ExternalLink,
  FileBadge,
  Info,
  Loader2,
  Lock,
  RotateCw,
  SearchX,
  ServerOff,
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
          "The Barretenberg verifier successfully evaluated all 256 UltraPlonk proof segments against the public commitments.",
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
          "The verifier runtime environment is unavailable, required tooling is missing, or the submitted proof job is not owned by your active session.",
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

  // Read requested proofId from query parameter
  const requestedProofId = searchParams.get("proofId") || "";
  const [selectedProofId, setSelectedProofId] = useState<string | null>(null);
  const activeProofId = selectedProofId !== null ? selectedProofId : requestedProofId;

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

  // Query authorized proof jobs
  const {
    data: proofs,
    isLoading: isLoadingProofs,
    isError: proofsError,
    refetch: refetchProofs,
  } = useQuery({
    queryKey: ["proofs"],
    queryFn: () => proofService.list(),
  });

  // Filter completed proofs (only completed proofs can be verified)
  const completedProofs = useMemo(() => {
    return proofs?.filter((p) => p.status === "completed") || [];
  }, [proofs]);

  // Selected proof object
  const selectedProof = useMemo(() => {
    return completedProofs.find((p) => p.id === activeProofId);
  }, [completedProofs, activeProofId]);

  // Verify mutation
  const verifyMutation = useMutation({
    mutationFn: async (proofIdToVerify: string) => {
      const targetProof = completedProofs.find((p) => p.id === proofIdToVerify);
      if (!targetProof) {
        throw new Error("Selected proof job was not found or is not completed.");
      }

      // Explicitly extract ONLY the supported metadata and pass to backend
      return verificationService.verify({
        sbom_root: targetProof.sbom_root || "",
        vulnerability_db_root: targetProof.vulnerability_db_root || "",
        policy_hash: targetProof.policy_hash || "",
        proof_job_id: targetProof.id,
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
    if (!activeProofId || verifyMutation.isPending) return;
    setVerificationResult(null);
    verifyMutation.mutate(activeProofId);
  };

  const outcomeConfig = verificationResult ? getVerificationOutcomeConfig(verificationResult.result) : null;
  const OutcomeIcon = outcomeConfig?.icon || ShieldCheck;

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Independent Proof Verification"
        description="Verify UltraPlonk zero-knowledge proof artifacts against native Barretenberg verifier contracts and authoritative public commitments."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            UltraPlonk Verifier
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Link href="/proofs" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Proof Jobs
            </Link>
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
              <CardTitle className="text-lg font-semibold">Verification Target</CardTitle>
              <CardDescription className="text-xs">
                Select a completed proof job to evaluate against authoritative public commitments.
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

              {/* Upstream Query Error */}
              {proofsError && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Unable to Load Proof Jobs</AlertTitle>
                  <AlertDescription className="flex flex-col gap-2 mt-1 text-xs">
                    <span>Authorized proof jobs could not be retrieved from the server.</span>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="w-fit"
                      onClick={() => void refetchProofs()}
                    >
                      <RotateCw className="size-3.5 mr-1" />
                      Retry Loading Proofs
                    </Button>
                  </AlertDescription>
                </Alert>
              )}

              {/* Loading State */}
              {isLoadingProofs ? (
                <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-3">
                  <Loader2 className="size-6 animate-spin text-primary" />
                  <p className="text-xs font-medium">Loading completed proof jobs...</p>
                </div>
              ) : completedProofs.length === 0 ? (
                /* Empty Completed Proofs State */
                <EmptyState
                  icon={Zap}
                  title="No verifiable proof jobs"
                  description="Verification requires a completed UltraPlonk proof job. No completed jobs are currently available in your account."
                  action={
                    <div className="flex items-center gap-2">
                      <Link href="/proofs/generate" className={cn(buttonVariants({ size: "sm" }), "gap-1.5")}>
                        <span>Generate a Proof</span>
                        <ArrowRight className="size-3.5" />
                      </Link>
                    </div>
                  }
                />
              ) : (
                <div className="space-y-4">
                  {/* Proof Selection Dropdown */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="proofSelect" className="text-xs font-semibold">
                        Completed Proof Job <span className="text-destructive">*</span>
                      </Label>
                      {selectedProof && (
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          Status: <StatusPill status={selectedProof.status} />
                        </span>
                      )}
                    </div>

                    <select
                      id="proofSelect"
                      className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      value={activeProofId}
                      onChange={(e) => {
                        setSelectedProofId(e.target.value);
                        setVerificationResult(null);
                        verifyMutation.reset();
                      }}
                      disabled={verifyMutation.isPending}
                      required
                    >
                      <option value="">-- Select a Completed Proof Job --</option>
                      {completedProofs.map((proof) => (
                        <option key={proof.id} value={proof.id}>
                          Job: {proof.id.slice(0, 8)}... — SBOM: {proof.sbom_upload_id.slice(0, 8)}... (Completed)
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Public Commitments Card */}
                  {selectedProof ? (
                    <div className="rounded-lg bg-muted/40 p-4 border border-border/50 space-y-3 text-xs">
                      <div className="flex items-center justify-between border-b border-border/50 pb-2">
                        <span className="font-semibold text-foreground text-xs">Public Inputs for Verification</span>
                        <Badge variant="outline" className="font-mono text-[10px]">
                          ZK-002 Bound
                        </Badge>
                      </div>

                      {/* SBOM Root */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                          <span className="font-semibold uppercase tracking-wider text-[10px]">SBOM Root (R_SBOM)</span>
                          {selectedProof.sbom_root && (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-4 text-[10px] px-1 text-primary"
                              onClick={() => copyToClipboard(selectedProof.sbom_root!, "sbom-root")}
                            >
                              {copiedKey === "sbom-root" ? "Copied" : "Copy"}
                            </Button>
                          )}
                        </div>
                        <p className="font-mono text-[11px] text-foreground break-all bg-background/80 p-2 rounded border border-border/40">
                          {selectedProof.sbom_root || "—"}
                        </p>
                      </div>

                      {/* Vulnerability DB Root */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                          <span className="font-semibold uppercase tracking-wider text-[10px]">
                            Vulnerability DB Root (R_VulnDB)
                          </span>
                          {selectedProof.vulnerability_db_root && (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-4 text-[10px] px-1 text-primary"
                              onClick={() => copyToClipboard(selectedProof.vulnerability_db_root!, "vuln-root")}
                            >
                              {copiedKey === "vuln-root" ? "Copied" : "Copy"}
                            </Button>
                          )}
                        </div>
                        <p className="font-mono text-[11px] text-foreground break-all bg-background/80 p-2 rounded border border-border/40">
                          {selectedProof.vulnerability_db_root || "—"}
                        </p>
                      </div>

                      {/* Policy Hash */}
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                          <span className="font-semibold uppercase tracking-wider text-[10px]">
                            Policy Hash (H_Policy)
                          </span>
                          {selectedProof.policy_hash && (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-4 text-[10px] px-1 text-primary"
                              onClick={() => copyToClipboard(selectedProof.policy_hash!, "policy-hash")}
                            >
                              {copiedKey === "policy-hash" ? "Copied" : "Copy"}
                            </Button>
                          )}
                        </div>
                        <p className="font-mono text-[11px] text-foreground break-all bg-background/80 p-2 rounded border border-border/40">
                          {selectedProof.policy_hash || "—"}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
                      Select a completed proof above to inspect its tri-commitments prior to submission.
                    </div>
                  )}

                  {/* Architecture & Requirement Notice */}
                  <div className="rounded-lg bg-blue-500/5 border border-blue-500/20 p-3 text-[11px] text-muted-foreground leading-relaxed flex items-start gap-2.5">
                    <Info className="size-4 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-foreground">Authoritative Job Binding:</strong> In the current system architecture, proof verification requires an authorized proof job ID. The backend verifier cross-references the 256 segment proof artifacts directly against stored UltraPlonk verification keys.
                    </div>
                  </div>
                </div>
              )}
            </CardContent>

            <CardFooter className="flex items-center justify-between border-t border-border/60 p-4 bg-muted/10">
              <Link
                href="/proofs"
                className={cn(
                  buttonVariants({ variant: "ghost", size: "sm" }),
                  verifyMutation.isPending && "pointer-events-none opacity-50"
                )}
              >
                Back to Proofs
              </Link>

              <Button
                type="submit"
                size="sm"
                disabled={verifyMutation.isPending || proofsError || !selectedProof || !activeProofId}
                className="gap-2"
              >
                {verifyMutation.isPending ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    <span>Evaluating Proofs...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="size-4" />
                    <span>Verify Proof</span>
                  </>
                )}
              </Button>
            </CardFooter>
          </form>
        </Card>

        {/* Right Column: Verification Results & Explanations */}
        <div className="space-y-6">
          <Card className="shadow-xs">
            <CardHeader className="border-b border-border/60 pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg font-semibold">Verification Decision</CardTitle>
                  <CardDescription className="text-xs">
                    Authoritative cryptographic outcome issued by the verification service.
                  </CardDescription>
                </div>
                {verificationResult && <StatusPill status={outcomeConfig?.pillStatus || "pending"} />}
              </div>
            </CardHeader>

            <CardContent className="p-6 text-center">
              {/* Idle State: No submission yet */}
              {!verificationResult && !verifyMutation.isPending && (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-3">
                  <div className="flex size-12 items-center justify-center rounded-full bg-muted">
                    <ShieldCheck className="size-6 text-muted-foreground/60" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-foreground">Awaiting Verification Submission</p>
                    <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                      Select an authorized completed proof job on the left and submit it to run the Barretenberg verifier contract.
                    </p>
                  </div>
                </div>
              )}

              {/* Pending Execution State */}
              {verifyMutation.isPending && (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-3">
                  <Loader2 className="size-8 animate-spin text-primary" />
                  <div>
                    <p className="text-sm font-semibold text-foreground">Evaluating 256 Proof Segments</p>
                    <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                      Checking ACIR constraints, opening polynomials, and validating tri-commitments against authoritative database roots...
                    </p>
                  </div>
                </div>
              )}

              {/* Verification Outcome State */}
              {verificationResult && outcomeConfig && (
                <div className="space-y-5 text-left animate-in fade-in-50">
                  <div className="flex items-start gap-3 p-4 rounded-lg border bg-muted/20">
                    <div
                      className={cn(
                        "flex size-10 shrink-0 items-center justify-center rounded-lg mt-0.5",
                        verificationResult.result === "verified"
                          ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                          : outcomeConfig.variant === "warning"
                            ? "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                            : "bg-destructive/10 text-destructive"
                      )}
                    >
                      <OutcomeIcon className="size-5" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="text-base font-semibold text-foreground">{outcomeConfig.title}</h3>
                      <p className="text-xs text-muted-foreground leading-relaxed">{outcomeConfig.description}</p>
                    </div>
                  </div>

                  {/* Metadata Table */}
                  <div className="rounded-lg bg-muted/40 p-3 border border-border/50 space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Verification Record ID:</span>
                      <span className="font-mono text-[11px] text-foreground">{verificationResult.id}</span>
                    </div>

                    {verificationResult.verified_at && (
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Verified At:</span>
                        <span className="text-[11px] text-foreground">
                          {formatTableTimestamp(verificationResult.verified_at)}
                        </span>
                      </div>
                    )}

                    {verificationResult.policy_hash && (
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Bound Policy Hash:</span>
                        <span className="font-mono text-[11px] text-foreground">
                          {verificationResult.policy_hash.slice(0, 16)}...
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Certificate Minted Card (ONLY if verified and certificate is present) */}
                  {verificationResult.result === "verified" && verificationResult.certificate && (
                    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <FileBadge className="size-4 text-emerald-600 dark:text-emerald-400" />
                          <span className="text-xs font-semibold text-emerald-900 dark:text-emerald-200">
                            Verification Certificate Minted
                          </span>
                        </div>
                        <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-300 border-emerald-500/30">
                          Active
                        </Badge>
                      </div>

                      <p className="text-xs text-muted-foreground leading-relaxed">
                        A public, tamper-evident verification certificate has been issued for this application state.
                      </p>

                      <div className="flex items-center justify-between bg-background p-2 rounded border border-emerald-500/20 text-xs font-mono">
                        <span className="truncate mr-2 text-foreground">{verificationResult.certificate.id}</span>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-6 text-[10px] px-1.5 shrink-0"
                          onClick={() => copyToClipboard(verificationResult.certificate!.id, "cert-id")}
                        >
                          {copiedKey === "cert-id" ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
                        </Button>
                      </div>

                      <div className="pt-1">
                        <Link
                          href={`/certificates/${encodeURIComponent(verificationResult.certificate.id)}`}
                          className={cn(buttonVariants({ size: "sm" }), "gap-1.5 w-full sm:w-auto")}
                        >
                          <span>View Public Certificate</span>
                          <ExternalLink className="size-3.5" />
                        </Link>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Cryptographic Scope & Boundary Explanation Card */}
          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Lock className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">Cryptographic Claim Bounds</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-muted-foreground text-[11px] leading-relaxed">
              <p>
                <strong>What verification proves:</strong> A valid proof establishes that every component in the software bill of materials committed in <span className="font-mono text-foreground">R_SBOM</span> satisfies the threshold configured in <span className="font-mono text-foreground">H_Policy</span> against vulnerability intelligence snapshot <span className="font-mono text-foreground">R_VulnDB</span>.
              </p>
              <p>
                <strong>What verification does NOT prove:</strong> Verification does not prove that an application is free from all vulnerabilities, does not guarantee zero-day immunity, and does not evaluate components outside the committed SBOM.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "buyer"]}>
      <Suspense
        fallback={
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <Loader2 className="size-8 animate-spin text-primary" />
            <p className="text-xs text-muted-foreground">Loading verification workspace...</p>
          </div>
        }
      >
        <VerificationForm />
      </Suspense>
    </RouteGuard>
  );
}
