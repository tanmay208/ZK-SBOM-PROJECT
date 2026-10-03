"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { verificationService } from "@/api/services/verificationService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, ShieldCheck, XCircle, ShieldAlert, SearchX, ServerOff, Loader2, FileBadge } from "lucide-react";
import { ApiError } from "@/api/errors";
import Link from "next/link";
import { VerificationResult, VerificationResponse } from "@/api/types";

function getVerificationIcon(result: VerificationResult | null) {
  switch (result) {
    case "verified":
      return <ShieldCheck className="h-12 w-12 text-success" aria-label="Verified" />;
    case "invalid":
      return <XCircle className="h-12 w-12 text-destructive" aria-label="Invalid" />;
    case "authoritative_record_mismatch":
      return <ShieldAlert className="h-12 w-12 text-warning" aria-label="Authoritative Record Mismatch" />;
    case "public_input_mismatch":
      return <SearchX className="h-12 w-12 text-warning" aria-label="Public Input Mismatch" />;
    case "unavailable":
      return <ServerOff className="h-12 w-12 text-muted-foreground" aria-label="Unavailable" />;
    default:
      return <ShieldCheck className="h-12 w-12 text-muted-foreground" />;
  }
}

function getVerificationMessage(result: VerificationResult | null) {
  switch (result) {
    case "verified":
      return "Proof successfully verified against authoritative backend records.";
    case "invalid":
      return "The backend determined that the submitted proof is invalid.";
    case "authoritative_record_mismatch":
      return "The cryptographic artifact does not correspond to expected authoritative records.";
    case "public_input_mismatch":
      return "The proof's public inputs do not match the expected verification context.";
    case "unavailable":
      return "Verification could not be completed because the backend capability is currently unavailable.";
    default:
      return "Verification pending.";
  }
}

function VerificationForm() {
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const [selectedProofId, setSelectedProofId] = useState(searchParams.get("proofId") || "");
  const [verificationResult, setVerificationResult] = useState<VerificationResponse | null>(null);

  const { data: proofs, isLoading: isLoadingProofs, isError: proofsError, refetch: refetchProofs } = useQuery({
    queryKey: ["proofs"],
    queryFn: () => proofService.list(),
  });

  const verifyMutation = useMutation({
    mutationFn: async (proofId: string) => {
      const proof = proofs?.find(p => p.id === proofId);
      if (!proof) throw new Error("Proof not found");
      
      // Explicitly extract ONLY the supported metadata and pass to backend
      return verificationService.verify({
        sbom_root: proof.sbom_root || "",
        vulnerability_db_root: proof.vulnerability_db_root || "",
        policy_hash: proof.policy_hash || "",
        proof_job_id: proof.id
      });
    },
    onSuccess: (data) => {
      setVerificationResult(data);
      queryClient.invalidateQueries({ queryKey: ["verifications"] });
      queryClient.invalidateQueries({ queryKey: ["certificates"] });
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProofId) return;
    setVerificationResult(null);
    verifyMutation.mutate(selectedProofId);
  };

  const completedProofs = proofs?.filter(p => p.status === "completed") || [];
  const selectedProof = completedProofs.find(p => p.id === selectedProofId);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Verify Proof</h1>
        <p className="text-muted-foreground">Submit a completed proof job to the authoritative backend verification service.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <form onSubmit={handleSubmit}>
            <CardHeader>
              <CardTitle>Verification Target</CardTitle>
              <CardDescription>Select a successfully generated proof to verify.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              
              {verifyMutation.error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Verification Request Failed</AlertTitle>
                  <AlertDescription>
                    {verifyMutation.error instanceof ApiError 
                      ? verifyMutation.error.message 
                      : verifyMutation.error.message || "An unexpected network error occurred."}
                  </AlertDescription>
                </Alert>
              )}

              {isLoadingProofs ? (
                <div className="flex items-center justify-center p-8 text-muted-foreground">
                  <Loader2 className="h-6 w-6 animate-spin mr-2" />
                  Loading proofs...
                </div>
              ) : proofsError ? (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Unable to load proofs</AlertTitle>
                  <AlertDescription className="flex flex-col items-start gap-3">
                    <span>Proof jobs could not be loaded. Retry before submitting a verification.</span>
                    <Button type="button" variant="outline" onClick={() => void refetchProofs()}>
                      Retry loading proofs
                    </Button>
                  </AlertDescription>
                </Alert>
              ) : completedProofs.length === 0 ? (
                <div className="flex flex-col items-center justify-center rounded-md border border-dashed p-8 text-center bg-muted/50">
                  <h3 className="mt-4 text-sm font-semibold">No verifiable proofs</h3>
                  <p className="mb-4 mt-2 text-sm text-muted-foreground">
                    No completed proof jobs are currently available for verification.
                  </p>
                  <Link href="/proofs/generate" className={buttonVariants({ variant: "outline" })}>
                    Generate Proof
                  </Link>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="proofSelect">Completed Proof Job</Label>
                    <select
                      id="proofSelect"
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      value={selectedProofId}
                      onChange={(e) => {
                        setSelectedProofId(e.target.value);
                        setVerificationResult(null);
                        verifyMutation.reset();
                      }}
                      disabled={verifyMutation.isPending}
                      required
                    >
                      <option value="">-- Select a Proof --</option>
                      {completedProofs.map(proof => (
                        <option key={proof.id} value={proof.id}>
                          Job: {proof.id.slice(0,8)} - SBOM: {proof.sbom_upload_id.slice(0,8)}
                        </option>
                      ))}
                    </select>
                  </div>

                  {selectedProof && (
                    <div className="rounded-md bg-muted p-4 space-y-3 mt-4 text-sm">
                      <p className="font-semibold text-foreground mb-2">Public Inputs for Verification</p>
                      
                      <div className="grid grid-cols-[150px_1fr] gap-2 items-start">
                        <span className="text-muted-foreground">SBOM Root:</span>
                        <span className="font-mono text-xs break-all">{selectedProof.sbom_root || "—"}</span>
                      </div>
                      
                      <div className="grid grid-cols-[150px_1fr] gap-2 items-start">
                        <span className="text-muted-foreground">Vuln DB Root:</span>
                        <span className="font-mono text-xs break-all">{selectedProof.vulnerability_db_root || "—"}</span>
                      </div>
                      
                      <div className="grid grid-cols-[150px_1fr] gap-2 items-start">
                        <span className="text-muted-foreground">Policy Hash:</span>
                        <span className="font-mono text-xs break-all">{selectedProof.policy_hash || "—"}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
            <CardFooter className="flex justify-end border-t p-6">
              <Button type="submit" disabled={verifyMutation.isPending || proofsError || !selectedProofId}>
                {verifyMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="mr-2 h-4 w-4" />
                    Verify Proof
                  </>
                )}
              </Button>
            </CardFooter>
          </form>
        </Card>

        <div className="space-y-6">
          <Card className="h-full flex flex-col">
            <CardHeader>
              <CardTitle>Verification Result</CardTitle>
              <CardDescription>Authoritative decision from the backend verification service.</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 flex flex-col items-center justify-center p-6 text-center space-y-6">
              {!verificationResult && !verifyMutation.isPending && (
                <div className="text-muted-foreground animate-in fade-in flex flex-col items-center">
                  <ShieldCheck className="h-12 w-12 mb-4 opacity-20" />
                  <p>Select a proof and click Verify to submit it to the backend.</p>
                </div>
              )}
              
              {verifyMutation.isPending && (
                <div className="text-muted-foreground animate-in fade-in flex flex-col items-center">
                  <Loader2 className="h-12 w-12 mb-4 animate-spin text-primary" />
                  <p>Awaiting authoritative backend decision...</p>
                </div>
              )}

              {verificationResult && (
                <div className="animate-in zoom-in-95 duration-300 flex flex-col items-center w-full">
                  {getVerificationIcon(verificationResult.result)}
                  
                  <h3 className="mt-4 text-2xl font-bold tracking-tight capitalize">
                    {verificationResult.result?.replace(/_/g, " ")}
                  </h3>
                  
                  <p className="mt-2 text-muted-foreground">
                    {getVerificationMessage(verificationResult.result)}
                  </p>

                  <div className="w-full mt-8 text-left space-y-3 bg-muted p-4 rounded-lg">
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-muted-foreground">Verification ID:</span>
                      <span className="font-mono text-xs">{verificationResult.id}</span>
                    </div>
                    {verificationResult.policy_hash && (
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-muted-foreground">Policy Hash:</span>
                        <span className="font-mono text-xs break-all">{verificationResult.policy_hash}</span>
                      </div>
                    )}
                    {verificationResult.verified_at && (
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-muted-foreground">Verified At:</span>
                        <span>{new Date(verificationResult.verified_at).toLocaleString()}</span>
                      </div>
                    )}
                  </div>

                  {verificationResult.result === "verified" && verificationResult.certificate && (
                    <div className="w-full mt-4 p-4 rounded-lg border border-success/30 bg-success/10 text-left">
                      <div className="flex items-center gap-2 mb-2">
                        <FileBadge className="h-5 w-5 text-success" aria-hidden="true" />
                        <span className="font-semibold text-success">Certificate Issued</span>
                      </div>
                      <p className="text-sm text-success/90 mb-3">
                        A certificate was automatically minted for this successful verification.
                      </p>
                      <Link href={`/certificates/${encodeURIComponent(verificationResult.certificate.id)}`} className="text-xs font-mono bg-background p-2 rounded truncate block hover:underline text-success">
                        {verificationResult.certificate.id}
                      </Link>
                      <div className="mt-4">
                        <Link href={`/certificates/${encodeURIComponent(verificationResult.certificate.id)}`} className={buttonVariants({ variant: "outline", size: "sm" })}>
                          View Public Certificate
                        </Link>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor"]}>
      <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}>
        <VerificationForm />
      </Suspense>
    </RouteGuard>
  );
}
