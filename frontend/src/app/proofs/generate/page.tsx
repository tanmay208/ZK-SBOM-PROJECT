"use client";

import * as React from "react";
import { useState, useMemo, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { sbomService } from "@/api/services/sbomService";
import { vulnerabilityService } from "@/api/services/vulnerabilityService";
import { policyService } from "@/api/services/policyService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  AlertCircle,
  AlertTriangle,
  Cpu,
  Loader2,
  Lock,
  RotateCw,
  ShieldCheck,
  Workflow
} from "lucide-react";

function GenerateProofForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();

  // Read requested sbomId from query param
  const requestedSbomId = searchParams.get("sbomId") || "";
  const [selectedSbomId, setSelectedSbomId] = useState<string | null>(null);
  const sbomUploadId = selectedSbomId !== null ? selectedSbomId : requestedSbomId;

  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);

  // Queries for authoritative dependencies
  const {
    data: sboms,
    isLoading: isLoadingSboms,
    isError: sbomsError,
    refetch: refetchSboms,
  } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => sbomService.list(),
  });

  const {
    data: snapshots,
    isLoading: isLoadingSnapshots,
    isError: snapshotsError,
    refetch: refetchSnapshots,
  } = useQuery({
    queryKey: ["vuln-snapshots"],
    queryFn: () => vulnerabilityService.listSnapshots(),
  });

  const {
    data: policies,
    isLoading: isLoadingPolicies,
    isError: policiesError,
    refetch: refetchPolicies,
  } = useQuery({
    queryKey: ["policies"],
    queryFn: () => policyService.list(),
  });

  // Evaluate requested SBOM existence & eligibility
  const requestedSbomExists = useMemo(() => {
    if (!requestedSbomId || !sboms) return true;
    return sboms.some((s) => s.upload_id === requestedSbomId);
  }, [requestedSbomId, sboms]);

  // Eligible frozen snapshots with authoritative SMT roots
  const eligibleSnapshots = useMemo(() => {
    return snapshots?.filter((s) => s.status === "frozen" && !!s.authoritative_smt_root) || [];
  }, [snapshots]);

  // Active security policies
  const activePolicies = useMemo(() => {
    return policies?.filter((p) => p.active) || [];
  }, [policies]);

  const snapshotId =
    selectedSnapshotId !== null
      ? selectedSnapshotId
      : eligibleSnapshots.length === 1
        ? eligibleSnapshots[0].id
        : "";

  const policyId =
    selectedPolicyId !== null
      ? selectedPolicyId
      : activePolicies.length === 1
        ? activePolicies[0].id
        : "";

  // Currently selected objects
  const selectedSbom = useMemo(() => {
    return sboms?.find((s) => s.upload_id === sbomUploadId);
  }, [sboms, sbomUploadId]);

  const selectedSnapshot = useMemo(() => {
    return snapshots?.find((s) => s.id === snapshotId);
  }, [snapshots, snapshotId]);

  const selectedPolicy = useMemo(() => {
    return policies?.find((p) => p.id === policyId);
  }, [policies, policyId]);

  // Eligibility verification checks
  const isSbomCommitted = selectedSbom?.status?.toLowerCase() === "committed" && !!selectedSbom?.sbom_root;
  const isSnapshotEligible = selectedSnapshot?.status === "frozen" && !!selectedSnapshot?.authoritative_smt_root;
  const isPolicyEligible = !!selectedPolicy && selectedPolicy.active;

  const canSubmit =
    !isLoadingSboms &&
    !isLoadingSnapshots &&
    !isLoadingPolicies &&
    !!sbomUploadId &&
    isSbomCommitted &&
    !!snapshotId &&
    isSnapshotEligible &&
    !!policyId &&
    isPolicyEligible;

  // Mutation for proof generation job submission
  const generateMutation = useMutation({
    mutationFn: async () => {
      if (!sbomUploadId || !snapshotId || !policyId) {
        throw new Error("Missing required generation parameters.");
      }
      return proofService.generate(sbomUploadId, snapshotId, policyId);
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["proofs"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
      router.push(`/proofs/${data.id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit || generateMutation.isPending) return;
    generateMutation.mutate();
  };

  const isLoadingDeps = isLoadingSboms || isLoadingSnapshots || isLoadingPolicies;
  const hasDependencyError = sbomsError || snapshotsError || policiesError;

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Generate Zero-Knowledge Proof"
        description="Cryptographically bind a committed software bill of materials (R_SBOM), an authoritative vulnerability snapshot (R_VulnDB), and a security policy (H_Policy) into an UltraPlonk proof."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            UltraPlonk Prover
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Link href="/proofs" className={buttonVariants({ variant: "outline", size: "sm" })}>
              Proof Jobs
            </Link>
            <Link href="/sboms" className={buttonVariants({ variant: "outline", size: "sm" })}>
              SBOM Workspace
            </Link>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Main Job Configuration Form (2 Cols) */}
        <Card className="lg:col-span-2 shadow-xs">
          <form onSubmit={handleSubmit}>
            <CardHeader>
              <CardTitle className="text-lg font-semibold">Job Parameters</CardTitle>
              <CardDescription className="text-xs">
                Select the three cryptographic references required to construct zero-knowledge supply chain constraints.
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              {/* Submission Error Banner */}
              {generateMutation.error && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Generation Request Failed</AlertTitle>
                  <AlertDescription className="text-xs mt-0.5">
                    {generateMutation.error instanceof ApiError
                      ? generateMutation.error.message
                      : "The server rejected the proof generation request. Please verify job lock status or quotas."}
                  </AlertDescription>
                </Alert>
              )}

              {/* Invalid / Inaccessible Query Param Notice */}
              {requestedSbomId && !isLoadingSboms && !requestedSbomExists && (
                <Alert variant="warning">
                  <AlertTriangle className="size-4" />
                  <AlertTitle>Requested SBOM Unavailable</AlertTitle>
                  <AlertDescription className="text-xs mt-0.5">
                    The requested SBOM identifier (<span className="font-mono">{requestedSbomId.slice(0, 8)}...</span>) was not found or is not owned by your account. Please select an authorized SBOM from the list below.
                  </AlertDescription>
                </Alert>
              )}

              {/* Upstream Dependency Error */}
              {hasDependencyError && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Unable to Load Reference Dependencies</AlertTitle>
                  <AlertDescription className="flex flex-col gap-2 mt-1 text-xs">
                    <span>Failed to retrieve authoritative SBOMs, vulnerability snapshots, or policies.</span>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="w-fit"
                      onClick={() => void Promise.all([refetchSboms(), refetchSnapshots(), refetchPolicies()])}
                    >
                      <RotateCw className="size-3.5 mr-1" />
                      Retry Loading References
                    </Button>
                  </AlertDescription>
                </Alert>
              )}

              {/* Dependency Loading Spinner */}
              {isLoadingDeps ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground gap-3">
                  <Loader2 className="size-7 animate-spin text-primary" />
                  <p className="text-xs font-medium">Loading authoritative references and Merkle roots...</p>
                </div>
              ) : (
                <>
                  {/* Parameter 1: Target SBOM Commitment */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="sbomSelect" className="text-xs font-semibold">
                        Target SBOM Commitment (R_SBOM) <span className="text-destructive">*</span>
                      </Label>
                      {selectedSbom && (
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          Status: <StatusPill status={selectedSbom.status} />
                        </span>
                      )}
                    </div>

                    <select
                      id="sbomSelect"
                      className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      value={sbomUploadId}
                      onChange={(e) => setSelectedSbomId(e.target.value)}
                      disabled={generateMutation.isPending}
                      required
                    >
                      <option value="">-- Select a Committed SBOM --</option>
                      {sboms?.map((sbom) => {
                        const isCommitted = sbom.status?.toLowerCase() === "committed" && !!sbom.sbom_root;
                        return (
                          <option
                            key={sbom.upload_id}
                            value={sbom.upload_id}
                            disabled={!isCommitted}
                          >
                            {sbom.filename || "payload.json"} ({sbom.application_id.slice(0, 8)}...) — {isCommitted ? `Committed (${sbom.component_count ?? 0} comps)` : `Ineligible: ${sbom.status}`}
                          </option>
                        );
                      })}
                    </select>

                    {/* SBOM Metadata Context / Eligibility Warning */}
                    {selectedSbom ? (
                      !isSbomCommitted ? (
                        <p className="text-[11px] text-destructive flex items-center gap-1 mt-1">
                          <AlertCircle className="size-3 shrink-0" />
                          This SBOM has status &quot;{selectedSbom.status}&quot; without a committed Sparse Merkle Tree root. Only committed SBOMs can generate proofs.
                        </p>
                      ) : (
                        <div className="rounded-md bg-muted/40 p-2 text-[11px] font-mono border border-border/50 text-muted-foreground break-all">
                          Commitment Root: <span className="text-foreground">{selectedSbom.sbom_root}</span>
                        </div>
                      )
                    ) : (
                      <p className="text-[11px] text-muted-foreground">
                        Select a committed SBOM with an authentic Poseidon Sparse Merkle Tree root (R_SBOM).
                      </p>
                    )}

                    {sboms && sboms.length === 0 && (
                      <div className="rounded-lg border border-dashed p-4 text-center">
                        <p className="text-xs text-muted-foreground mb-2">No SBOMs found in your account.</p>
                        <Link href="/sboms/upload" className={buttonVariants({ variant: "outline", size: "sm" })}>
                          Upload an SBOM First
                        </Link>
                      </div>
                    )}
                  </div>

                  {/* Parameter 2: Vulnerability Database Snapshot */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="snapshotSelect" className="text-xs font-semibold">
                        Authoritative Vulnerability Snapshot (R_VulnDB) <span className="text-destructive">*</span>
                      </Label>
                      {selectedSnapshot && (
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          Status: <StatusPill status={selectedSnapshot.status} />
                        </span>
                      )}
                    </div>

                    <select
                      id="snapshotSelect"
                      className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      value={snapshotId}
                      onChange={(e) => setSelectedSnapshotId(e.target.value)}
                      disabled={generateMutation.isPending}
                      required
                    >
                      <option value="">-- Select a Frozen Vulnerability Snapshot --</option>
                      {eligibleSnapshots.map((snap) => (
                        <option key={snap.id} value={snap.id}>
                          {snap.snapshot_label} — {snap.record_count} CVEs ({snap.id.slice(0, 8)}...)
                        </option>
                      ))}
                    </select>

                    {selectedSnapshot ? (
                      <div className="rounded-md bg-muted/40 p-2 text-[11px] font-mono border border-border/50 text-muted-foreground break-all">
                        Authoritative Root: <span className="text-foreground">{selectedSnapshot.authoritative_smt_root}</span>
                      </div>
                    ) : (
                      <p className="text-[11px] text-muted-foreground">
                        Requires a snapshot in &quot;frozen&quot; state with an authoritative Poseidon Merkle root.
                      </p>
                    )}

                    {snapshots && eligibleSnapshots.length === 0 && (
                      <p className="text-[11px] text-destructive flex items-center gap-1 mt-1">
                        <AlertCircle className="size-3 shrink-0" />
                        No frozen vulnerability snapshots available. A snapshot must be approved and frozen by an administrator before proofs can be generated.
                      </p>
                    )}
                  </div>

                  {/* Parameter 3: Security Policy */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="policySelect" className="text-xs font-semibold">
                        Compliance Security Policy (H_Policy) <span className="text-destructive">*</span>
                      </Label>
                      {selectedPolicy && (
                        <Badge variant="outline" className="text-[10px] font-mono">
                          Max CVSS: {selectedPolicy.max_cvss_score.toFixed(1)}
                        </Badge>
                      )}
                    </div>

                    <select
                      id="policySelect"
                      className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      value={policyId}
                      onChange={(e) => setSelectedPolicyId(e.target.value)}
                      disabled={generateMutation.isPending}
                      required
                    >
                      <option value="">-- Select an Active Policy --</option>
                      {activePolicies.map((pol) => (
                        <option key={pol.id} value={pol.id}>
                          {pol.name || "Default Security Policy"} (Threshold: Max CVSS {pol.max_cvss_score})
                        </option>
                      ))}
                    </select>

                    {selectedPolicy?.policy_hash ? (
                      <div className="rounded-md bg-muted/40 p-2 text-[11px] font-mono border border-border/50 text-muted-foreground break-all">
                        Policy Hash: <span className="text-foreground">{selectedPolicy.policy_hash}</span>
                      </div>
                    ) : (
                      <p className="text-[11px] text-muted-foreground">
                        Specifies the maximum allowable CVSS score for third-party dependencies in this application.
                      </p>
                    )}

                    {policies && activePolicies.length === 0 && (
                      <p className="text-[11px] text-destructive flex items-center gap-1 mt-1">
                        <AlertCircle className="size-3 shrink-0" />
                        No active security policies available. An administrator must create an active policy.
                      </p>
                    )}
                  </div>
                </>
              )}
            </CardContent>

            <CardFooter className="flex items-center justify-between border-t border-border/60 p-4 bg-muted/10">
              <Link
                href="/proofs"
                className={cn(
                  buttonVariants({ variant: "ghost", size: "sm" }),
                  generateMutation.isPending && "pointer-events-none opacity-50"
                )}
              >
                Cancel
              </Link>

              <Button
                type="submit"
                size="sm"
                disabled={!canSubmit || generateMutation.isPending}
                className="gap-2"
              >
                {generateMutation.isPending ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    <span>Initiating Prover Job...</span>
                  </>
                ) : (
                  <>
                    <Cpu className="size-4" />
                    <span>Generate Proof</span>
                  </>
                )}
              </Button>
            </CardFooter>
          </form>
        </Card>

        {/* Cryptographic & Architecture Sidebar (1 Col) */}
        <div className="space-y-4">
          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Workflow className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">Tri-Commitment Proof</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-muted-foreground text-[11px] leading-relaxed">
              <p>
                The UltraPlonk proving circuit binds three public commitments without disclosing private dependency trees:
              </p>
              <ul className="space-y-1.5 list-disc list-inside">
                <li>
                  <strong className="text-foreground">R_SBOM:</strong> Sparse Merkle Tree root of vendor application components.
                </li>
                <li>
                  <strong className="text-foreground">R_VulnDB:</strong> Authoritative frozen snapshot of known CVE intelligence.
                </li>
                <li>
                  <strong className="text-foreground">H_Policy:</strong> Poseidon hash of the compliance policy threshold.
                </li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-emerald-600 dark:text-emerald-400" />
                <CardTitle className="text-sm font-semibold">Generation vs. Verification</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-muted-foreground text-[11px] leading-relaxed">
              <p>
                Generating a proof initiates asynchronous backend prover workers.
              </p>
              <p>
                <strong>Generation is not verification:</strong> Once a proof job reaches &quot;completed&quot;, the proof artifact must be evaluated by the independent verification service to issue a verification certificate.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Lock className="size-4 text-purple-600 dark:text-purple-400" />
                <CardTitle className="text-sm font-semibold">Zero Witness Exposure</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-1.5 text-muted-foreground text-[11px] leading-relaxed">
              <p>
                Proving execution runs in a sandboxed native Barretenberg environment. Private witnesses, PURLs, and vulnerability mappings are never transmitted to the browser or stored in public certificates.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function GenerateProofPage() {
  return (
    <RouteGuard allowedRoles={["vendor"]}>
      <Suspense
        fallback={
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <Loader2 className="size-8 animate-spin text-primary" />
            <p className="text-xs text-muted-foreground">Loading proof generator workspace...</p>
          </div>
        }
      >
        <GenerateProofForm />
      </Suspense>
    </RouteGuard>
  );
}
