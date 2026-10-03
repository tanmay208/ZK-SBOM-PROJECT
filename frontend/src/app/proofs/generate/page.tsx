"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { proofService } from "@/api/services/proofService";
import { sbomService } from "@/api/services/sbomService";
import { vulnerabilityService } from "@/api/services/vulnerabilityService";
import { policyService } from "@/api/services/policyService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, FileUp, Loader2 } from "lucide-react";
import { ApiError } from "@/api/errors";
import Link from "next/link";
import { cn } from "@/lib/utils";

function GenerateProofForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  
  const [sbomUploadId, setSbomUploadId] = useState(searchParams.get("sbomId") || "");
  const [snapshotId, setSnapshotId] = useState("");
  const [policyId, setPolicyId] = useState("");

  const { data: sboms, isLoading: isLoadingSboms, isError: sbomsError, refetch: refetchSboms } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => sbomService.list(),
  });

  const { data: snapshots, isLoading: isLoadingSnapshots, isError: snapshotsError, refetch: refetchSnapshots } = useQuery({
    queryKey: ["vuln-snapshots"],
    queryFn: () => vulnerabilityService.listSnapshots(),
  });

  const { data: policies, isLoading: isLoadingPolicies, isError: policiesError, refetch: refetchPolicies } = useQuery({
    queryKey: ["policies"],
    queryFn: () => policyService.list(),
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      return proofService.generate(sbomUploadId, snapshotId, policyId);
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["proofs"] });
      router.push(`/proofs/${data.id}`);
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!sbomUploadId || !snapshotId || !policyId) return;
    generateMutation.mutate();
  };

  const isLoadingDeps = isLoadingSboms || isLoadingSnapshots || isLoadingPolicies;
  const hasDependencyError = sbomsError || snapshotsError || policiesError;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Generate Proof</h1>
        <p className="text-muted-foreground">Request a Zero-Knowledge Proof computation for an SBOM against a policy and vulnerability database.</p>
      </div>

      <Card className="max-w-2xl">
        <form onSubmit={handleSubmit}>
          <CardHeader>
            <CardTitle>Job Parameters</CardTitle>
            <CardDescription>Select the references required to build the proof constraints.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            
            {generateMutation.error && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Generation Failed</AlertTitle>
                <AlertDescription>
                  {generateMutation.error instanceof ApiError 
                    ? generateMutation.error.message 
                    : "An unexpected network error occurred."}
                </AlertDescription>
              </Alert>
            )}

            {isLoadingDeps ? (
              <div className="flex items-center justify-center p-8 text-muted-foreground">
                <Loader2 className="h-6 w-6 animate-spin mr-2" />
                Loading references...
              </div>
            ) : hasDependencyError ? (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Unable to load required references</AlertTitle>
                <AlertDescription className="flex flex-col items-start gap-3">
                  <span>SBOMs, approved vulnerability snapshots, or active policies could not be loaded. Retry before generating a proof.</span>
                  <Button type="button" variant="outline" onClick={() => void Promise.all([refetchSboms(), refetchSnapshots(), refetchPolicies()])}>
                    Retry loading references
                  </Button>
                </AlertDescription>
              </Alert>
            ) : (
              <>
                <div className="space-y-2">
                  <Label htmlFor="sbomSelect">Target SBOM</Label>
                  <select
                    id="sbomSelect"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                    value={sbomUploadId}
                    onChange={(e) => setSbomUploadId(e.target.value)}
                    disabled={generateMutation.isPending}
                    required
                  >
                    <option value="">-- Select an SBOM --</option>
                    {sboms?.map(sbom => (
                      <option key={sbom.upload_id} value={sbom.upload_id}>
                        {sbom.application_id} {sbom.filename ? `(${sbom.filename})` : ""} - {sbom.upload_id.slice(0,8)}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="snapshotSelect">Vulnerability Database Snapshot</Label>
                  <select
                    id="snapshotSelect"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                    value={snapshotId}
                    onChange={(e) => setSnapshotId(e.target.value)}
                    disabled={generateMutation.isPending}
                    required
                  >
                    <option value="">-- Select a Snapshot --</option>
                    {snapshots?.filter(s => s.status === 'approved').map(snap => (
                      <option key={snap.id} value={snap.id}>
                        {snap.snapshot_label} ({snap.status}) - {snap.id.slice(0,8)}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="policySelect">Security Policy</Label>
                  <select
                    id="policySelect"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                    value={policyId}
                    onChange={(e) => setPolicyId(e.target.value)}
                    disabled={generateMutation.isPending}
                    required
                  >
                    <option value="">-- Select a Policy --</option>
                    {policies?.filter(p => p.active).map(policy => (
                      <option key={policy.id} value={policy.id}>
                        {policy.name} (Max CVSS: {policy.max_cvss_score})
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}

            <div className="bg-muted p-4 rounded-md text-sm text-muted-foreground">
              <strong className="block text-foreground mb-1">Security Notice</strong>
              Proof generation happens entirely on the server. Your browser does not compute or have access to the cryptographic witness. You will be able to review the job status on the next screen.
            </div>

          </CardContent>
          <CardFooter className="flex justify-between border-t p-6">
            <Link href="/proofs" className={cn(buttonVariants({ variant: "ghost" }), generateMutation.isPending ? "pointer-events-none opacity-50" : "")}>
              Cancel
            </Link>
            <Button type="submit" disabled={generateMutation.isPending || isLoadingDeps || hasDependencyError || !sbomUploadId || !snapshotId || !policyId}>
              {generateMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Requesting...
                </>
              ) : (
                <>
                  <FileUp className="mr-2 h-4 w-4" />
                  Generate Proof
                </>
              )}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}

export default function GenerateProofPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}>
        <GenerateProofForm />
      </Suspense>
    </RouteGuard>
  );
}
