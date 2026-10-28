"use client";

import * as React from "react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { policyService } from "@/api/services/policyService";
import { RouteGuard } from "@/auth/RouteGuard";
import { useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/api/errors";
import { PolicyResponse } from "@/api/types";
import { cn } from "@/lib/utils";
import {
  AlertCircle,
  Check,
  Copy,
  Info,
  Loader2,
  Plus,
  RotateCw,
  Scale,
  ShieldAlert,
} from "lucide-react";

function PolicyManagement() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [maxCvss, setMaxCvss] = useState("9.0");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [activateTarget, setActivateTarget] = useState<PolicyResponse | null>(null);
  const [activationError, setActivationError] = useState<string | null>(null);
  const [activationSuccess, setActivationSuccess] = useState<string | null>(null);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // Fallback
    }
  };

  const { data: policies, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["policies"],
    queryFn: () => policyService.list(),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const score = parseFloat(maxCvss);
      if (isNaN(score)) throw new Error("Invalid CVSS score");
      if (score < 0 || score > 10) throw new Error("CVSS threshold must be between 0.0 and 10.0");
      return policyService.create({
        name,
        description,
        max_cvss_score: score,
      });
    },
    onSuccess: () => {
      setName("");
      setDescription("");
      setMaxCvss("9.0");
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const activateMutation = useMutation({
    mutationFn: async (policyId: string) => {
      setActivationError(null);
      return policyService.activate(policyId);
    },
    onSuccess: (data) => {
      setActivateTarget(null);
      setActivationSuccess(
        `Policy "${data.name || data.id.slice(0, 8)}" is now active. Subsequent proof evaluations will enforce this policy.`
      );
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err) => {
      const msg = err instanceof ApiError ? err.message : "Failed to activate policy.";
      setActivationError(msg);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdmin || createMutation.isPending) return;
    createMutation.mutate();
  };

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Security Policies"
        description="Authoritative CVSS evaluation thresholds and canonical SHA-256 policy digest bindings (H_Policy)."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            {policies ? `${policies.length} Defined` : "Policy Registry"}
          </Badge>
        }
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refetch()}
            disabled={isLoading || isFetching}
            className="gap-1.5"
          >
            <RotateCw className={cn("size-3.5", (isLoading || isFetching) && "animate-spin")} />
            <span>Refresh</span>
          </Button>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Column: Policy List Table */}
        <div className="lg:col-span-2 space-y-6">
          <Card className="shadow-xs">
            <CardHeader className="border-b border-border/60 pb-4">
              <CardTitle className="text-base font-semibold">Active & Historical Policies</CardTitle>
              <CardDescription className="text-xs">
                Deterministic rule sets evaluated during UltraPlonk proof compilation and verification.
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-4">
              {isLoading && (
                <div className="space-y-2">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-14 w-full" />
                  <Skeleton className="h-14 w-full" />
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Error loading policies</AlertTitle>
                  <AlertDescription className="flex flex-col gap-2 text-xs mt-1">
                    <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                    <Button variant="outline" size="sm" className="w-fit" onClick={() => void refetch()}>
                      Retry
                    </Button>
                  </AlertDescription>
                </Alert>
              )}

              {!isLoading && !error && policies && policies.length === 0 && (
                <EmptyState
                  icon={Scale}
                  title="No security policies defined"
                  description="Policies define maximum allowable CVSS thresholds against vulnerability databases."
                />
              )}

              {activationSuccess && (
                <Alert className="mb-4 bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300">
                  <Check className="size-4 text-emerald-600" />
                  <AlertTitle className="text-xs font-semibold">Policy Activated</AlertTitle>
                  <AlertDescription className="text-xs mt-0.5">
                    {activationSuccess}
                  </AlertDescription>
                </Alert>
              )}

              {!isLoading && !error && policies && policies.length > 0 && (
                <div className="rounded-lg border border-border/70 overflow-hidden">
                  <Table>
                    <TableHeader className="bg-muted/40">
                      <TableRow>
                        <TableHead className="font-semibold text-xs">Policy ID</TableHead>
                        <TableHead className="font-semibold text-xs">Name</TableHead>
                        <TableHead className="font-semibold text-xs">Max CVSS</TableHead>
                        <TableHead className="font-semibold text-xs">Status</TableHead>
                        <TableHead className="font-semibold text-xs">Policy Hash (H_Policy)</TableHead>
                        <TableHead className="font-semibold text-xs text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {policies.map((policy) => (
                        <TableRow key={policy.id} className="transition-colors hover:bg-muted/30">
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {policy.id.slice(0, 8)}...
                          </TableCell>
                          <TableCell className="font-medium text-xs text-foreground">
                            {policy.name || "—"}
                          </TableCell>
                          <TableCell className="font-mono text-xs font-semibold text-foreground">
                            &le; {policy.max_cvss_score.toFixed(1)}
                          </TableCell>
                          <TableCell>
                            <StatusPill status={policy.active ? "active" : "revoked"} />
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {policy.policy_hash ? (
                              <div className="flex items-center gap-1.5">
                                <span title={policy.policy_hash}>
                                  {policy.policy_hash.slice(0, 10)}...{policy.policy_hash.slice(-6)}
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="size-5 shrink-0 text-muted-foreground hover:text-foreground"
                                  onClick={() => copyToClipboard(policy.policy_hash!, policy.id)}
                                >
                                  {copiedKey === policy.id ? (
                                    <Check className="size-3 text-emerald-500" />
                                  ) : (
                                    <Copy className="size-3" />
                                  )}
                                </Button>
                              </div>
                            ) : (
                              "—"
                            )}
                          </TableCell>
                          <TableCell className="text-right">
                            {isAdmin && (
                              policy.active ? (
                                <span className="text-[11px] font-mono font-medium text-emerald-600 dark:text-emerald-400">
                                  Active
                                </span>
                              ) : (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => {
                                    setActivationError(null);
                                    setActivateTarget(policy);
                                  }}
                                  disabled={activateMutation.isPending}
                                  className="h-7 text-xs px-2 gap-1 text-emerald-600 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-500/10"
                                >
                                  <Check className="size-3" />
                                  <span>Activate</span>
                                </Button>
                              )
                            )}
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

        {/* Right Column: Create Policy Form (Admin Only) */}
        <div className="lg:col-span-1">
          <Card className="shadow-xs">
            <form onSubmit={handleSubmit}>
              <CardHeader className="border-b border-border/60 pb-3">
                <CardTitle className="text-sm font-semibold">Create Security Policy</CardTitle>
                <CardDescription className="text-xs">
                  Deploy a new authoritative CVSS threshold baseline. (Admin role required)
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 pt-4 text-xs">
                {!isAdmin && (
                  <Alert className="bg-muted/40 border-border/70">
                    <ShieldAlert className="size-4 text-amber-600 dark:text-amber-400" />
                    <AlertTitle className="text-xs font-semibold">Read-Only Mode</AlertTitle>
                    <AlertDescription className="text-[11px] mt-0.5 text-muted-foreground">
                      Your current role (<code>{user?.role}</code>) permits policy inspection. Policy creation requires the <code>admin</code> role.
                    </AlertDescription>
                  </Alert>
                )}

                {createMutation.error && (
                  <Alert variant="destructive">
                    <AlertCircle className="size-4" />
                    <AlertTitle className="text-xs">Creation Failed</AlertTitle>
                    <AlertDescription className="text-[11px] mt-0.5">
                      {createMutation.error instanceof ApiError
                        ? createMutation.error.message
                        : createMutation.error.message || "An unexpected error occurred."}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-1.5">
                  <Label htmlFor="policy-name" className="text-xs font-semibold">
                    Policy Name <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="policy-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    disabled={!isAdmin || createMutation.isPending}
                    placeholder="e.g. Strict Production Profile"
                    className="h-8 text-xs"
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="policy-desc" className="text-xs font-semibold">
                    Description
                  </Label>
                  <Input
                    id="policy-desc"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    disabled={!isAdmin || createMutation.isPending}
                    placeholder="Optional compliance scope details"
                    className="h-8 text-xs"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="policy-max-cvss" className="text-xs font-semibold">
                    Maximum Allowed CVSS Score (0.0 – 10.0) <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="policy-max-cvss"
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={maxCvss}
                    onChange={(e) => setMaxCvss(e.target.value)}
                    disabled={!isAdmin || createMutation.isPending}
                    className="h-8 text-xs"
                    required
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Dependencies exceeding this CVSS score will trigger non-membership failure in zero-knowledge proofs.
                  </p>
                </div>
              </CardContent>
              <CardFooter className="pt-2 border-t border-border/50 bg-muted/10">
                <Button
                  type="submit"
                  size="sm"
                  className="w-full gap-1.5"
                  disabled={!isAdmin || createMutation.isPending || !name.trim() || !maxCvss}
                >
                  {createMutation.isPending ? (
                    <>
                      <Loader2 className="size-3.5 animate-spin" />
                      <span>Deploying Policy...</span>
                    </>
                  ) : (
                    <>
                      <Plus className="size-3.5" />
                      <span>Deploy Policy</span>
                    </>
                  )}
                </Button>
              </CardFooter>
            </form>
          </Card>

          {/* Policy Invariant Card */}
          <div className="rounded-lg bg-blue-500/5 border border-blue-500/20 p-3 mt-4 text-[11px] text-muted-foreground leading-relaxed flex items-start gap-2.5">
            <Info className="size-4 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-foreground">Deterministic Digest:</strong> The backend computes the SHA-256 canonical hash of the policy parameters. This commitment is embedded directly into the UltraPlonk public inputs (H_Policy).
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Dialog for Policy Activation */}
      {activateTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in-50"
          role="dialog"
          aria-modal="true"
        >
          <Card className="w-full max-w-md shadow-xl border-border bg-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold">
                Activate Security Policy?
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                Activating &quot;{activateTarget.name || activateTarget.id.slice(0, 8)}&quot; (CVSS &le; {activateTarget.max_cvss_score.toFixed(1)}) establishes it as the single active policy. Any previously active policy will be retired. New proof generation requests will enforce this policy commitment.
              </CardDescription>
            </CardHeader>
            {activationError && (
              <CardContent className="pt-0 pb-2">
                <Alert variant="destructive" className="py-2 text-xs">
                  <AlertCircle className="size-3.5" />
                  <AlertDescription>{activationError}</AlertDescription>
                </Alert>
              </CardContent>
            )}
            <div className="flex items-center justify-end gap-2 p-4 border-t border-border/70 bg-muted/10">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setActivateTarget(null)}
                disabled={activateMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => activateMutation.mutate(activateTarget.id)}
                disabled={activateMutation.isPending}
                className="gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white"
              >
                {activateMutation.isPending ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" />
                    <span>Activating...</span>
                  </>
                ) : (
                  <>
                    <Check className="size-3.5" />
                    <span>Confirm Activation</span>
                  </>
                )}
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

export default function AdminPoliciesPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "buyer"]}>
      <PolicyManagement />
    </RouteGuard>
  );
}
