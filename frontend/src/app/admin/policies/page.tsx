"use client";

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
import { AlertCircle, Plus, ShieldAlert, Loader2 } from "lucide-react";
import { ApiError } from "@/api/errors";
import { Badge } from "@/components/ui/badge";

function PolicyManagement() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [maxCvss, setMaxCvss] = useState("9.0");

  const { data: policies, isLoading, error, refetch } = useQuery({
    queryKey: ["policies"],
    queryFn: () => policyService.list(),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const score = parseFloat(maxCvss);
      if (isNaN(score)) throw new Error("Invalid CVSS score");
      return policyService.create({
        name,
        description,
        max_cvss_score: score
      });
    },
    onSuccess: () => {
      setName("");
      setDescription("");
      setMaxCvss("9.0");
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate();
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Policies</h1>
        <p className="text-muted-foreground">Manage organizational security thresholds for ZKP evaluations.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Policy Definitions</CardTitle>
              <CardDescription>Active and historical proof verification policies.</CardDescription>
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
                  <AlertTitle>Error loading policies</AlertTitle>
                  <AlertDescription className="flex flex-col gap-2">
                    <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                    <Button variant="outline" size="sm" className="w-fit" onClick={() => refetch()}>
                      Retry
                    </Button>
                  </AlertDescription>
                </Alert>
              )}

              {!isLoading && !error && policies && policies.length === 0 && (
                <div className="flex flex-col items-center justify-center rounded-md border border-dashed p-8 text-center bg-muted/50">
                  <h3 className="mt-4 text-sm font-semibold">No policies found</h3>
                  <p className="mb-4 mt-2 text-sm text-muted-foreground">
                    No security policies are currently available.
                  </p>
                </div>
              )}

              {!isLoading && !error && policies && policies.length > 0 && (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Policy ID</TableHead>
                        <TableHead>Name</TableHead>
                        <TableHead>Max CVSS</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Hash</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {policies.map((policy) => (
                        <TableRow key={policy.id}>
                          <TableCell className="font-mono text-xs">{policy.id.slice(0, 8)}...</TableCell>
                          <TableCell className="font-medium">{policy.name || "—"}</TableCell>
                          <TableCell>{policy.max_cvss_score}</TableCell>
                          <TableCell>
                            {policy.active ? (
                              <Badge className="bg-success hover:bg-success/90">Active</Badge>
                            ) : (
                              <Badge variant="secondary">Inactive</Badge>
                            )}
                          </TableCell>
                          <TableCell className="font-mono text-xs truncate max-w-[120px]" title={policy.policy_hash || ""}>
                            {policy.policy_hash || "—"}
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

        <div className="lg:col-span-1">
          <Card>
            <form onSubmit={handleSubmit}>
              <CardHeader>
                <CardTitle>Create Policy</CardTitle>
                <CardDescription>Deploy a new active security threshold. (Admin Only)</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                
                {!isAdmin && (
                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Read Only</AlertTitle>
                    <AlertDescription>
                      Your current role does not permit policy creation.
                    </AlertDescription>
                  </Alert>
                )}

                {createMutation.error && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Creation Failed</AlertTitle>
                    <AlertDescription>
                      {createMutation.error instanceof ApiError 
                        ? createMutation.error.message 
                        : createMutation.error.message || "An unexpected error occurred."}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-2">
                  <Label htmlFor="name">Policy Name</Label>
                  <Input
                    id="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    disabled={!isAdmin || createMutation.isPending}
                    placeholder="e.g. Strict Enterprise Profile"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Input
                    id="description"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    disabled={!isAdmin || createMutation.isPending}
                    placeholder="Optional details"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="maxCvss">Maximum Allowed CVSS Score</Label>
                  <Input
                    id="maxCvss"
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={maxCvss}
                    onChange={(e) => setMaxCvss(e.target.value)}
                    disabled={!isAdmin || createMutation.isPending}
                    required
                  />
                  <p className="text-xs text-muted-foreground">Components exceeding this score will fail verification.</p>
                </div>

              </CardContent>
              <CardFooter>
                <Button type="submit" className="w-full" disabled={!isAdmin || createMutation.isPending || !name || !maxCvss}>
                  {createMutation.isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    <>
                      <Plus className="mr-2 h-4 w-4" />
                      Create Policy
                    </>
                  )}
                </Button>
              </CardFooter>
            </form>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function AdminPoliciesPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor"]}>
      <PolicyManagement />
    </RouteGuard>
  );
}
