"use client";

import * as React from "react";
import { useState, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { applicationService } from "@/api/services/applicationService";
import { ApplicationResponse } from "@/api/types";
import { RouteGuard } from "@/auth/RouteGuard";
import { useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { formatTableTimestamp } from "@/lib/dateTime";
import { ApiError } from "@/api/errors";
import Link from "next/link";
import {
  AlertCircle,
  Plus,
  RotateCw,
  Search,
  AppWindow,
  CheckCircle2,
  Archive,
  RefreshCw,
  FileUp,
  X,
  Loader2,
  Building2,
} from "lucide-react";

// Control character validation matching backend Pydantic rule
function hasControlCharacters(val: string): boolean {
  for (let i = 0; i < val.length; i++) {
    const code = val.charCodeAt(i);
    if (code < 32 && code !== 9) {
      return true;
    }
  }
  return false;
}

function ApplicationManagement() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "archived">("all");
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [actionTargetApp, setActionTargetApp] = useState<{
    app: ApplicationResponse;
    action: "archive" | "reactivate";
  } | null>(null);

  // Form states for application creation
  const [name, setName] = useState("");
  const [vendor, setVendor] = useState(user?.username || "");
  const [description, setDescription] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const {
    data: applications,
    isLoading,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["applications"],
    queryFn: () => applicationService.list({ include_archived: true }),
  });

  const createMutation = useMutation({
    mutationFn: async (payload: { name: string; vendor: string; description?: string }) => {
      return applicationService.create(payload);
    },
    onSuccess: () => {
      setIsCreateModalOpen(false);
      setName("");
      setDescription("");
      setFormError(null);
      queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
  });

  const archiveMutation = useMutation({
    mutationFn: async (appId: string) => {
      return applicationService.archive(appId);
    },
    onSuccess: () => {
      setActionTargetApp(null);
      queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
  });

  const reactivateMutation = useMutation({
    mutationFn: async (appId: string) => {
      return applicationService.reactivate(appId);
    },
    onSuccess: () => {
      setActionTargetApp(null);
      queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
  });

  // Metrics derived from verified API payload
  const metrics = useMemo(() => {
    if (!applications) return { total: 0, active: 0, archived: 0 };
    const total = applications.length;
    const active = applications.filter((a) => a.is_active).length;
    const archived = applications.filter((a) => !a.is_active).length;
    return { total, active, archived };
  }, [applications]);

  // Client-side filtering
  const filteredApps = useMemo(() => {
    if (!applications) return [];
    return applications.filter((app) => {
      const matchesSearch =
        searchTerm.trim() === "" ||
        app.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        app.vendor.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (app.description && app.description.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "active" && app.is_active) ||
        (statusFilter === "archived" && !app.is_active);

      return matchesSearch && matchesStatus;
    });
  }, [applications, searchTerm, statusFilter]);

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    const trimmedName = name.trim();
    if (!trimmedName) {
      setFormError("Application name is required (1 to 255 characters).");
      return;
    }
    if (trimmedName.length > 255) {
      setFormError("Application name must not exceed 255 characters.");
      return;
    }
    if (hasControlCharacters(trimmedName)) {
      setFormError("Application name contains disallowed control characters.");
      return;
    }

    const trimmedVendor = vendor.trim();
    if (!trimmedVendor) {
      setFormError("Vendor name is required.");
      return;
    }
    if (trimmedVendor.length > 255) {
      setFormError("Vendor name must not exceed 255 characters.");
      return;
    }
    if (hasControlCharacters(trimmedVendor)) {
      setFormError("Vendor name contains disallowed control characters.");
      return;
    }

    if (description && description.length > 2000) {
      setFormError("Description must not exceed 2000 characters.");
      return;
    }

    createMutation.mutate({
      name: trimmedName,
      vendor: trimmedVendor,
      description: description.trim() || undefined,
    });
  };

  const handleActionConfirm = () => {
    if (!actionTargetApp) return;
    if (actionTargetApp.action === "archive") {
      archiveMutation.mutate(actionTargetApp.app.id);
    } else {
      reactivateMutation.mutate(actionTargetApp.app.id);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Application Management"
        description="Register and govern software supply-chain applications authorized to receive SBOM commitments."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            {metrics.total} Registered
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
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
            <Button
              size="sm"
              onClick={() => {
                setVendor(user?.username || "");
                setIsCreateModalOpen(true);
              }}
              className="gap-1.5"
            >
              <Plus className="size-4" />
              <span>Register Application</span>
            </Button>
          </div>
        }
      />

      {/* Metrics Cards */}
      {!isLoading && !error && applications && applications.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <AppWindow className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total Applications</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.total}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Active</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.active}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-card/60">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                <Archive className="size-4" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Archived</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{metrics.archived}</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Main Table Card */}
      <Card>
        <CardHeader className="border-b border-border/60 pb-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-lg font-semibold">Registered Applications</CardTitle>
              <CardDescription className="text-xs mt-0.5">
                Applications owned by your tenant organization. Archived applications cannot receive new SBOM uploads.
              </CardDescription>
            </div>

            {/* Filter and Search Bar */}
            {!isLoading && !error && applications && applications.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[200px] sm:w-64">
                  <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search by name, vendor, or desc..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="h-8 pl-8 text-xs"
                  />
                  {searchTerm && (
                    <button
                      type="button"
                      onClick={() => setSearchTerm("")}
                      className="absolute right-2 top-2 text-muted-foreground hover:text-foreground"
                    >
                      <X className="size-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-lg border border-border/50 text-xs">
                  <button
                    type="button"
                    onClick={() => setStatusFilter("all")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "all"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    All
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("active")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "active"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Active
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter("archived")}
                    className={cn(
                      "px-2.5 py-1 rounded-md transition-colors font-medium",
                      statusFilter === "archived"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    Archived
                  </button>
                </div>
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="pt-4">
          {isLoading && (
            <div className="space-y-3 py-2">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="size-4" />
              <AlertTitle>Error loading applications</AlertTitle>
              <AlertDescription className="flex flex-col gap-2 mt-1">
                <p>{error instanceof ApiError ? error.message : "An unexpected network error occurred."}</p>
                <Button variant="outline" size="sm" className="w-fit" onClick={() => void refetch()}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {!isLoading && !error && applications && applications.length === 0 && (
            <EmptyState
              icon={AppWindow}
              title="No applications registered"
              description="Register your first vendor application to associate and manage cryptographic SBOM commitments."
              action={
                <Button
                  onClick={() => {
                    setVendor(user?.username || "");
                    setIsCreateModalOpen(true);
                  }}
                  className="gap-2"
                >
                  <Plus className="size-4" />
                  Register First Application
                </Button>
              }
            />
          )}

          {!isLoading && !error && applications && applications.length > 0 && filteredApps.length === 0 && (
            <EmptyState
              icon={Search}
              title="No matching applications"
              description="No applications matched your search or status filter. Try clearing filters."
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearchTerm("");
                    setStatusFilter("all");
                  }}
                >
                  Clear Filters
                </Button>
              }
            />
          )}

          {!isLoading && !error && filteredApps.length > 0 && (
            <div className="rounded-lg border border-border/70 overflow-hidden">
              <Table>
                <TableHeader className="bg-muted/40">
                  <TableRow>
                    <TableHead className="font-semibold text-xs">Application Name</TableHead>
                    <TableHead className="font-semibold text-xs">Vendor</TableHead>
                    <TableHead className="font-semibold text-xs">Description</TableHead>
                    <TableHead className="font-semibold text-xs">Status</TableHead>
                    <TableHead className="font-semibold text-xs">Created</TableHead>
                    <TableHead className="font-semibold text-xs text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredApps.map((app) => (
                    <TableRow key={app.id} className="transition-colors hover:bg-muted/30">
                      <TableCell className="font-medium text-xs text-foreground">
                        <div className="flex items-center gap-2">
                          <AppWindow className="size-3.5 text-primary shrink-0" />
                          <span>{app.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <div className="flex items-center gap-1.5">
                          <Building2 className="size-3 text-muted-foreground/70 shrink-0" />
                          <span>{app.vendor}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">
                        {app.description || "—"}
                      </TableCell>
                      <TableCell>
                        <StatusPill
                          status={app.is_active ? "active" : "frozen"}
                          label={app.is_active ? "Active" : "Archived"}
                        />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatTableTimestamp(app.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {app.is_active ? (
                            <>
                              <Link
                                href={`/sboms/upload`}
                                className={cn(
                                  buttonVariants({ variant: "ghost", size: "sm" }),
                                  "h-7 text-xs px-2 gap-1"
                                )}
                              >
                                <FileUp className="size-3 text-primary" />
                                <span>Upload SBOM</span>
                              </Link>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setActionTargetApp({ app, action: "archive" })}
                                className="h-7 text-xs px-2 gap-1 text-muted-foreground hover:text-destructive"
                              >
                                <Archive className="size-3" />
                                <span>Archive</span>
                              </Button>
                            </>
                          ) : (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setActionTargetApp({ app, action: "reactivate" })}
                              className="h-7 text-xs px-2 gap-1 text-emerald-600 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-500/10"
                            >
                              <RefreshCw className="size-3" />
                              <span>Reactivate</span>
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Register Application Modal */}
      {isCreateModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in-50"
          role="dialog"
          aria-modal="true"
        >
          <Card className="w-full max-w-lg shadow-xl border-border bg-card">
            <form onSubmit={handleCreateSubmit}>
              <CardHeader className="border-b border-border/70 pb-3 flex flex-row items-start justify-between">
                <div>
                  <CardTitle className="text-base font-semibold">Register New Application</CardTitle>
                  <CardDescription className="text-xs mt-0.5">
                    Define an application identity to link subsequent SBOM uploads.
                  </CardDescription>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={() => setIsCreateModalOpen(false)}
                >
                  <X className="size-4" />
                </Button>
              </CardHeader>

              <CardContent className="space-y-4 pt-4 text-xs">
                {formError && (
                  <Alert variant="destructive">
                    <AlertCircle className="size-4" />
                    <AlertTitle>Validation Notice</AlertTitle>
                    <AlertDescription className="text-xs mt-0.5">{formError}</AlertDescription>
                  </Alert>
                )}

                {createMutation.error && (
                  <Alert variant="destructive">
                    <AlertCircle className="size-4" />
                    <AlertTitle>Registration Failed</AlertTitle>
                    <AlertDescription className="text-xs mt-0.5">
                      {createMutation.error instanceof ApiError
                        ? createMutation.error.message
                        : "Failed to register application. A record with this name and vendor may already exist."}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="space-y-1.5">
                  <Label htmlFor="appName" className="text-xs font-semibold">
                    Application Name <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="appName"
                    placeholder="e.g. payment-service or identity-api"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    maxLength={255}
                    className="text-xs"
                    disabled={createMutation.isPending}
                    required
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Unique component or service identifier within your vendor scope.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="appVendor" className="text-xs font-semibold">
                    Vendor Organization <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="appVendor"
                    value={vendor}
                    onChange={(e) => setVendor(e.target.value)}
                    maxLength={255}
                    className="text-xs bg-muted/30"
                    disabled={!isAdmin || createMutation.isPending}
                    required
                  />
                  <p className="text-[11px] text-muted-foreground">
                    {isAdmin
                      ? "Vendor organization name (editable by administrator)."
                      : "Bound to your authenticated tenant account."}
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="appDescription" className="text-xs font-semibold">
                    Description
                  </Label>
                  <Input
                    id="appDescription"
                    placeholder="Optional scope or environment notes"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    maxLength={2000}
                    className="text-xs"
                    disabled={createMutation.isPending}
                  />
                </div>
              </CardContent>

              <div className="flex items-center justify-end gap-2 p-4 border-t border-border/70 bg-muted/10">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setIsCreateModalOpen(false)}
                  disabled={createMutation.isPending}
                >
                  Cancel
                </Button>
                <Button type="submit" size="sm" disabled={createMutation.isPending} className="gap-1.5">
                  {createMutation.isPending ? (
                    <>
                      <Loader2 className="size-3.5 animate-spin" />
                      <span>Registering...</span>
                    </>
                  ) : (
                    <>
                      <Plus className="size-3.5" />
                      <span>Register</span>
                    </>
                  )}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* Confirmation Dialog for Archive / Reactivate */}
      {actionTargetApp && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in-50"
          role="dialog"
          aria-modal="true"
        >
          <Card className="w-full max-w-md shadow-xl border-border bg-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold">
                {actionTargetApp.action === "archive"
                  ? `Archive "${actionTargetApp.app.name}"?`
                  : `Reactivate "${actionTargetApp.app.name}"?`}
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                {actionTargetApp.action === "archive"
                  ? "Archiving prevents new SBOM uploads for this application. Existing historical SBOMs, proofs, and verification certificates remain intact and immutable."
                  : "Reactivating restores this application to Active status, allowing new SBOM uploads to resume."}
              </CardDescription>
            </CardHeader>
            <div className="flex items-center justify-end gap-2 p-4 border-t border-border/70 bg-muted/10">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setActionTargetApp(null)}
                disabled={archiveMutation.isPending || reactivateMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                variant={actionTargetApp.action === "archive" ? "destructive" : "default"}
                onClick={handleActionConfirm}
                disabled={archiveMutation.isPending || reactivateMutation.isPending}
                className="gap-1.5"
              >
                {archiveMutation.isPending || reactivateMutation.isPending ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" />
                    <span>Processing...</span>
                  </>
                ) : actionTargetApp.action === "archive" ? (
                  <>
                    <Archive className="size-3.5" />
                    <span>Confirm Archive</span>
                  </>
                ) : (
                  <>
                    <RefreshCw className="size-3.5" />
                    <span>Confirm Reactivate</span>
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

export default function ApplicationsPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <ApplicationManagement />
    </RouteGuard>
  );
}
