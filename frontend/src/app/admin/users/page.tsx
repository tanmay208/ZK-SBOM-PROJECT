"use client";

import * as React from "react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { adminService } from "@/api/services/adminService";
import { AdminUser, Role } from "@/api/types";
import { RouteGuard } from "@/auth/RouteGuard";
import { useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/api/errors";
import { cn } from "@/lib/utils";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Loader2,
  RotateCw,
  Shield,
  UserCheck,
  Users,
  UserX,
} from "lucide-react";

export const PRIMARY_ASSIGNABLE_ROLES: Role[] = [
  "vendor",
  "buyer",
  "admin",
];

export const LEGACY_ROLES: Role[] = [
  "auditor",
  "trusted_importer",
];

export const APPROVED_ROLES: Role[] = [
  ...PRIMARY_ASSIGNABLE_ROLES,
  ...LEGACY_ROLES,
];

interface PendingAction {
  type: "role" | "status";
  user: AdminUser;
  targetRole?: Role;
  targetStatus?: boolean;
}

export function AdminUsersContent() {
  const queryClient = useQueryClient();
  const { user: currentAdmin } = useAuth();

  // Filters & Pagination state
  const [skip, setSkip] = useState(0);
  const limit = 20;
  const [roleFilter, setRoleFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Interaction & Confirmation state
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [selectedRole, setSelectedRole] = useState<Role>("buyer");
  const [actionError, setActionError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Query users
  const {
    data: users,
    isLoading,
    isFetching,
    error,
    refetch,
  } = useQuery<AdminUser[], Error>({
    queryKey: [
      "adminUsers",
      {
        skip,
        limit,
        role: roleFilter === "all" ? undefined : (roleFilter as Role),
        is_active: statusFilter === "all" ? undefined : statusFilter === "active",
      },
    ],
    queryFn: () =>
      adminService.listUsers({
        skip,
        limit,
        role: roleFilter === "all" ? undefined : (roleFilter as Role),
        is_active: statusFilter === "all" ? undefined : statusFilter === "active",
      }),
  });

  // Role update mutation
  const roleMutation = useMutation({
    mutationFn: async ({ userId, newRole }: { userId: string; newRole: Role }) => {
      return adminService.updateUserRole(userId, { role: newRole });
    },
    onSuccess: (updatedUser) => {
      setSuccessMessage(
        `Successfully updated role for user "${updatedUser.username}" to "${updatedUser.role}".`
      );
      setActionError(null);
      setPendingAction(null);
      queryClient.invalidateQueries({ queryKey: ["adminUsers"] });
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
          ? err.message
          : "An unexpected error occurred during role update.";
      setActionError(msg);
      setSuccessMessage(null);
    },
  });

  // Status update mutation
  const statusMutation = useMutation({
    mutationFn: async ({
      userId,
      isActive,
    }: {
      userId: string;
      isActive: boolean;
    }) => {
      return adminService.updateUserStatus(userId, { is_active: isActive });
    },
    onSuccess: (updatedUser) => {
      setSuccessMessage(
        `Successfully ${
          updatedUser.is_active ? "activated" : "deactivated"
        } account "${updatedUser.username}".`
      );
      setActionError(null);
      setPendingAction(null);
      queryClient.invalidateQueries({ queryKey: ["adminUsers"] });
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
          ? err.message
          : "An unexpected error occurred during status update.";
      setActionError(msg);
      setSuccessMessage(null);
    },
  });

  const isMutating = roleMutation.isPending || statusMutation.isPending;

  const handleRoleInitiate = (user: AdminUser) => {
    const initialRole = PRIMARY_ASSIGNABLE_ROLES.includes(user.role)
      ? user.role
      : "buyer";
    setSelectedRole(initialRole);
    setActionError(null);
    setSuccessMessage(null);
    setPendingAction({
      type: "role",
      user,
      targetRole: initialRole,
    });
  };

  const handleStatusInitiate = (user: AdminUser) => {
    setActionError(null);
    setSuccessMessage(null);
    setPendingAction({
      type: "status",
      user,
      targetStatus: !user.is_active,
    });
  };

  const handleConfirmAction = () => {
    if (!pendingAction) return;

    if (pendingAction.type === "role") {
      roleMutation.mutate({
        userId: pendingAction.user.id,
        newRole: selectedRole,
      });
    } else if (pendingAction.type === "status") {
      statusMutation.mutate({
        userId: pendingAction.user.id,
        isActive: pendingAction.targetStatus ?? !pendingAction.user.is_active,
      });
    }
  };

  const handleCancelAction = () => {
    setPendingAction(null);
    setActionError(null);
  };

  const formatTimestamp = (dateStr?: string | null): string => {
    if (!dateStr) return "-";
    try {
      const date = new Date(dateStr);
      return date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
    } catch {
      return dateStr;
    }
  };

  const isSelf = (targetUser: AdminUser): boolean => {
    if (!currentAdmin) return false;
    return (
      targetUser.id === currentAdmin.id ||
      targetUser.username.toLowerCase() === currentAdmin.username.toLowerCase()
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="User & Role Administration"
        description="Platform account governance, authorized role allocation, and status lifecycle management with active administrator safeguards."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            Admin Authority
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

      {/* Alerts */}
      {actionError && (
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>Operation Failed</AlertTitle>
          <AlertDescription>{actionError}</AlertDescription>
        </Alert>
      )}

      {successMessage && (
        <Alert className="border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300">
          <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{successMessage}</AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>Failed to Load Users</AlertTitle>
          <AlertDescription>
            {error instanceof ApiError ? error.message : error.message}
          </AlertDescription>
        </Alert>
      )}

      {/* Confirmation Modal / Card */}
      {pendingAction && (
        <Card className="border-amber-500/40 bg-amber-500/5 shadow-md">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2 text-amber-700 dark:text-amber-400">
              <AlertTriangle className="size-5" />
              <CardTitle className="text-base font-semibold">
                Confirm Administrative Action
              </CardTitle>
            </div>
            <CardDescription className="text-xs">
              Review and confirm this administrative modification. All actions are checked against system security invariants.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 pt-1">
            <div className="rounded-md border border-border bg-background p-3 text-sm space-y-2">
              <div>
                <span className="text-muted-foreground text-xs">Target User:</span>{" "}
                <strong className="font-mono text-foreground">{pendingAction.user.username}</strong>
                <span className="text-muted-foreground text-xs ml-2">({pendingAction.user.id})</span>
              </div>

              {pendingAction.type === "role" ? (
                <div className="space-y-2 pt-2 border-t border-border/50">
                  <div className="text-xs text-muted-foreground">
                    Current Role: <Badge variant="outline">{pendingAction.user.role}</Badge>
                  </div>
                  <div className="flex items-center gap-3">
                    <label htmlFor="role-select" className="text-xs font-medium text-foreground">
                      New Role:
                    </label>
                    <select
                      id="role-select"
                      value={selectedRole}
                      onChange={(e) => setSelectedRole(e.target.value as Role)}
                      disabled={isMutating}
                      className="h-8 rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                    >
                      {PRIMARY_ASSIGNABLE_ROLES.map((role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                  </div>
                  {LEGACY_ROLES.includes(pendingAction.user.role) && (
                    <p className="text-[11px] text-amber-600 dark:text-amber-400">
                      Notice: User currently holds legacy role &ldquo;{pendingAction.user.role}&rdquo;. Select a primary role to transition this account.
                    </p>
                  )}
                  {isSelf(pendingAction.user) && selectedRole !== "admin" && (
                    <p className="text-[11px] text-amber-600 dark:text-amber-400">
                      Warning: You are demoting your own administrator account. This will succeed only if another active administrator remains.
                    </p>
                  )}
                </div>
              ) : (
                <div className="space-y-2 pt-2 border-t border-border/50">
                  <div className="text-xs">
                    Current Status:{" "}
                    <StatusPill status={pendingAction.user.is_active ? "active" : "revoked"}>
                      {pendingAction.user.is_active ? "Active" : "Deactivated"}
                    </StatusPill>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Action:{" "}
                    <span className="font-semibold text-foreground">
                      {pendingAction.targetStatus ? "Activate Account" : "Deactivate Account"}
                    </span>
                  </div>
                  {!pendingAction.targetStatus && (
                    <p className="text-[11px] text-muted-foreground">
                      Deactivating an account immediately blocks login and revokes access across all authenticated endpoints for existing JWTs.
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleCancelAction}
                disabled={isMutating}
              >
                Cancel
              </Button>
              <Button
                variant={pendingAction.type === "status" && !pendingAction.targetStatus ? "destructive" : "default"}
                size="sm"
                onClick={handleConfirmAction}
                disabled={isMutating || (pendingAction.type === "role" && selectedRole === pendingAction.user.role)}
                className="gap-1.5"
              >
                {isMutating && <Loader2 className="size-3.5 animate-spin" />}
                <span>
                  {isMutating
                    ? "Applying Mutation..."
                    : pendingAction.type === "role"
                    ? "Apply Role Change"
                    : pendingAction.targetStatus
                    ? "Confirm Activation"
                    : "Confirm Deactivation"}
                </span>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters Card */}
      <Card className="shadow-xs border-border/80">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-4">
              {/* Role Filter */}
              <div className="flex items-center gap-2">
                <label htmlFor="filter-role" className="text-xs font-medium text-muted-foreground">
                  Role:
                </label>
                <select
                  id="filter-role"
                  value={roleFilter}
                  onChange={(e) => {
                    setRoleFilter(e.target.value);
                    setSkip(0);
                  }}
                  className="h-8 rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                >
                  <option value="all">All Roles</option>
                  <optgroup label="Primary Roles">
                    {PRIMARY_ASSIGNABLE_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </optgroup>
                  <optgroup label="Legacy Roles">
                    {LEGACY_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </optgroup>
                </select>
              </div>

              {/* Status Filter */}
              <div className="flex items-center gap-2">
                <label htmlFor="filter-status" className="text-xs font-medium text-muted-foreground">
                  Status:
                </label>
                <select
                  id="filter-status"
                  value={statusFilter}
                  onChange={(e) => {
                    setStatusFilter(e.target.value);
                    setSkip(0);
                  }}
                  className="h-8 rounded-md border border-input bg-background px-3 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                >
                  <option value="all">All Statuses</option>
                  <option value="active">Active Only</option>
                  <option value="inactive">Deactivated Only</option>
                </select>
              </div>
            </div>

            {/* Pagination Controls */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">
                Offset {skip} &ndash; {skip + (users?.length || 0)}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSkip(Math.max(0, skip - limit))}
                disabled={skip === 0 || isLoading}
                aria-label="Previous Page"
              >
                <ChevronLeft className="size-3.5" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSkip(skip + limit)}
                disabled={!users || users.length < limit || isLoading}
                aria-label="Next Page"
              >
                <ChevronRight className="size-3.5" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Users Table */}
      <Card className="shadow-xs border-border/80">
        <CardHeader className="pb-3 border-b border-border/50">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base font-semibold">Registered Users</CardTitle>
              <CardDescription className="text-xs">
                Authoritative user registry. Password hashes and credentials are strictly excluded.
              </CardDescription>
            </div>
            {users && (
              <Badge variant="secondary" className="font-mono text-xs">
                {users.length} {users.length === 1 ? "User" : "Users"} Displayed
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {[1, 2, 3, 4, 5].map((i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : !users || users.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon={Users}
                title="No Users Found"
                description={
                  roleFilter !== "all" || statusFilter !== "all"
                    ? "No registered users match the selected filters."
                    : "No users are currently registered in the database."
                }
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Last Updated</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => {
                    const selfTarget = isSelf(u);
                    const canDeactivate = !selfTarget;

                    return (
                      <TableRow key={u.id} className="hover:bg-muted/30">
                        <TableCell>
                          <div className="flex flex-col">
                            <span className="font-medium text-foreground flex items-center gap-1.5">
                              {u.username}
                              {selfTarget && (
                                <Badge variant="outline" className="text-[10px] py-0 text-primary border-primary/40">
                                  You
                                </Badge>
                              )}
                            </span>
                            <span className="text-[11px] font-mono text-muted-foreground">{u.id}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={u.role === "admin" ? "default" : "outline"}
                            className="text-xs font-mono capitalize"
                          >
                            {u.role.replace("_", " ")}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <StatusPill status={u.is_active ? "active" : "revoked"}>
                            {u.is_active ? "Active" : "Deactivated"}
                          </StatusPill>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(u.created_at)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(u.updated_at)}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {/* Change Role Button */}
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleRoleInitiate(u)}
                              disabled={isMutating}
                              className="h-7 text-xs px-2"
                              title="Change user role"
                            >
                              <Shield className="size-3 mr-1" />
                              <span>Role</span>
                            </Button>

                            {/* Status Button */}
                            {u.is_active ? (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleStatusInitiate(u)}
                                disabled={isMutating || !canDeactivate}
                                className={cn(
                                  "h-7 text-xs px-2 text-destructive hover:bg-destructive/10 hover:text-destructive",
                                  !canDeactivate && "opacity-50 cursor-not-allowed"
                                )}
                                title={
                                  selfTarget
                                    ? "Cannot deactivate your own active admin account (enforced by system invariant)"
                                    : "Deactivate user account"
                                }
                              >
                                <UserX className="size-3 mr-1" />
                                <span>Deactivate</span>
                              </Button>
                            ) : (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleStatusInitiate(u)}
                                disabled={isMutating}
                                className="h-7 text-xs px-2 text-emerald-600 hover:bg-emerald-500/10 hover:text-emerald-700"
                                title="Reactivate user account"
                              >
                                <UserCheck className="size-3 mr-1" />
                                <span>Activate</span>
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function AdminUsersPage() {
  return (
    <RouteGuard allowedRoles={["admin"]}>
      <AdminUsersContent />
    </RouteGuard>
  );
}
