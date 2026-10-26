"use client";

import * as React from "react";
import { useState } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PasswordInput } from "@/components/ui/password-input";
import { Label } from "@/components/ui/label";
import { authService } from "@/api/services/authService";
import { ApiError } from "@/api/errors";
import {
  Check,
  Copy,
  Lock,
  Shield,
  ShieldCheck,
  User,
  Clock,
  KeyRound,
  CheckCircle2,
  Sliders,
  Loader2,
  AlertCircle,
} from "lucide-react";

function getRoleBadgeVariant(role: string): "default" | "info" | "warning" | "secondary" {
  switch (role) {
    case "admin":
      return "default";
    case "vendor":
      return "info";
    case "buyer":
      return "info";
    case "trusted_importer":
      return "warning";
    case "auditor":
    default:
      return "secondary";
  }
}

function getRoleDetails(role: string) {
  switch (role) {
    case "admin":
      return {
        label: "Administrator",
        summary: "System governance authority: security policy definition, vulnerability snapshot approvals, and cryptographic lifecycle oversight.",
        permissions: [
          "Create and activate security policies (/admin/policies)",
          "Ingest vulnerability threat intelligence feeds (/admin/vulnerabilities)",
          "Approve, freeze, and revoke vulnerability snapshots (/admin/vulnerabilities)",
          "Inspect verification certificates and run independent verifications",
          "Manage application, user, and SBOM configurations",
        ],
        restrictions: [
          "Cannot approve self-created vulnerability snapshots (Two-Person Integrity Rule enforced)",
          "Cannot view private component names or raw SBOM trees belonging to other tenants",
        ],
      };
    case "vendor":
      return {
        label: "Software Vendor",
        summary: "Supply chain publisher: manages authorized application manifests, generates Sparse Merkle Trees, and produces UltraPlonk zero-knowledge proofs.",
        permissions: [
          "Upload and manage CycloneDX / SPDX SBOM manifests (/sboms)",
          "Generate and monitor UltraPlonk proof jobs (/proofs)",
          "Verify proofs and inspect issued verification certificates (/verify, /certificates)",
          "Inspect approved and frozen vulnerability snapshots (/admin/vulnerabilities)",
        ],
        restrictions: [
          "Cannot define or modify global security policies (Admin only)",
          "Cannot approve, freeze, or revoke vulnerability snapshots (Admin only)",
          "Cannot access or verify proofs of other tenant accounts",
        ],
      };
    case "trusted_importer":
      return {
        label: "Trusted Threat Intelligence Importer",
        summary: "Restricted feeder role: authoritative ingestion of CVE intelligence records with provenance verification.",
        permissions: [
          "Ingest vulnerability databases from trusted sources (NVD, OSV, GitHub Advisory) (/admin/vulnerabilities)",
          "Attach cryptographic provenance metadata to ingested feeds",
          "Inspect existing snapshot lifecycle states",
        ],
        restrictions: [
          "Cannot approve or freeze vulnerability snapshots (Separation of Duties; Admin only)",
          "Cannot upload SBOM manifests or initiate ZKP proving jobs",
          "Excluded from general tenant dashboard and verification workspace",
        ],
      };
    case "buyer":
      return {
        label: "Procurement Buyer",
        summary: "Supply chain consumer: independent verification of vendor cryptographic evidence, public commitments (R_SBOM, R_VulnDB, H_Policy), and compliance certificates.",
        permissions: [
          "Independently verify zero-knowledge proofs against public commitments (/verify)",
          "Inspect issued verification certificates and validate public records (/certificates)",
          "Review active security policies (/admin/policies)",
          "Inspect approved and frozen vulnerability snapshots (/admin/vulnerabilities)",
          "Access procurement dashboard with cryptographic metrics (/dashboard)",
        ],
        restrictions: [
          "Cannot upload private SBOM manifests or compile proof jobs (Vendor/Admin only)",
          "Cannot modify security policies or approve vulnerability snapshots (Admin only)",
          "Cannot edit or revoke certificates",
        ],
      };
    case "auditor":
    default:
      return {
        label: "Compliance Auditor",
        summary: "Independent verifier: read-only inspection of cryptographic evidence, public commitment verification, and certificate attestation.",
        permissions: [
          "Independently verify zero-knowledge proofs against public commitments (/verify)",
          "Inspect issued verification certificates and validate public records (/certificates)",
          "Review active security policies and frozen vulnerability snapshot commitments",
        ],
        restrictions: [
          "Cannot upload private SBOM manifests or compile proof jobs",
          "Cannot modify security policies or approve vulnerability snapshots",
          "Cannot edit or revoke certificates",
        ],
      };
  }
}

export function ProfileContent() {
  const { user } = useAuth();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [passwordSuccessMsg, setPasswordSuccessMsg] = useState<string | null>(null);
  const [passwordErrorMsg, setPasswordErrorMsg] = useState<string | null>(null);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordErrorMsg(null);
    setPasswordSuccessMsg(null);

    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordErrorMsg("All password fields are required.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordErrorMsg("New password and confirmation do not match.");
      return;
    }

    if (newPassword.length < 8) {
      setPasswordErrorMsg("New password must be at least 8 characters.");
      return;
    }

    const utf8Length = new TextEncoder().encode(newPassword).length;
    if (utf8Length > 72) {
      setPasswordErrorMsg("New password must not exceed 72 UTF-8 bytes.");
      return;
    }

    try {
      setIsChangingPassword(true);
      const res = await authService.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPasswordSuccessMsg(res.message || "Password changed successfully.");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      if (err instanceof ApiError) {
        setPasswordErrorMsg(err.message || "Failed to change password.");
      } else {
        setPasswordErrorMsg("An unexpected error occurred while changing password.");
      }
    } finally {
      setIsChangingPassword(false);
    }
  };

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // Clipboard fallback
    }
  };

  const roleInfo = getRoleDetails(user?.role || "auditor");

  return (
    <div className="space-y-6">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Profile & Session Settings"
        description="Active authenticated identity, role-based authorization boundaries, and in-memory session security guarantees."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            Session Security
          </Badge>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Column: Identity & In-Memory Privacy Invariants */}
        <div className="lg:col-span-2 space-y-6">
          {/* Identity & Session Metadata Card */}
          <Card className="shadow-xs">
            <CardHeader className="border-b border-border/60 pb-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <User className="size-5" />
                  </div>
                  <div>
                    <CardTitle className="text-base font-semibold">Caller Identity</CardTitle>
                    <CardDescription className="text-xs">
                      Cryptographic credentials validated via <code>/api/v1/auth/me</code>
                    </CardDescription>
                  </div>
                </div>
                <Badge variant={getRoleBadgeVariant(user?.role || "auditor")} className="capitalize text-xs">
                  {user?.role?.replace(/_/g, " ")}
                </Badge>
              </div>
            </CardHeader>

            <CardContent className="space-y-4 pt-5 text-xs">
              {/* Username Field */}
              <div className="rounded-lg bg-muted/40 p-3.5 border border-border/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                    Account Username
                  </span>
                  <span className="text-sm font-medium text-foreground mt-0.5 block">{user?.username || "—"}</span>
                </div>
                <Badge variant="secondary" className="w-fit text-[10px]">
                  Read-Only Identity
                </Badge>
              </div>

              {/* User ID Field */}
              <div className="rounded-lg bg-muted/40 p-3.5 border border-border/50">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                    Authoritative User ID (UUID)
                  </span>
                  {user?.id && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-5 text-[11px] px-1.5 text-primary"
                      onClick={() => copyToClipboard(user.id, "user-id")}
                    >
                      {copiedKey === "user-id" ? (
                        <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                          <Check className="size-3" /> Copied
                        </span>
                      ) : (
                        <span className="flex items-center gap-1">
                          <Copy className="size-3" /> Copy UUID
                        </span>
                      )}
                    </Button>
                  )}
                </div>
                <p className="font-mono text-xs text-foreground mt-1 break-all bg-background/80 p-2 rounded border border-border/40">
                  {user?.id || "—"}
                </p>
              </div>

              {/* Account Lifecycle & Status */}
              <div className="rounded-lg bg-muted/40 p-3.5 border border-border/50 flex items-center justify-between">
                <div>
                  <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                    Account Status
                  </span>
                  <span className="text-xs font-medium text-foreground mt-0.5 flex items-center gap-1.5">
                    {user?.is_active !== false ? (
                      <>
                        <span className="inline-block size-2 rounded-full bg-emerald-500" />
                        Active Account
                      </>
                    ) : (
                      <>
                        <span className="inline-block size-2 rounded-full bg-destructive" />
                        Deactivated
                      </>
                    )}
                  </span>
                </div>
                <Badge variant={user?.is_active !== false ? "outline" : "destructive"} className="text-[10px]">
                  {user?.is_active !== false ? "Enforced" : "Inactive"}
                </Badge>
              </div>

              {/* Account Timestamps */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
                  <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                    Created At
                  </span>
                  <span className="font-mono text-[11px] text-foreground mt-0.5 block">
                    {user?.created_at ? new Date(user.created_at).toLocaleString() : "—"}
                  </span>
                </div>
                <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
                  <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                    Last Updated
                  </span>
                  <span className="font-mono text-[11px] text-foreground mt-0.5 block">
                    {user?.updated_at ? new Date(user.updated_at).toLocaleString() : "—"}
                  </span>
                </div>
              </div>

              {/* Assigned Role Summary */}
              <div className="rounded-lg bg-muted/40 p-3.5 border border-border/50 space-y-1.5">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block">
                  Active Role Description
                </span>
                <p className="text-foreground leading-relaxed">
                  {roleInfo.summary}
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Role Permissions Breakdown */}
          <Card className="shadow-xs">
            <CardHeader className="border-b border-border/60 pb-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">Authorized Role Capabilities</CardTitle>
              </div>
              <CardDescription className="text-xs">
                Server-side permissions granted to the <code>{user?.role}</code> role under existing backend contracts.
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4 pt-5 text-xs">
              <div className="space-y-2">
                <span className="font-semibold text-emerald-700 dark:text-emerald-400 text-xs flex items-center gap-1.5">
                  <CheckCircle2 className="size-3.5" /> Granted Capabilities
                </span>
                <ul className="grid gap-1.5 pl-5 list-disc text-muted-foreground">
                  {roleInfo.permissions.map((perm, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {perm}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2 pt-2 border-t border-border/50">
                <span className="font-semibold text-amber-700 dark:text-amber-400 text-xs flex items-center gap-1.5">
                  <Shield className="size-3.5" /> Enforced Separation of Duties & Restrictions
                </span>
                <ul className="grid gap-1.5 pl-5 list-disc text-muted-foreground">
                  {roleInfo.restrictions.map((res, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {res}
                    </li>
                  ))}
                </ul>
              </div>
            </CardContent>
          </Card>

          {/* System-Wide 5-Role Model Reference Table */}
          <Card className="shadow-xs">
            <CardHeader className="border-b border-border/60 pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">Platform Role Architecture Reference</CardTitle>
              </div>
              <CardDescription className="text-xs">
                Planned 5-role security model mapped against active and planned backend capabilities.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs font-semibold">Role Name</TableHead>
                    <TableHead className="text-xs font-semibold">Backend Status</TableHead>
                    <TableHead className="text-xs font-semibold">Primary Responsibility</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className="text-xs">
                  <TableRow className={user?.role === "vendor" ? "bg-primary/5 font-medium" : ""}>
                    <TableCell className="font-mono">vendor</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                        Active
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">Manages private SBOMs, compiles Sparse Merkle Trees, and initiates ZKP proving.</TableCell>
                  </TableRow>
                  <TableRow className={user?.role === "admin" ? "bg-primary/5 font-medium" : ""}>
                    <TableCell className="font-mono">admin</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                        Active
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">Maintains security policies, approves/freezes vulnerability snapshots, oversees proofs.</TableCell>
                  </TableRow>
                  <TableRow className={user?.role === "auditor" ? "bg-primary/5 font-medium" : ""}>
                    <TableCell className="font-mono">auditor</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                        Active
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">Compliance audit role; independently verifies proofs and inspects public certificates.</TableCell>
                  </TableRow>
                  <TableRow className={user?.role === "trusted_importer" ? "bg-primary/5 font-medium" : ""}>
                    <TableCell className="font-mono">trusted_importer</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                        Active (SoD)
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">Ingests NVD/OSV/GitHub threat intelligence with provenance; separated from snapshot approval.</TableCell>
                  </TableRow>
                  <TableRow className={user?.role === "buyer" ? "bg-primary/5 font-medium" : ""}>
                    <TableCell className="font-mono">buyer</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                        Active (Default)
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">Default self-registration role; dedicated procurement recipient with independent proof verification.</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Security Architecture & Account Operations */}
        <div className="space-y-6">
          {/* In-Memory Privacy Invariants */}
          <Card className="shadow-xs border-primary/20 bg-primary/[0.02]">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Lock className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">In-Memory Privacy Model</CardTitle>
              </div>
              <CardDescription className="text-xs">
                Zero persistent storage architecture enforced by <code>authTransport.ts</code>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-xs text-muted-foreground leading-relaxed">
              <p>
                <strong>Bearer Token Ephemerality:</strong> Authentication tokens are stored exclusively in JavaScript memory variables. Tokens are never persisted to <code className="font-mono text-foreground">localStorage</code>, <code className="font-mono text-foreground">sessionStorage</code>, or cookies.
              </p>
              <p>
                <strong>Refresh Trade-Off:</strong> Page reloads, tab closures, or explicit sign-out immediately purge the in-memory token, requiring re-authentication. This intentional trade-off completely eliminates browser storage token leakage.
              </p>
              <div className="rounded-md bg-muted/60 p-2.5 border border-border/50 text-[11px] font-mono text-foreground flex items-center gap-2">
                <Clock className="size-3.5 text-primary shrink-0" />
                <span>Token Expiration: 24h &bull; Ephemeral</span>
              </div>
            </CardContent>
          </Card>

          {/* Account Operations: Self-Service Password Change */}
          <Card className="shadow-xs bg-card/60">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">Change Password</CardTitle>
              </div>
              <CardDescription className="text-xs">
                Self-service credential rotation enforced by <code>POST /api/v1/auth/change-password</code>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3.5 text-xs">
              {passwordSuccessMsg && (
                <Alert className="border-emerald-500/30 bg-emerald-500/10 text-emerald-900 dark:text-emerald-200 py-2">
                  <CheckCircle2 className="size-3.5 text-emerald-600 dark:text-emerald-400" />
                  <AlertTitle className="text-xs font-semibold">Success</AlertTitle>
                  <AlertDescription className="text-[11px]">{passwordSuccessMsg}</AlertDescription>
                </Alert>
              )}

              {passwordErrorMsg && (
                <Alert variant="destructive" className="py-2">
                  <AlertCircle className="size-3.5" />
                  <AlertTitle className="text-xs font-semibold">Error</AlertTitle>
                  <AlertDescription className="text-[11px]">{passwordErrorMsg}</AlertDescription>
                </Alert>
              )}

              <form onSubmit={handlePasswordChange} className="space-y-3">
                <div className="space-y-1">
                  <Label htmlFor="current-password" className="text-xs font-medium text-foreground">
                    Current Password
                  </Label>
                  <PasswordInput
                    id="current-password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Enter current password"
                    disabled={isChangingPassword}
                    required
                    className="h-8 text-xs"
                  />
                </div>

                <div className="space-y-1">
                  <Label htmlFor="new-password" className="text-xs font-medium text-foreground">
                    New Password
                  </Label>
                  <PasswordInput
                    id="new-password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="At least 8 characters (max 72 bytes)"
                    disabled={isChangingPassword}
                    required
                    className="h-8 text-xs"
                  />
                </div>

                <div className="space-y-1">
                  <Label htmlFor="confirm-password" className="text-xs font-medium text-foreground">
                    Confirm New Password
                  </Label>
                  <PasswordInput
                    id="confirm-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter new password"
                    disabled={isChangingPassword}
                    required
                    className="h-8 text-xs"
                  />
                </div>

                <Button
                  type="submit"
                  size="sm"
                  className="w-full gap-1.5 mt-2"
                  disabled={isChangingPassword || !currentPassword || !newPassword || !confirmPassword}
                >
                  {isChangingPassword ? (
                    <>
                      <Loader2 className="size-3.5 animate-spin" />
                      <span>Updating Password...</span>
                    </>
                  ) : (
                    <>
                      <KeyRound className="size-3.5" />
                      <span>Update Password</span>
                    </>
                  )}
                </Button>
              </form>

              <div className="pt-2 border-t border-border/50 text-[11px] text-muted-foreground space-y-1">
                <div className="flex items-center justify-between">
                  <span>Profile Schema:</span>
                  <Badge variant="outline" className="text-[10px]">Schema-Locked</Badge>
                </div>
                <p className="text-[10px] leading-tight text-muted-foreground/80 pt-1">
                  Username and role modifications are restricted to preserve cryptographic provenance and multi-tenant audit boundaries.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function ProfilePage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin", "auditor", "trusted_importer", "buyer"]}>
      <ProfileContent />
    </RouteGuard>
  );
}
