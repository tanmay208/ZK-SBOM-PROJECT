"use client";

import * as React from "react";
import Link from "next/link";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import {
  ArrowRight,
  Database,
  EyeOff,
  Info,
  Scale,
  ShieldAlert,
  Users,
} from "lucide-react";

export function AdminOverviewContent() {
  return (
    <div className="space-y-8">
      {/* C1 Design System PageHeader */}
      <PageHeader
        title="Administration Workspace"
        description="Platform governance, security policy management, and threat intelligence lifecycle oversight."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30">
            Admin Authority
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Link href="/admin/users" className={buttonVariants({ variant: "outline", size: "sm" })}>
              <Users className="size-3.5 mr-1.5" />
              <span>Users</span>
            </Link>
            <Link href="/admin/policies" className={buttonVariants({ variant: "outline", size: "sm" })}>
              <Scale className="size-3.5 mr-1.5" />
              <span>Policies</span>
            </Link>
            <Link href="/admin/vulnerabilities" className={buttonVariants({ variant: "outline", size: "sm" })}>
              <Database className="size-3.5 mr-1.5" />
              <span>Vulnerability Intel</span>
            </Link>
          </div>
        }
      />

      {/* Core Administrative Pillars */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-foreground">Governance Pillars</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Core operational domains governed by the administrator role.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-3 items-stretch">
          {/* Pillar 1: Security Policies */}
          <Card className="flex flex-col justify-between shadow-xs border-border/80 hover:border-primary/50 transition-colors">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Scale className="size-5" />
                </div>
                <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                  Active Endpoint
                </Badge>
              </div>
              <CardTitle className="text-base font-semibold mt-3">Security Policies</CardTitle>
              <CardDescription className="text-xs leading-relaxed">
                Define organizational CVSS score thresholds, deploy active policies, and inspect canonical policy digest commitments (H_Policy).
              </CardDescription>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground space-y-2">
              <div className="rounded bg-muted/50 p-2 text-[11px] font-mono">
                Route: /api/v1/policy
              </div>
              <p>
                Policies are transparent reference objects. Any authenticated user can inspect policies; only admins can create new thresholds.
              </p>
            </CardContent>
            <CardFooter className="pt-2 border-t border-border/50">
              <Link
                href="/admin/policies"
                className={cn(buttonVariants({ size: "sm" }), "w-full justify-between gap-1.5")}
              >
                <span>Manage Policies</span>
                <ArrowRight className="size-3.5" />
              </Link>
            </CardFooter>
          </Card>

          {/* Pillar 2: Vulnerability Intelligence */}
          <Card className="flex flex-col justify-between shadow-xs border-border/80 hover:border-primary/50 transition-colors">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Database className="size-5" />
                </div>
                <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                  Active Endpoint
                </Badge>
              </div>
              <CardTitle className="text-base font-semibold mt-3">Vulnerability Intelligence</CardTitle>
              <CardDescription className="text-xs leading-relaxed">
                Oversee snapshot lifecycle (<code className="text-foreground">pending</code> &rarr; <code className="text-foreground">approved</code> &rarr; <code className="text-foreground">frozen</code> &rarr; <code className="text-foreground">revoked</code>) and compute authoritative SMT roots (R_VulnDB).
              </CardDescription>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground space-y-2">
              <div className="rounded bg-muted/50 p-2 text-[11px] font-mono">
                Route: /api/v1/vulnerability
              </div>
              <p>
                Enforces strict separation of duties: admins review, approve, freeze, and revoke snapshots; ingestion is restricted to trusted importers.
              </p>
            </CardContent>
            <CardFooter className="pt-2 border-t border-border/50">
              <Link
                href="/admin/vulnerabilities"
                className={cn(buttonVariants({ size: "sm" }), "w-full justify-between gap-1.5")}
              >
                <span>Manage Snapshots</span>
                <ArrowRight className="size-3.5" />
              </Link>
            </CardFooter>
          </Card>

          {/* Pillar 3: User & Role Administration */}
          <Card className="flex flex-col justify-between shadow-xs border-border/80 hover:border-primary/50 transition-colors">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Users className="size-5" />
                </div>
                <Badge variant="outline" className="text-[10px] text-emerald-700 dark:text-emerald-400 border-emerald-500/30">
                  Active Endpoint
                </Badge>
              </div>
              <CardTitle className="text-base font-semibold mt-3">User & Role Administration</CardTitle>
              <CardDescription className="text-xs leading-relaxed">
                Platform account oversight, administrative role allocation across the 5 approved roles, and account activation lifecycle management.
              </CardDescription>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground space-y-2">
              <div className="rounded bg-muted/50 p-2 text-[11px] font-mono">
                Route: /api/v1/admin/users
              </div>
              <p>
                Strictly gated on administrator authority. Enforces concurrency-safe invariants protecting the last active administrator and prohibiting self-deactivation.
              </p>
            </CardContent>
            <CardFooter className="pt-2 border-t border-border/50">
              <Link
                href="/admin/users"
                className={cn(buttonVariants({ size: "sm" }), "w-full justify-between gap-1.5")}
              >
                <span>Manage Users</span>
                <ArrowRight className="size-3.5" />
              </Link>
            </CardFooter>
          </Card>
        </div>
      </div>

      {/* Administrative Invariants & Separation of Duties Guidance */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Tenancy & Privacy Isolation Card */}
        <Card className="shadow-xs">
          <CardHeader className="pb-3 border-b border-border/60">
            <div className="flex items-center gap-2">
              <EyeOff className="size-4 text-primary" />
              <CardTitle className="text-sm font-semibold">Vendor Privacy & Tenancy Isolation</CardTitle>
            </div>
            <CardDescription className="text-xs">
              Architectural privacy invariants strictly preserved across administrative operations.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 pt-4 text-xs text-muted-foreground leading-relaxed">
            <p>
              <strong>Zero Vendor Manifest Disclosure:</strong> Administrative roles do not bypass tenant isolation. Vendor SBOM components, package URLs (PURLs), licenses, and internal dependency graphs are private to the owning tenant.
            </p>
            <p>
              <strong>Cryptographic Verification Only:</strong> Administrators inspect only public commitments (R_SBOM, R_VulnDB, H_Policy) and issued verification certificates. Raw SBOM contents are never stored in administrative logs or exposed in admin views.
            </p>
          </CardContent>
        </Card>

        {/* Separation of Duties (SoD) Card */}
        <Card className="shadow-xs">
          <CardHeader className="pb-3 border-b border-border/60">
            <div className="flex items-center gap-2">
              <ShieldAlert className="size-4 text-amber-600 dark:text-amber-400" />
              <CardTitle className="text-sm font-semibold">Separation of Duties (SoD) Invariants</CardTitle>
            </div>
            <CardDescription className="text-xs">
              Cryptographic and operational role segregation enforced by backend services.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 pt-4 text-xs text-muted-foreground leading-relaxed">
            <p>
              <strong>Two-Person Integrity Rule:</strong> Administrators ingest vulnerability threat intelligence feeds directly. Snapshots must be reviewed and approved by a distinct Administrator before freezing.
            </p>
            <p>
              <strong>No Self-Approval:</strong> The vulnerability service rejects approval attempts if the snapshot creator matches the approving administrator ID (<code className="font-mono text-foreground">creator != approver</code>).
            </p>
            <p>
              <strong>Certificate Ownership:</strong> Proof verification certificates are owned by the submitting tenant. Administrators cannot revoke certificates without valid tenant ownership.
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Honest Limitation Callout */}
      <Alert className="bg-muted/30 border-border/80 text-muted-foreground">
        <Info className="size-4 text-primary" />
        <AlertTitle className="text-xs font-semibold text-foreground">Backend Contract Integrity</AlertTitle>
        <AlertDescription className="text-xs leading-relaxed mt-0.5">
          This administration workspace connects exclusively to verified, active backend routes (<code className="font-mono text-foreground">/api/v1/policy</code> and <code className="font-mono text-foreground">/api/v1/vulnerability</code>). Unimplemented capabilities, such as multi-tenant user modification or global system telemetry, are explicitly marked as planned for Stage D.
        </AlertDescription>
      </Alert>
    </div>
  );
}

export default function AdminPage() {
  return (
    <RouteGuard allowedRoles={["admin"]}>
      <AdminOverviewContent />
    </RouteGuard>
  );
}
