"use client";

import Link from "next/link";
import { useState } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { 
  ShieldCheck, 
  Lock, 
  FileText, 
  CheckCircle2, 
  AlertTriangle, 
  ArrowRight, 
  Cpu, 
  Award, 
  Database, 
  Scale, 
  EyeOff, 
  FileCode2, 
  Layers, 
  Menu, 
  X,
  KeyRound
} from "lucide-react";

export default function HomePage() {
  const { user, status } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const isAuthenticated = status === "authenticated";

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground antialiased selection:bg-primary/15 selection:text-primary">
      {/* ----------------------------------------------------------------------- */}
      {/* SECTION A: PUBLIC NAVIGATION                                            */}
      {/* ----------------------------------------------------------------------- */}
      <header className="sticky top-0 z-40 w-full border-b border-border/80 bg-background/95 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          {/* Brand Identity */}
          <Link 
            href="/" 
            className="flex items-center gap-2.5 font-semibold text-foreground transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-md"
          >
            <div className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-2xs">
              <ShieldCheck className="size-5" aria-hidden="true" />
            </div>
            <div className="flex flex-col">
              <span className="text-base font-bold tracking-tight">ZK-SBOM Verify</span>
              <span className="text-[10px] text-muted-foreground font-normal tracking-wide uppercase">Zero-Knowledge Supply Chain</span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-muted-foreground">
            <a href="#overview" className="transition-colors hover:text-foreground">Overview</a>
            <a href="#problem" className="transition-colors hover:text-foreground">The Dilemma</a>
            <a href="#workflow" className="transition-colors hover:text-foreground">How It Works</a>
            <a href="#capabilities" className="transition-colors hover:text-foreground">Capabilities</a>
            <a href="#limitations" className="transition-colors hover:text-foreground">Security & Scope</a>
          </nav>

          {/* Desktop User Actions */}
          <div className="hidden md:flex items-center gap-3">
            <ThemeToggle />
            {isAuthenticated ? (
              <div className="flex items-center gap-2.5 pl-2 border-l border-border/70">
                <span className="text-xs text-muted-foreground">
                  Signed in as <strong className="text-foreground font-medium">{user?.username}</strong>
                </span>
                <Link href="/dashboard" className={buttonVariants({ size: "sm" })}>
                  Go to Dashboard
                  <ArrowRight className="size-4 ml-1.5" />
                </Link>
              </div>
            ) : (
              <div className="flex items-center gap-2.5">
                <Link href="/login" className={buttonVariants({ variant: "ghost", size: "sm" })}>
                  Sign In
                </Link>
                <Link href="/register" className={buttonVariants({ size: "sm" })}>
                  Get Started
                </Link>
              </div>
            )}
          </div>

          {/* Mobile Menu Trigger */}
          <div className="flex items-center gap-2 md:hidden">
            <ThemeToggle />
            <Button 
              variant="outline" 
              size="icon" 
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
              className="size-9"
            >
              {mobileMenuOpen ? <X className="size-5" /> : <Menu className="size-5" />}
            </Button>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="border-b border-border bg-card px-4 py-4 md:hidden animate-in slide-in-from-top duration-200">
            <nav className="flex flex-col gap-3 text-sm font-medium">
              <a 
                href="#overview" 
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-md px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                Overview
              </a>
              <a 
                href="#problem" 
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-md px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                The Dilemma
              </a>
              <a 
                href="#workflow" 
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-md px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                How It Works
              </a>
              <a 
                href="#capabilities" 
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-md px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                Capabilities
              </a>
              <a 
                href="#limitations" 
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-md px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                Security & Scope
              </a>
              <div className="pt-3 border-t border-border flex flex-col gap-2">
                {isAuthenticated ? (
                  <Link 
                    href="/dashboard" 
                    onClick={() => setMobileMenuOpen(false)}
                    className={buttonVariants({ className: "w-full justify-center" })}
                  >
                    Open Dashboard
                    <ArrowRight className="size-4 ml-1.5" />
                  </Link>
                ) : (
                  <>
                    <Link 
                      href="/login" 
                      onClick={() => setMobileMenuOpen(false)}
                      className={buttonVariants({ variant: "outline", className: "w-full justify-center" })}
                    >
                      Sign In
                    </Link>
                    <Link 
                      href="/register" 
                      onClick={() => setMobileMenuOpen(false)}
                      className={buttonVariants({ className: "w-full justify-center" })}
                    >
                      Get Started
                    </Link>
                  </>
                )}
              </div>
            </nav>
          </div>
        )}
      </header>

      {/* ----------------------------------------------------------------------- */}
      {/* SECTION B: HERO SECTION                                                 */}
      {/* ----------------------------------------------------------------------- */}
      <section id="overview" className="relative overflow-hidden pt-12 pb-16 md:pt-20 md:pb-24 border-b border-border/60 bg-gradient-to-b from-muted/30 to-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col items-center text-center max-w-4xl mx-auto space-y-6">
            {/* Semantic Verification Pill */}
            <Badge variant="outline" className="gap-1.5 py-1 px-3 border-primary/30 bg-primary/5 text-primary text-xs font-medium">
              <ShieldCheck className="size-3.5 text-primary" />
              <span>Zero-Knowledge Cryptographic Supply Chain Security</span>
            </Badge>

            {/* Headline */}
            <h1 className="text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-foreground leading-[1.15]">
              Verify Software Security Claims Without Exposing Proprietary SBOMs
            </h1>

            {/* Subparagraph */}
            <p className="text-base sm:text-lg lg:text-xl text-muted-foreground max-w-2xl leading-relaxed">
              Enable software vendors to mathematically prove compliance against authoritative vulnerability databases and security policies using UltraPlonk zero-knowledge proofs—without disclosing component lists, internal versioning, or supplier trees.
            </p>

              {/* Primary & Secondary CTAs */}
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              {isAuthenticated ? (
                <Link href="/dashboard" className={buttonVariants({ size: "lg", className: "shadow-xs gap-2" })}>
                  Enter Workspace
                  <ArrowRight className="size-4" />
                </Link>
              ) : (
                <Link href="/register" className={buttonVariants({ size: "lg", className: "shadow-xs gap-2" })}>
                  Get Started Free
                  <ArrowRight className="size-4" />
                </Link>
              )}
              <a href="#workflow" className={buttonVariants({ variant: "outline", size: "lg" })}>
                Explore Architecture
              </a>
              {isAuthenticated ? (
                <Link href="/certificates" className={buttonVariants({ variant: "ghost", size: "lg", className: "text-muted-foreground hover:text-foreground" })}>
                  Certificate Registry
                  <ArrowRight className="size-3.5 ml-1.5 opacity-70" />
                </Link>
              ) : (
                <Link href="/login" className={buttonVariants({ variant: "ghost", size: "lg", className: "text-muted-foreground hover:text-foreground" })}>
                  Sign In to Verify
                  <ArrowRight className="size-3.5 ml-1.5 opacity-70" />
                </Link>
              )}
            </div>

            {/* Verification Architecture Visual Diagram */}
            <div className="w-full mt-10 rounded-2xl border border-border/80 bg-card p-5 sm:p-7 shadow-xs text-left">
              <div className="flex items-center justify-between pb-4 border-b border-border/70 mb-5">
                <div className="flex items-center gap-2">
                  <Cpu className="size-4 text-primary" />
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Verification Circuit Boundary</span>
                </div>
                <Badge variant="secondary" className="font-mono text-[11px]">Noir 0.32.0 ACIR • 2,144B UltraPlonk Proof Body</Badge>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* 1. Private Vendor Inputs */}
                <div className="rounded-xl border border-border/70 bg-muted/20 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-primary font-semibold text-xs uppercase tracking-wide">
                    <Lock className="size-3.5" />
                    <span>Private Inputs</span>
                  </div>
                  <h4 className="font-medium text-sm text-foreground">Vendor SBOM Tree</h4>
                  <p className="text-xs text-muted-foreground">CycloneDX / SPDX JSON parsed into CPE leaves and Poseidon Sparse Merkle Tree (R_SBOM).</p>
                  <div className="pt-2">
                    <Badge variant="outline" className="text-[10px] font-mono text-muted-foreground">Hidden Witness</Badge>
                  </div>
                </div>

                {/* 2. Public Commitments */}
                <div className="rounded-xl border border-border/70 bg-muted/20 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-primary font-semibold text-xs uppercase tracking-wide">
                    <Database className="size-3.5" />
                    <span>Public Inputs</span>
                  </div>
                  <h4 className="font-medium text-sm text-foreground">Authoritative State</h4>
                  <p className="text-xs text-muted-foreground">Frozen CVE Vulnerability snapshot (R_VulnDB) and canonical security policy hash (H_Policy).</p>
                  <div className="pt-2">
                    <Badge variant="info" className="text-[10px] font-mono">Public Commitments</Badge>
                  </div>
                </div>

                {/* 3. ZK Circuit */}
                <div className="rounded-xl border border-primary/40 bg-primary/5 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-primary font-semibold text-xs uppercase tracking-wide">
                    <Cpu className="size-3.5" />
                    <span>ZK Engine</span>
                  </div>
                  <h4 className="font-medium text-sm text-foreground">Noir ACIR Circuit</h4>
                  <p className="text-xs text-muted-foreground">Evaluates non-membership in zero knowledge. Protects the private witness while binding public roots and policy digests.</p>
                  <div className="pt-2">
                    <Badge variant="default" className="text-[10px] font-mono">Zero Component Disclosure</Badge>
                  </div>
                </div>

                {/* 4. Verifier Outcome */}
                <div className="rounded-xl border border-success/40 bg-success/5 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-800 dark:text-emerald-300 font-semibold text-xs uppercase tracking-wide">
                    <Award className="size-3.5" />
                    <span>Verification</span>
                  </div>
                  <h4 className="font-medium text-sm text-foreground">Automated Proof Check</h4>
                  <p className="text-xs text-muted-foreground">UltraPlonk verifier validates public-input bindings and executes automated cryptographic proof verification.</p>
                  <div className="pt-2">
                    <Badge variant="success" className="text-[10px] font-mono">Cryptographically Valid</Badge>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------------------------- */}
      {/* SECTION C: PROBLEM AND SOLUTION (THE SUPPLY CHAIN DILEMMA)              */}
      {/* ----------------------------------------------------------------------- */}
      <section id="problem" className="py-16 md:py-24 border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-3 mb-12">
            <Badge variant="secondary" className="text-xs uppercase font-semibold">The Core Dilemma</Badge>
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-foreground">
              Why Conventional Software Supply-Chain Verification Fails
            </h2>
            <p className="text-sm sm:text-base text-muted-foreground leading-relaxed">
              Modern enterprise software procurement requires verifiable assurance, yet conventional verification models force an unacceptable trade-off between proprietary privacy and security transparency.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* The Buyer Pain */}
            <Card className="flex flex-col justify-between">
              <CardHeader>
                <div className="flex size-10 items-center justify-center rounded-lg bg-warning/15 text-amber-800 dark:text-warning mb-2">
                  <Scale className="size-5" />
                </div>
                <CardTitle>Buyer Regulatory Pressure</CardTitle>
                <CardDescription>Demanding complete dependency visibility</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2.5 text-sm text-muted-foreground">
                <p>
                  Regulatory standards (such as US Executive Order 14028 and the EU Cyber Resilience Act) require buyers to verify the provenance and vulnerability status of third-party software.
                </p>
                <p>
                  However, buyers lack the means to independently audit static PDF reports or attestations without trusting vendor statements.
                </p>
              </CardContent>
            </Card>

            {/* The Vendor Pain */}
            <Card className="flex flex-col justify-between">
              <CardHeader>
                <div className="flex size-10 items-center justify-center rounded-lg bg-destructive/15 text-destructive mb-2">
                  <EyeOff className="size-5" />
                </div>
                <CardTitle>Vendor IP Exposure</CardTitle>
                <CardDescription>The risk of disclosing raw component trees</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2.5 text-sm text-muted-foreground">
                <p>
                  Delivering a raw Software Bill of Materials (SBOM) discloses proprietary architecture, proprietary library names, sub-tier vendor contracts, and exact version numbers.
                </p>
                <p>
                  In hostile hands, a disclosed SBOM provides attackers with a precise reconnaissance map of known attack surfaces.
                </p>
              </CardContent>
            </Card>

            {/* The Zero-Knowledge Solution */}
            <Card className="flex flex-col justify-between border-primary/40 bg-card shadow-xs">
              <CardHeader>
                <div className="flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary mb-2">
                  <ShieldCheck className="size-5" />
                </div>
                <CardTitle>The Zero-Knowledge Resolution</CardTitle>
                <CardDescription>Mathematical proof instead of raw disclosure</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2.5 text-sm text-muted-foreground">
                <p>
                  Zero-Knowledge Proofs (ZKPs) allow a vendor to prove: <em>&ldquo;My software components contain zero CVEs listed in approved vulnerability snapshot S under security policy P&rdquo;</em>.
                </p>
                <p>
                  The buyer independently verifies the mathematical proof without learning what components exist in the vendor&apos;s product.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------------------------- */}
      {/* SECTION D: HOW IT WORKS (THE 6-STEP VERIFICATION PIPELINE)               */}
      {/* ----------------------------------------------------------------------- */}
      <section id="workflow" className="py-16 md:py-24 border-b border-border/60 bg-muted/15">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-3 mb-14">
            <Badge variant="secondary" className="text-xs uppercase font-semibold">End-to-End Pipeline</Badge>
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-foreground">
              How Zero-Knowledge Verification Works
            </h2>
            <p className="text-sm sm:text-base text-muted-foreground leading-relaxed">
              A structured, reproducible workflow linking vendor SBOM parsing, authoritative vulnerability snapshots, deterministic security policy hashes, and native proof validation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Step 1 */}
            <div className="flex flex-col justify-between h-full rounded-xl border border-border/80 bg-card p-6 sm:p-7 shadow-2xs hover:shadow-xs hover:border-border transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <span className="font-mono text-xs font-bold text-primary px-2.5 py-1 rounded-md bg-primary/10">01</span>
                  <FileCode2 className="size-5 text-muted-foreground/80" />
                </div>
                <h3 className="font-semibold text-base sm:text-lg text-foreground tracking-tight pt-1">SBOM Canonicalization</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1 pt-1 break-words">
                  Vendor uploads a CycloneDX or SPDX JSON SBOM. The ingestion parser extracts CPE identifiers, normalizes versions, and computes Poseidon leaf hashes to build a Sparse Merkle Tree commitment (R_SBOM).
                </p>
              </div>
              <div className="pt-3.5 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                <span>Commitment</span>
                <span className="text-foreground font-medium">R_SBOM</span>
              </div>
            </div>

            {/* Step 2 */}
            <div className="flex flex-col justify-between h-full rounded-xl border border-border/80 bg-card p-6 sm:p-7 shadow-2xs hover:shadow-xs hover:border-border transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <span className="font-mono text-xs font-bold text-primary px-2.5 py-1 rounded-md bg-primary/10">02</span>
                  <Database className="size-5 text-muted-foreground/80" />
                </div>
                <h3 className="font-semibold text-base sm:text-lg text-foreground tracking-tight pt-1">Vulnerability Snapshot Freezing</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1 pt-1 break-words">
                  Authoritative CVE intelligence from trusted feeds is ingested and frozen into an immutable Merkle root snapshot (R_VulnDB). Freezing eliminates race conditions during verification.
                </p>
              </div>
              <div className="pt-3.5 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                <span>Snapshot Root</span>
                <span className="text-foreground font-medium">R_VulnDB</span>
              </div>
            </div>

            {/* Step 3 */}
            <div className="flex flex-col justify-between h-full rounded-xl border border-border/80 bg-card p-6 sm:p-7 shadow-2xs hover:shadow-xs hover:border-border transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <span className="font-mono text-xs font-bold text-primary px-2.5 py-1 rounded-md bg-primary/10">03</span>
                  <Scale className="size-5 text-muted-foreground/80" />
                </div>
                <h3 className="font-semibold text-base sm:text-lg text-foreground tracking-tight pt-1">Deterministic Policy Binding</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1 pt-1 break-words">
                  Security rules (e.g. CVSS severity thresholds, banned CVE lists, package exemptions) are canonicalized into a deterministic SHA-256 policy digest (H_Policy).
                </p>
              </div>
              <div className="pt-3.5 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                <span>Policy Digest</span>
                <span className="text-foreground font-medium">H_Policy</span>
              </div>
            </div>

            {/* Step 4 */}
            <div className="flex flex-col justify-between h-full rounded-xl border border-border/80 bg-card p-6 sm:p-7 shadow-2xs hover:shadow-xs hover:border-border transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <span className="font-mono text-xs font-bold text-primary px-2.5 py-1 rounded-md bg-primary/10">04</span>
                  <Cpu className="size-5 text-muted-foreground/80" />
                </div>
                <h3 className="font-semibold text-base sm:text-lg text-foreground tracking-tight pt-1">ZK Proof Generation</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1 pt-1 break-words">
                  The ZKP service executes Noir 0.32.0 ACIR circuits with Barretenberg native runtimes, generating a compact 2,144-byte UltraPlonk proof body (excluding public inputs) that non-membership holds without disclosing witness leaves.
                </p>
              </div>
              <div className="pt-3.5 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                <span>Proof Body</span>
                <span className="text-foreground font-medium">2,144 Bytes</span>
              </div>
            </div>

            {/* Step 5 */}
            <div className="flex flex-col justify-between h-full rounded-xl border border-border/80 bg-card p-6 sm:p-7 shadow-2xs hover:shadow-xs hover:border-border transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <span className="font-mono text-xs font-bold text-primary px-2.5 py-1 rounded-md bg-primary/10">05</span>
                  <CheckCircle2 className="size-5 text-muted-foreground/80" />
                </div>
                <h3 className="font-semibold text-base sm:text-lg text-foreground tracking-tight pt-1">Cryptographic Verification</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1 pt-1 break-words">
                  The verifier checks public-input bindings (R_SBOM, R_VulnDB, H_Policy) against the UltraPlonk proof body for the recorded proof job; performance depends on the proof package and verification workload. Detached third-party package verification is planned for Stage D6.
                </p>
              </div>
              <div className="pt-3.5 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                <span>Public Bindings</span>
                <span className="text-foreground font-medium">R_SBOM, R_VulnDB, H_Policy</span>
              </div>
            </div>

            {/* Step 6 */}
            <div className="flex flex-col justify-between h-full rounded-xl border border-border/80 bg-card p-6 sm:p-7 shadow-2xs hover:shadow-xs hover:border-border transition-all">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <span className="font-mono text-xs font-bold text-primary px-2.5 py-1 rounded-md bg-primary/10">06</span>
                  <Award className="size-5 text-muted-foreground/80" />
                </div>
                <h3 className="font-semibold text-base sm:text-lg text-foreground tracking-tight pt-1">Tamper-Evident Certificate Issuance</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1 pt-1 break-words">
                  A tamper-evident cryptographic certificate record is generated with a durable UUID, timestamp, public commitments, and verification status, publicly verifiable by ID and revocable via administrator controls.
                </p>
              </div>
              <div className="pt-3.5 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] font-mono text-muted-foreground">
                <span>Verification Output</span>
                <span className="text-foreground font-medium">Tamper-Evident Certificate</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------------------------- */}
      {/* SECTION E: VERIFIED PRODUCT CAPABILITIES                                 */}
      {/* ----------------------------------------------------------------------- */}
      <section id="capabilities" className="py-16 md:py-24 border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-3 mb-14">
            <Badge variant="secondary" className="text-xs uppercase font-semibold">System Capabilities</Badge>
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-foreground">
              Built on Authoritative Security Standards
            </h2>
            <p className="text-sm sm:text-base text-muted-foreground leading-relaxed">
              Every capability is backed by inspected repository code, multi-tenant database constraints, and cryptographic verifier contracts.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Capability 1 */}
            <div className="flex flex-col p-5 rounded-xl border border-border/70 bg-card space-y-2.5">
              <div className="flex items-center gap-2 font-semibold text-foreground text-sm">
                <FileText className="size-4 text-primary" />
                <span>Multi-Tenant SBOM Repository</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Strict multi-tenant application isolation enforcing vendor ownership. Raw component files remain bounded and isolated from cross-tenant visibility.
              </p>
              <div className="mt-auto pt-2">
                <Badge variant="secondary" className="text-[10px]">CycloneDX / SPDX Standard</Badge>
              </div>
            </div>

            {/* Capability 2 */}
            <div className="flex flex-col p-5 rounded-xl border border-border/70 bg-card space-y-2.5">
              <div className="flex items-center gap-2 font-semibold text-foreground text-sm">
                <Database className="size-4 text-primary" />
                <span>Vulnerability Intelligence Lifecycle</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Ingestion delimited by the <code className="text-foreground font-mono">trusted_importer</code> role. Explicit four-state lifecycle (<code className="font-mono">pending</code> &rarr; <code className="font-mono">approved</code> &rarr; <code className="font-mono">frozen</code> &rarr; <code className="font-mono">revoked</code>) for auditability.
              </p>
              <div className="mt-auto pt-2">
                <Badge variant="secondary" className="text-[10px]">Separation of Duties</Badge>
              </div>
            </div>

            {/* Capability 3 */}
            <div className="flex flex-col p-5 rounded-xl border border-border/70 bg-card space-y-2.5">
              <div className="flex items-center gap-2 font-semibold text-foreground text-sm">
                <Scale className="size-4 text-primary" />
                <span>Deterministic Policy Engine</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Canonical JSON normalization ensures reproducible SHA-256 policy digests regardless of client serialization, whitespace, or dictionary ordering.
              </p>
              <div className="mt-auto pt-2">
                <Badge variant="secondary" className="text-[10px]">Deterministic Hashes</Badge>
              </div>
            </div>

            {/* Capability 4 */}
            <div className="flex flex-col p-5 rounded-xl border border-border/70 bg-card space-y-2.5">
              <div className="flex items-center gap-2 font-semibold text-foreground text-sm">
                <Cpu className="size-4 text-primary" />
                <span>Asynchronous Proving Worker</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Background execution queue handling UltraPlonk witness compilation and proof generation with persistent recovery locks and polling status updates.
              </p>
              <div className="mt-auto pt-2">
                <Badge variant="secondary" className="text-[10px]">Barretenberg 0.46.1</Badge>
              </div>
            </div>

            {/* Capability 5 */}
            <div className="flex flex-col p-5 rounded-xl border border-border/70 bg-card space-y-2.5">
              <div className="flex items-center gap-2 font-semibold text-foreground text-sm">
                <KeyRound className="size-4 text-primary" />
                <span>In-Memory Privacy Architecture</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Zero persistent browser storage for session tokens. Bearer credentials are kept in memory to eliminate local storage leakage and cross-site extraction.
              </p>
              <div className="mt-auto pt-2">
                <Badge variant="secondary" className="text-[10px]">No LocalStorage</Badge>
              </div>
            </div>

            {/* Capability 6 */}
            <div className="flex flex-col p-5 rounded-xl border border-border/70 bg-card space-y-2.5">
              <div className="flex items-center gap-2 font-semibold text-foreground text-sm">
                <Award className="size-4 text-primary" />
                <span>Public Certificate Validation</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Public certificate validation routes (<code className="font-mono text-foreground">/certificates/[id]</code>) allow external parties to validate issued certificates; detached proof-package verification is planned for Stage D6.
              </p>
              <div className="mt-auto pt-2">
                <Badge variant="secondary" className="text-[10px]">Public Validation</Badge>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------------------------- */}
      {/* SECTION F: SECURITY INVARIANTS & HONEST LIMITATIONS                     */}
      {/* ----------------------------------------------------------------------- */}
      <section id="limitations" className="py-16 md:py-24 border-b border-border/60 bg-muted/10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-3 mb-12">
            <Badge variant="outline" className="text-xs uppercase font-semibold border-amber-500/30 text-amber-800 dark:text-amber-300">
              Honest Engineering Boundaries
            </Badge>
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-foreground">
              Security Guarantees & Operational Limitations
            </h2>
            <p className="text-sm sm:text-base text-muted-foreground leading-relaxed">
              Credible cryptography requires transparent boundaries. Here is exactly what the system proves and what remains outside the cryptographic proof.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="rounded-xl border border-border/80 bg-card p-6 space-y-3">
              <div className="flex items-center gap-2 font-semibold text-sm text-foreground">
                <CheckCircle2 className="size-4 text-success" />
                <span>What Is Proven & Exposed</span>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                A valid UltraPlonk proof establishes that component CPEs committed in R_SBOM match zero CVEs in R_VulnDB under H_Policy. While the private witness is protected from component disclosure, public commitments and verification metadata remain visible.
              </p>
            </div>

            <div className="rounded-xl border border-border/80 bg-card p-6 space-y-3">
              <div className="flex items-center gap-2 font-semibold text-sm text-foreground">
                <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" />
                <span>Zero-Day Limitations</span>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                The proof does <strong>NOT</strong> prove that software is free from unknown zero-day vulnerabilities or CVEs outside the frozen database snapshot. Verification is strictly bounded by snapshot intelligence.
              </p>
            </div>

            <div className="rounded-xl border border-border/80 bg-card p-6 space-y-3">
              <div className="flex items-center gap-2 font-semibold text-sm text-foreground">
                <Layers className="size-4 text-primary" />
                <span>SBOM Generation Integrity</span>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Zero-knowledge verification operates on the submitted SBOM artifact. Ensuring that the SBOM completely and truthfully reflects the compiled binary remains the vendor&apos;s build-pipeline responsibility.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------------------------- */}
      {/* SECTION G: FINAL CALL TO ACTION AND FOOTER                               */}
      {/* ----------------------------------------------------------------------- */}
      <section className="py-16 md:py-20 bg-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-2xl border border-primary/30 bg-gradient-to-r from-primary/5 via-card to-primary/5 p-8 sm:p-12 text-center max-w-4xl mx-auto space-y-6">
            <Badge variant="secondary" className="text-xs uppercase font-semibold">Local Verification Node</Badge>
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-foreground">
              Ready to Explore Zero-Knowledge Supply Chain Verification?
            </h2>
            <p className="text-sm sm:text-base text-muted-foreground max-w-xl mx-auto leading-relaxed">
              Access the bounded local environment to manage private SBOMs, inspect frozen vulnerability feeds, define security policies, and verify cryptographic certificates.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              {isAuthenticated ? (
                <>
                  <Link href="/dashboard" className={buttonVariants({ size: "lg" })}>
                    Go to Dashboard
                    <ArrowRight className="size-4 ml-1.5" />
                  </Link>
                  <Link href="/certificates" className={buttonVariants({ variant: "outline", size: "lg" })}>
                    Inspect Certificates
                  </Link>
                </>
              ) : (
                <>
                  <Link href="/register" className={buttonVariants({ size: "lg" })}>
                    Create Account
                  </Link>
                  <Link href="/login" className={buttonVariants({ variant: "outline", size: "lg" })}>
                    Sign In
                  </Link>
                  <Link href="/login" className={buttonVariants({ variant: "ghost", size: "lg", className: "text-muted-foreground hover:text-foreground" })}>
                    Sign In for Certificates
                    <ArrowRight className="size-3.5 ml-1.5 opacity-70" />
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Restrained Footer */}
      <footer className="border-t border-border/80 bg-card py-12 text-sm text-muted-foreground">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-2 font-semibold text-foreground">
              <ShieldCheck className="size-5 text-primary" />
              <span>ZK-SBOM Verify</span>
              <span className="text-xs font-normal text-muted-foreground">| Privacy-Preserving Supply Chain Security</span>
            </div>
            <div className="flex flex-wrap items-center gap-5 text-xs text-muted-foreground">
              <a href="#overview" className="hover:text-foreground">Overview</a>
              <a href="#problem" className="hover:text-foreground">The Dilemma</a>
              <a href="#workflow" className="hover:text-foreground">Architecture</a>
              <a href="#capabilities" className="hover:text-foreground">Capabilities</a>
              <a href="#limitations" className="hover:text-foreground">Security Boundaries</a>
              {isAuthenticated ? (
                <Link href="/certificates" className="hover:text-foreground">Certificates</Link>
              ) : (
                <Link href="/login" className="hover:text-foreground">Certificates (Sign In)</Link>
              )}
              {!isAuthenticated && (
                <Link href="/login" className="hover:text-foreground">Sign In</Link>
              )}
            </div>
          </div>

          <div className="border-t border-border/60 pt-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-center sm:text-left">
            <p className="leading-relaxed">
              Cryptographic Engine: Noir 0.32.0 ACIR &bull; Barretenberg 0.46.1 UltraPlonk &bull; Poseidon Sponge (t=2, t=3)
            </p>
            <p className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
              Operating Mode: LOCAL-ONLY &bull; Port 5433
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
