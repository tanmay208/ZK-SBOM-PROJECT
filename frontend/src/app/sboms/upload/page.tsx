"use client";

import * as React from "react";
import { useState, useCallback } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { sbomService } from "@/api/services/sbomService";
import { applicationService } from "@/api/services/applicationService";
import { ApplicationResponse, SBOMUploadResponse } from "@/api/types";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { StatusPill } from "@/components/ui/status-pill";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ApiError } from "@/api/errors";
import { useAuth } from "@/auth/AuthProvider";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  AlertCircle,
  CheckCircle2,
  FileUp,
  Loader2,
  FileCode,
  ShieldCheck,
  Lock,
  ArrowRight,
  RotateCw,
  Copy,
  Check,
  UploadCloud,
  FileCheck2,
  X
} from "lucide-react";

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

// Helper to format bytes
function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

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

function SbomUploadForm() {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const [file, setFile] = useState<File | null>(null);
  const [appMode, setAppMode] = useState<"select" | "create">("select");
  const [selectedAppId, setSelectedAppId] = useState<string>("");
  const [customVendor, setCustomVendor] = useState<string | null>(null);
  const vendorName = customVendor !== null ? customVendor : (user?.username || "");
  const [newAppName, setNewAppName] = useState("");
  const [newAppVendor, setNewAppVendor] = useState(user?.username || "");
  const [newAppDescription, setNewAppDescription] = useState("");
  const [createdApp, setCreatedApp] = useState<ApplicationResponse | null>(null);
  const [isCreatingApp, setIsCreatingApp] = useState(false);

  const [isDragging, setIsDragging] = useState(false);
  const [jsonValidated, setJsonValidated] = useState<boolean | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [successData, setSuccessData] = useState<SBOMUploadResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const {
    data: applications,
    isLoading: isLoadingApps,
    error: appsError,
  } = useQuery({
    queryKey: ["applications", "active"],
    queryFn: () => applicationService.list({ include_archived: false }),
  });

  // When user has zero active applications, gracefully default to create mode without effect
  const hasNoActiveApps = Boolean(!isLoadingApps && applications && applications.length === 0);
  const effectiveAppMode = hasNoActiveApps ? "create" : appMode;

  const handleAppSelect = (id: string) => {
    setSelectedAppId(id);
    const chosen = applications?.find((a) => a.id === id);
    if (chosen) {
      setCustomVendor(chosen.vendor);
    } else {
      setCustomVendor(null);
    }
  };

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // Fallback
    }
  };

  const uploadMutation = useMutation({
    mutationFn: async ({
      appName,
      vendor,
      format,
      content,
      filename,
    }: {
      appName: string;
      vendor: string;
      format: string;
      content: string;
      filename: string;
    }) => {
      return sbomService.upload(appName, vendor, format, content, filename);
    },
    onSuccess: (data) => {
      setSuccessData(data);
      queryClient.invalidateQueries({ queryKey: ["sboms"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
    },
  });

  const validateAndSetFile = useCallback(async (selected: File) => {
    setValidationError(null);
    setSuccessData(null);
    setJsonValidated(null);

    // Size validation
    if (selected.size > MAX_FILE_SIZE_BYTES) {
      setValidationError("File exceeds maximum allowed size of 10 MB.");
      setFile(null);
      return;
    }

    // Extension validation
    if (!selected.name.toLowerCase().endsWith(".json")) {
      setValidationError("Invalid file extension. Only CycloneDX JSON files are accepted.");
      setFile(null);
      return;
    }

    // Preliminary JSON structure validation
    try {
      const text = await selected.text();
      if (!text.trim()) {
        setValidationError("The selected file is empty.");
        setFile(null);
        return;
      }
      JSON.parse(text);
      setJsonValidated(true);
      setFile(selected);
    } catch {
      setValidationError("File contains malformed JSON syntax. Please verify the document format.");
      setFile(null);
      setJsonValidated(false);
    }
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected) {
      validateAndSetFile(selected);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files?.[0];
    if (droppedFile) {
      validateAndSetFile(droppedFile);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    // Prevent duplicate submission while pending
    if (uploadMutation.isPending || isCreatingApp) {
      return;
    }

    if (!file) {
      setValidationError("Please select a CycloneDX JSON file to upload.");
      return;
    }

    let effectiveAppName = "";
    let effectiveVendor = "";

    if (effectiveAppMode === "select") {
      if (!selectedAppId) {
        setValidationError("Please select an active application from the dropdown, or choose 'Register New'.");
        return;
      }
      const chosen = applications?.find((a) => a.id === selectedAppId);
      if (!chosen) {
        setValidationError("The selected application could not be verified. Please re-select.");
        return;
      }
      effectiveAppName = chosen.name;
      effectiveVendor = chosen.vendor;
    } else {
      // Inline application registration mode
      const trimmedApp = newAppName.trim();
      if (!trimmedApp) {
        setValidationError("Application name is required (1 to 255 characters).");
        return;
      }
      if (trimmedApp.length > 255) {
        setValidationError("Application name must not exceed 255 characters.");
        return;
      }
      if (hasControlCharacters(trimmedApp)) {
        setValidationError("Application name contains disallowed control characters.");
        return;
      }

      const trimmedVendor = (newAppVendor || user?.username || "").trim();
      if (!trimmedVendor) {
        setValidationError("Vendor identity is required.");
        return;
      }
      if (trimmedVendor.length > 255) {
        setValidationError("Vendor name must not exceed 255 characters.");
        return;
      }
      if (hasControlCharacters(trimmedVendor)) {
        setValidationError("Vendor name contains disallowed control characters.");
        return;
      }

      // Check if already created in an immediate prior attempt (e.g. upload failed)
      if (createdApp && createdApp.name === trimmedApp && createdApp.vendor === trimmedVendor) {
        effectiveAppName = createdApp.name;
        effectiveVendor = createdApp.vendor;
      } else {
        try {
          setIsCreatingApp(true);
          const newApp = await applicationService.create({
            name: trimmedApp,
            vendor: trimmedVendor,
            description: newAppDescription.trim() || undefined,
          });
          setCreatedApp(newApp);
          effectiveAppName = newApp.name;
          effectiveVendor = newApp.vendor;
          queryClient.invalidateQueries({ queryKey: ["applications"] });
        } catch (err) {
          setIsCreatingApp(false);
          const msg = err instanceof ApiError ? err.message : "Failed to register application.";
          setValidationError(msg);
          return;
        } finally {
          setIsCreatingApp(false);
        }
      }
    }

    try {
      const content = await file.text();

      // Final JSON check before sending
      try {
        JSON.parse(content);
      } catch {
        setValidationError("The file could not be parsed as valid JSON.");
        return;
      }

      uploadMutation.mutate({
        appName: effectiveAppName,
        vendor: effectiveVendor,
        format: "CycloneDX",
        content,
        filename: file.name,
      });
    } catch {
      setValidationError("Failed to read file from disk. Please re-select the file.");
    }
  };

  const resetForm = () => {
    setSuccessData(null);
    setFile(null);
    setAppMode("select");
    setCustomVendor(null);
    setSelectedAppId("");
    setNewAppName("");
    setNewAppVendor(user?.username || "");
    setNewAppDescription("");
    setCreatedApp(null);
    setJsonValidated(null);
    setValidationError(null);
    uploadMutation.reset();
  };

  // --------------------------------------------------------------------------
  // Success Confirmation View
  // --------------------------------------------------------------------------
  if (successData) {
    return (
      <div className="max-w-3xl mx-auto space-y-6">
        <PageHeader
          title="SBOM Ingested & Committed"
          description="Cryptographic commitment pipeline successfully processed the Software Bill of Materials."
          badge={
            <Badge variant="outline" className="font-mono text-xs text-emerald-600 border-emerald-300">
              Pipeline Committed
            </Badge>
          }
        />

        <Card className="border-emerald-500/30 bg-card shadow-sm">
          <CardHeader className="text-center pb-2">
            <div className="mx-auto mb-3 flex size-12 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 ring-4 ring-emerald-500/10">
              <CheckCircle2 className="size-6" />
            </div>
            <CardTitle className="text-xl font-bold">Commitment Computed Successfully</CardTitle>
            <CardDescription className="text-xs max-w-md mx-auto">
              The Poseidon Sparse Merkle Tree (R_SBOM) root has been persisted. Your raw components remain confidential within the vendor boundary.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4 pt-4">
            {/* Metadata Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                  Upload ID
                </span>
                <div className="flex items-center justify-between mt-1">
                  <p className="font-mono text-foreground break-all">{successData.upload_id}</p>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-6 shrink-0 ml-1 text-muted-foreground hover:text-foreground"
                    onClick={() => copyToClipboard(successData.upload_id, "upload-id")}
                  >
                    {copiedKey === "upload-id" ? (
                      <Check className="size-3 text-emerald-500" />
                    ) : (
                      <Copy className="size-3" />
                    )}
                  </Button>
                </div>
              </div>

              <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                  Application ID
                </span>
                <div className="flex items-center justify-between mt-1">
                  <p className="font-mono text-foreground break-all">{successData.application_id}</p>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-6 shrink-0 ml-1 text-muted-foreground hover:text-foreground"
                    onClick={() => copyToClipboard(successData.application_id, "app-id")}
                  >
                    {copiedKey === "app-id" ? (
                      <Check className="size-3 text-emerald-500" />
                    ) : (
                      <Copy className="size-3" />
                    )}
                  </Button>
                </div>
              </div>

              <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                  Status & Components
                </span>
                <div className="flex items-center gap-2 mt-1">
                  <StatusPill status={successData.status} />
                  <span className="font-medium text-foreground">
                    {successData.component_count ?? 0} components verified
                  </span>
                </div>
              </div>

              <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                  Format
                </span>
                <p className="font-medium text-foreground mt-1">
                  {successData.format} ({successData.filename || "payload.json"})
                </p>
              </div>
            </div>

            {/* Poseidon Merkle Root Hash */}
            <div className="rounded-lg bg-muted/60 p-3.5 border border-border/70 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">
                  Poseidon Merkle Root (R_SBOM)
                </span>
                {successData.sbom_root && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-5 text-[10px] px-1.5 gap-1 text-primary"
                    onClick={() => copyToClipboard(successData.sbom_root!, "root-hash")}
                  >
                    {copiedKey === "root-hash" ? (
                      <>
                        <Check className="size-2.5 text-emerald-500" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="size-2.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </Button>
                )}
              </div>
              <p className="font-mono text-[11px] text-foreground mt-1.5 break-all select-all bg-background/90 p-2.5 rounded border border-border/50">
                {successData.sbom_root || "Root calculation committed"}
              </p>
            </div>

            {/* Cryptographic Boundary Invariant */}
            <div className="flex items-start gap-2.5 rounded-lg bg-primary/5 p-3 text-xs text-muted-foreground border border-primary/10">
              <ShieldCheck className="size-4 text-primary shrink-0 mt-0.5" />
              <p className="leading-relaxed">
                <strong className="text-foreground">Zero Component Disclosure:</strong> This Merkle commitment (R_SBOM) can now be bound to a policy and vulnerability database snapshot to generate an UltraPlonk zero-knowledge proof without disclosing confidential dependencies.
              </p>
            </div>
          </CardContent>

          <CardFooter className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-border/60 p-5 bg-muted/20">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Link href="/sboms" className={buttonVariants({ variant: "outline", size: "sm" })}>
                Return to Workspace
              </Link>
              <Button variant="ghost" size="sm" onClick={resetForm} className="gap-1.5">
                <RotateCw className="size-3.5" />
                Upload Another
              </Button>
            </div>

            <Link
              href={`/proofs/generate?sbomId=${encodeURIComponent(successData.upload_id)}`}
              className={cn(buttonVariants({ size: "sm" }), "w-full sm:w-auto gap-1.5")}
            >
              <span>Generate ZK Proof</span>
              <ArrowRight className="size-4" />
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  // --------------------------------------------------------------------------
  // Intake Form View
  // --------------------------------------------------------------------------
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header with Breadcrumb Back link */}
      <PageHeader
        title="Upload SBOM"
        description="Ingest a CycloneDX JSON document to generate cryptographic supply-chain commitments."
        badge={
          <Badge variant="outline" className="font-mono text-xs text-muted-foreground">
            CycloneDX 1.4+
          </Badge>
        }
        actions={
          <Link href="/sboms" className={buttonVariants({ variant: "outline", size: "sm" })}>
            Back to SBOMs
          </Link>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Upload Form Card (2 Cols) */}
        <Card className="lg:col-span-2 shadow-xs">
          <form onSubmit={handleSubmit}>
            <CardHeader>
              <CardTitle className="text-lg font-semibold">Intake Parameters</CardTitle>
              <CardDescription className="text-xs">
                Provide the application metadata and select your CycloneDX JSON bill of materials.
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-5">
              {/* Client Validation Error Alert */}
              {validationError && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Validation Notice</AlertTitle>
                  <AlertDescription className="text-xs mt-0.5">{validationError}</AlertDescription>
                </Alert>
              )}

              {/* Server-Side Upload Error Alert */}
              {uploadMutation.error && (
                <Alert variant="destructive">
                  <AlertCircle className="size-4" />
                  <AlertTitle>Upload Failed</AlertTitle>
                  <AlertDescription className="text-xs mt-0.5">
                    {uploadMutation.error instanceof ApiError
                      ? uploadMutation.error.message
                      : "The server encountered an error while processing the SBOM payload."}
                  </AlertDescription>
                </Alert>
              )}

              {/* Application Selection & Inline Creation Section */}
              <div className="space-y-3 rounded-lg border border-border/70 p-3.5 bg-muted/15">
                <div className="flex items-center justify-between">
                  <Label className="text-xs font-semibold">
                    Target Application <span className="text-destructive">*</span>
                  </Label>
                  <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-md border border-border/50 text-[11px]">
                    <button
                      type="button"
                      onClick={() => setAppMode("select")}
                      disabled={uploadMutation.isPending || isCreatingApp || hasNoActiveApps}
                      className={cn(
                        "px-2 py-0.5 rounded transition-colors font-medium",
                        effectiveAppMode === "select"
                          ? "bg-background text-foreground shadow-xs"
                          : "text-muted-foreground hover:text-foreground",
                        hasNoActiveApps && "opacity-50 cursor-not-allowed"
                      )}
                    >
                      Select Existing
                    </button>
                    <button
                      type="button"
                      onClick={() => setAppMode("create")}
                      disabled={uploadMutation.isPending || isCreatingApp}
                      className={cn(
                        "px-2 py-0.5 rounded transition-colors font-medium",
                        effectiveAppMode === "create"
                          ? "bg-background text-foreground shadow-xs"
                          : "text-muted-foreground hover:text-foreground"
                      )}
                    >
                      + Register New
                    </button>
                  </div>
                </div>

                {effectiveAppMode === "select" ? (
                  <div className="space-y-2">
                    {isLoadingApps ? (
                      <Skeleton className="h-8 w-full" />
                    ) : appsError ? (
                      <Alert variant="destructive" className="py-2 text-xs">
                        <AlertCircle className="size-3.5" />
                        <AlertDescription>
                          Failed to load existing applications. Switch to &quot;Register New&quot; or reload.
                        </AlertDescription>
                      </Alert>
                    ) : applications && applications.length === 0 ? (
                      <div className="rounded-md border border-dashed border-border/80 p-3 text-center">
                        <p className="text-xs text-muted-foreground">No active applications found.</p>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          className="mt-2 h-7 text-xs"
                          onClick={() => setAppMode("create")}
                        >
                          Register New Application
                        </Button>
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        <select
                          id="applicationSelect"
                          value={selectedAppId}
                          onChange={(e) => handleAppSelect(e.target.value)}
                          disabled={uploadMutation.isPending || isCreatingApp}
                          className="w-full h-8 px-2.5 text-xs rounded-md border border-input bg-background text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                        >
                          <option value="">-- Choose an active application --</option>
                          {applications?.map((app) => (
                            <option key={app.id} value={app.id}>
                              {app.name} ({app.vendor})
                            </option>
                          ))}
                        </select>
                        {selectedAppId && (
                          <p className="text-[11px] text-muted-foreground">
                            Vendor bound to: <span className="font-medium text-foreground">{vendorName}</span>
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  /* Inline Registration Form */
                  <div className="space-y-3 pt-1">
                    <div className="space-y-1.5">
                      <Label htmlFor="inlineAppName" className="text-xs font-semibold">
                        New Application Name <span className="text-destructive">*</span>
                      </Label>
                      <Input
                        id="inlineAppName"
                        placeholder="e.g., identity-service or payment-gateway"
                        value={newAppName}
                        onChange={(e) => {
                          setNewAppName(e.target.value);
                          setCreatedApp(null);
                        }}
                        disabled={uploadMutation.isPending || isCreatingApp}
                        maxLength={255}
                        className="text-xs"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <Label htmlFor="inlineVendorName" className="text-xs font-semibold">
                        Vendor Organization <span className="text-destructive">*</span>
                      </Label>
                      <Input
                        id="inlineVendorName"
                        value={newAppVendor}
                        onChange={(e) => {
                          setNewAppVendor(e.target.value);
                          setCreatedApp(null);
                        }}
                        disabled={user?.role !== "admin" || uploadMutation.isPending || isCreatingApp}
                        maxLength={255}
                        className="text-xs bg-muted/30"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <Label htmlFor="inlineAppDesc" className="text-xs font-semibold">
                        Description (Optional)
                      </Label>
                      <Input
                        id="inlineAppDesc"
                        placeholder="Optional description"
                        value={newAppDescription}
                        onChange={(e) => {
                          setNewAppDescription(e.target.value);
                          setCreatedApp(null);
                        }}
                        disabled={uploadMutation.isPending || isCreatingApp}
                        maxLength={2000}
                        className="text-xs"
                      />
                    </div>

                    {createdApp && (
                      <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
                        ✓ Registered application &quot;{createdApp.name}&quot; (ready for SBOM upload)
                      </p>
                    )}
                  </div>
                )}
              </div>

              {/* Format Field (Locked to CycloneDX) */}
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold">Accepted Format</Label>
                <div className="flex items-center gap-2">
                  <Input value="CycloneDX JSON (Syft compatible)" disabled className="text-xs bg-muted/40 font-mono" />
                  <Badge variant="secondary" className="text-xs shrink-0 font-medium">
                    Enforced
                  </Badge>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Only CycloneDX JSON format is accepted at this stage of the cryptographic pipeline.
                </p>
              </div>

              {/* Drag & Drop File Upload Zone */}
              <div className="space-y-2">
                <Label className="text-xs font-semibold">
                  SBOM Document (.json) <span className="text-destructive">*</span>
                </Label>

                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={cn(
                    "relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center transition-colors cursor-pointer",
                    isDragging
                      ? "border-primary bg-primary/5"
                      : "border-border/80 hover:border-primary/50 bg-card/50",
                    uploadMutation.isPending && "pointer-events-none opacity-60"
                  )}
                  onClick={() => document.getElementById("sbom-file-input")?.click()}
                >
                  <input
                    id="sbom-file-input"
                    type="file"
                    accept=".json,application/json"
                    onChange={handleFileChange}
                    disabled={uploadMutation.isPending}
                    className="sr-only"
                  />

                  {file ? (
                    <div className="flex flex-col items-center gap-2">
                      <div className="flex size-11 items-center justify-center rounded-full bg-primary/10 text-primary">
                        <FileCheck2 className="size-5" />
                      </div>
                      <div className="text-center">
                        <p className="text-xs font-medium text-foreground truncate max-w-xs">{file.name}</p>
                        <p className="text-[11px] text-muted-foreground">{formatFileSize(file.size)}</p>
                      </div>
                      {jsonValidated && (
                        <Badge variant="success" className="text-[10px] px-2 py-0.5 mt-1 gap-1">
                          <Check className="size-2.5" />
                          <span>Valid JSON Syntax</span>
                        </Badge>
                      )}
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="mt-2 h-7 text-xs text-muted-foreground hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          setFile(null);
                          setJsonValidated(null);
                        }}
                      >
                        <X className="size-3 mr-1" />
                        Remove File
                      </Button>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-2">
                      <div className="flex size-11 items-center justify-center rounded-full bg-muted text-muted-foreground">
                        <UploadCloud className="size-5" />
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs font-medium text-foreground">
                          Drop your CycloneDX JSON file here, or <span className="text-primary underline">browse</span>
                        </p>
                        <p className="text-[11px] text-muted-foreground">
                          Maximum file size: 10 MB. Serialized UTF-8 JSON.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>

            <CardFooter className="flex items-center justify-between border-t border-border/60 p-4 bg-muted/10">
              <Link
                href="/sboms"
                className={cn(
                  buttonVariants({ variant: "ghost", size: "sm" }),
                  uploadMutation.isPending && "pointer-events-none opacity-50"
                )}
              >
                Cancel
              </Link>

              <Button
                type="submit"
                size="sm"
                disabled={
                  uploadMutation.isPending ||
                  isCreatingApp ||
                  !file ||
                  (effectiveAppMode === "select" ? !selectedAppId : !newAppName.trim())
                }
                className="gap-2"
              >
                {isCreatingApp ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    <span>Registering Application...</span>
                  </>
                ) : uploadMutation.isPending ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    <span>Computing Commitment...</span>
                  </>
                ) : (
                  <>
                    <FileUp className="size-4" />
                    <span>Commit SBOM</span>
                  </>
                )}
              </Button>
            </CardFooter>
          </form>
        </Card>

        {/* Informational & Security Sidebar (1 Col) */}
        <div className="space-y-4">
          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-primary" />
                <CardTitle className="text-sm font-semibold">Zero Component Disclosure</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-muted-foreground text-[11px] leading-relaxed">
              <p>
                The backend intake pipeline normalizes component identifiers into canonical PURLs, calculates Poseidon hashes, and builds a sparse Merkle tree.
              </p>
              <p>
                The resulting root hash (R_SBOM) is the only public commitment published. Component names, versions, and dependencies remain strictly confidential.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Lock className="size-4 text-emerald-600 dark:text-emerald-400" />
                <CardTitle className="text-sm font-semibold">In-Memory Privacy</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-muted-foreground text-[11px] leading-relaxed">
              <p>
                Session authentication tokens are strictly held in memory. Neither your raw SBOM content nor security tokens are stored in browser localStorage or cookies.
              </p>
              <p>
                Closing or refreshing your session immediately purges client-side buffers.
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/60 border-border/70 text-xs">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <FileCode className="size-4 text-purple-600 dark:text-purple-400" />
                <CardTitle className="text-sm font-semibold">Intake Specifications</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="text-muted-foreground text-[11px] space-y-1.5">
              <div className="flex justify-between border-b border-border/40 pb-1">
                <span>Standard</span>
                <span className="font-medium text-foreground">CycloneDX JSON</span>
              </div>
              <div className="flex justify-between border-b border-border/40 pb-1">
                <span>Max Payload</span>
                <span className="font-medium text-foreground">10 MB</span>
              </div>
              <div className="flex justify-between border-b border-border/40 pb-1">
                <span>Tree Construction</span>
                <span className="font-medium text-foreground">Poseidon SMT ($t=3$)</span>
              </div>
              <div className="flex justify-between pt-0.5">
                <span>Proof Generation</span>
                <span className="font-medium text-foreground">UltraPlonk 2,144 B</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function SbomUploadPage() {
  return (
    <RouteGuard allowedRoles={["vendor", "admin"]}>
      <SbomUploadForm />
    </RouteGuard>
  );
}
