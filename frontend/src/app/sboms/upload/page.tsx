"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { sbomService } from "@/api/services/sbomService";
import { RouteGuard } from "@/auth/RouteGuard";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, CheckCircle2, FileUp, Loader2 } from "lucide-react";
import { ApiError } from "@/api/errors";
import Link from "next/link";
import { useAuth } from "@/auth/AuthProvider";

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

function SbomUploadForm() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  
  const [file, setFile] = useState<File | null>(null);
  const [applicationName, setApplicationName] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [successId, setSuccessId] = useState<string | null>(null);

  const uploadMutation = useMutation({
    mutationFn: async ({
      applicationName,
      vendor,
      format,
      content,
      filename
    }: {
      applicationName: string,
      vendor: string,
      format: string,
      content: string,
      filename: string
    }) => {
      return sbomService.upload(applicationName, vendor, format, content, filename);
    },
    onSuccess: (data) => {
      setSuccessId(data.upload_id);
      queryClient.invalidateQueries({ queryKey: ["sboms"] });
    },
    onError: () => {
      // Allow the alert rendering to handle this
    }
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    setValidationError(null);
    setSuccessId(null);
    
    if (!selected) {
      setFile(null);
      return;
    }

    if (selected.size > MAX_FILE_SIZE_BYTES) {
      setValidationError(`File is too large. Maximum size is 10 MB.`);
      setFile(null);
      e.target.value = '';
      return;
    }

    if (!selected.name.endsWith('.json')) {
      setValidationError(`Only CycloneDX JSON format is accepted.`);
      setFile(null);
      e.target.value = '';
      return;
    }

    setFile(selected);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    
    if (!file) {
      setValidationError("Please select a file to upload.");
      return;
    }
    
    if (!applicationName.trim()) {
      setValidationError("Please enter an application name.");
      return;
    }

    if (!user?.username) {
      setValidationError("Session identity is missing.");
      return;
    }

    try {
      const content = await file.text();
      // Basic check to ensure it's parseable JSON before wasting network resources
      try {
        JSON.parse(content);
      } catch {
        setValidationError("The file is not a valid JSON document.");
        return;
      }

      uploadMutation.mutate({
        applicationName,
        vendor: user.username, // Send the currently authenticated username as the vendor parameter
        format: "CycloneDX",
        content,
        filename: file.name
      });
    } catch {
      setValidationError("Failed to read the file from the filesystem.");
    }
  };

  if (successId) {
    return (
      <Card className="max-w-2xl mx-auto border-green-200">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <CheckCircle2 className="h-12 w-12 text-green-500" />
          </div>
          <CardTitle>Upload Successful</CardTitle>
          <CardDescription>The backend accepted your SBOM upload.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-muted p-4 rounded-md">
            <Label className="text-xs text-muted-foreground uppercase">Upload ID</Label>
            <p className="font-mono text-sm break-all">{successId}</p>
          </div>
        </CardContent>
        <CardFooter className="flex flex-col sm:flex-row justify-center gap-4">
          <Link href="/sboms" className={buttonVariants({ variant: "outline" })}>Return to List</Link>
          <Button onClick={() => {
            setSuccessId(null);
            setFile(null);
            setApplicationName("");
            uploadMutation.reset();
          }} variant="outline">
            Upload Another
          </Button>
            <Link href={`/proofs/generate?sbomId=${encodeURIComponent(successId)}`} className={buttonVariants()}>
            Generate Proof
          </Link>
        </CardFooter>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Upload SBOM</h1>
        <p className="text-muted-foreground">Submit a CycloneDX SBOM for future vulnerability analysis and proof generation.</p>
      </div>

      <Card className="max-w-2xl">
        <form onSubmit={handleSubmit}>
          <CardHeader>
            <CardTitle>SBOM Details</CardTitle>
            <CardDescription>Please provide the required metadata and select your JSON file.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {validationError && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Validation Error</AlertTitle>
                <AlertDescription>{validationError}</AlertDescription>
              </Alert>
            )}

            {uploadMutation.error && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Upload Failed</AlertTitle>
                <AlertDescription>
                  {uploadMutation.error instanceof ApiError 
                    ? uploadMutation.error.message 
                    : "An unexpected network error occurred."}
                </AlertDescription>
              </Alert>
            )}

            <div className="space-y-2">
              <Label htmlFor="applicationName">Application Name</Label>
              <Input
                id="applicationName"
                placeholder="e.g. backend-services"
                value={applicationName}
                onChange={(e) => setApplicationName(e.target.value)}
                disabled={uploadMutation.isPending}
              />
              <p className="text-[0.8rem] text-muted-foreground">The internal identifier for this software component.</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sbomFile">CycloneDX JSON File</Label>
              <Input
                id="sbomFile"
                type="file"
                accept=".json,application/json"
                onChange={handleFileChange}
                disabled={uploadMutation.isPending}
              />
              <p className="text-[0.8rem] text-muted-foreground">Maximum size: 10 MB.</p>
            </div>
            
            {/* The vendor field is supplied automatically from the authenticated session context (user.username) */}
            <div className="space-y-2">
              <Label>Format</Label>
              <Input value="CycloneDX" disabled />
              <p className="text-[0.8rem] text-muted-foreground">Only CycloneDX format is currently supported.</p>
            </div>

          </CardContent>
          <CardFooter className="flex justify-between border-t p-6">
            <Link href="/sboms" className={buttonVariants({ variant: "ghost", className: uploadMutation.isPending ? "pointer-events-none opacity-50" : "" })}>Cancel</Link>
            <Button type="submit" disabled={uploadMutation.isPending || !file || !applicationName}>
              {uploadMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Uploading...
                </>
              ) : (
                <>
                  <FileUp className="mr-2 h-4 w-4" />
                  Upload
                </>
              )}
            </Button>
          </CardFooter>
        </form>
      </Card>
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
