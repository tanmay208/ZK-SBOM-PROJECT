// AUTH
export interface User {
  id: string;
  username: string;
  role: "vendor" | "admin" | "auditor";
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

// METRICS
export interface DashboardMetrics {
  sbom_count: number;
  proof_count: number;
  verification_count: number;
  certificate_count: number;
}

// SBOM
export interface SBOMUploadResponse {
  upload_id: string;
  application_id: string;
  status: string;
  format: string;
  filename: string | null;
  sbom_root: string | null;
  component_count: number | null;
  created_at: string;
}

// VULNERABILITY
export type VulnerabilitySnapshotStatus = "pending" | "approved" | "revoked";

export interface VulnerabilitySnapshotResponse {
  id: string;
  snapshot_label: string;
  record_count: number;
  status: VulnerabilitySnapshotStatus;
}

export interface VulnerabilityIngestionItem {
  purl: string;
  cvss_score: number;
}

export interface VulnerabilityIngestionRequest {
  vulnerabilities: VulnerabilityIngestionItem[];
}

export interface VulnerabilityDatabaseResponse {
  snapshot_id: string;
  components_processed: number;
}

// POLICY
export interface PolicyResponse {
  id: string;
  name: string | null;
  description: string | null;
  max_cvss_score: number;
  policy_hash: string | null;
  created_at: string;
  active: boolean;
}

export interface PolicyCreateRequest {
  name?: string;
  description?: string;
  max_cvss_score: number;
}

// PROOF
export type ProofJobStatus = "pending" | "assembling_witness" | "completed" | "failed" | "execution_blocked";

export interface ProofJobResponse {
  id: string;
  sbom_upload_id: string;
  snapshot_id: string;
  policy_id: string;
  status: ProofJobStatus;
  sbom_root: string | null;
  vulnerability_db_root: string | null;
  policy_hash: string | null;
  proof_artifact: string | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

// VERIFICATION
export type VerificationResult = "verified" | "invalid" | "authoritative_record_mismatch" | "public_input_mismatch" | "unavailable";

export interface VerifyProofRequest {
  sbom_root: string;
  vulnerability_db_root: string;
  policy_hash: string;
  proof_artifact?: string | null;
  proof_job_id?: string | null;
}

export interface VerificationCertificateResponse {
  id: string;
  verification_request_id: string;
  certificate_data: string | null;
  sbom_root: string;
  vulnerability_db_root: string;
  policy_hash: string;
  issued_at: string;
  is_revoked: boolean;
  revoked_at: string | null;
  revoked_reason: string | null;
}

export interface VerificationResponse {
  id: string;
  sbom_root: string;
  vulnerability_db_root: string;
  policy_hash: string;
  result: VerificationResult | null;
  verified_at: string | null;
  created_at: string;
  certificate: VerificationCertificateResponse | null;
}
