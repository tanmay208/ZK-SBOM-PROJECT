// AUTH & ROLES (Roadmap V3 Stage G2: Consolidated 3-role primary model)
export type PrimaryRole = "vendor" | "buyer" | "admin";
export type LegacyRole = "auditor" | "trusted_importer";
export type Role = PrimaryRole | LegacyRole;

export interface User {
  id: string;
  username: string;
  role: Role;
  is_active?: boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface PasswordChangeRequest {
  current_password: string;
  new_password: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

// ADMIN USER MANAGEMENT
export interface AdminUser {
  id: string;
  username: string;
  role: Role;
  is_active: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface UserRoleUpdateRequest {
  role: Role;
}

export interface UserStatusUpdateRequest {
  is_active: boolean;
}

export interface AdminUserFilterParams {
  skip?: number;
  limit?: number;
  role?: Role;
  is_active?: boolean;
}

// METRICS
export interface BackendMetricsResponse {
  total_sboms: number;
  total_jobs: number;
  total_certificates: number;
  total_verifications: number;
}

export interface DashboardMetrics {
  total_sboms: number;
  total_jobs: number;
  total_certificates: number;
  total_verifications: number;
  sbom_count?: number;
  proof_count?: number;
  verification_count?: number;
  certificate_count?: number;
}

// APPLICATION
export interface ApplicationResponse {
  id: string;
  name: string;
  vendor: string;
  description?: string | null;
  user_id?: string | null;
  is_active: boolean;
  archived_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApplicationCreateRequest {
  name: string;
  vendor: string;
  description?: string | null;
}

export interface ApplicationUpdateRequest {
  name?: string | null;
  description?: string | null;
}

export interface ApplicationListParams {
  skip?: number;
  limit?: number;
  include_archived?: boolean;
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
  application_name?: string | null;
  vendor?: string | null;
}

// VULNERABILITY
export type VulnerabilitySnapshotStatus = "pending" | "approved" | "frozen" | "revoked";

export interface VulnerabilitySnapshotResponse {
  id: string;
  snapshot_label: string;
  record_count: number;
  status: VulnerabilitySnapshotStatus;
  authoritative_smt_root?: string | null;
  frozen_at?: string | null;
  frozen_by?: string | null;
  approved_at?: string | null;
  approved_by?: string | null;
  revoked_at?: string | null;
  revoked_by?: string | null;
  revocation_reason?: string | null;
}

export interface RevocationRequest {
  reason?: string | null;
}

export interface VulnerabilityIngestionItem {
  purl: string;
  cvss_score: number;
}

export const TRUSTED_VULNERABILITY_SOURCES = [
  "NVD",
  "OSV",
  "GitHub Advisory Database",
] as const;

export type TrustedVulnerabilitySource = (typeof TRUSTED_VULNERABILITY_SOURCES)[number];

export interface VulnerabilityIngestionRequest {
  source_identity: TrustedVulnerabilitySource | string;
  provenance: Record<string, unknown>;
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
export type ProofJobStatus = "pending" | "assembling_witness" | "running" | "completed" | "failed" | "execution_blocked";

export interface SegmentProofResponse {
  id: string;
  chunk_id: string;
  chunk_index: number;
  total_chunks: number;
  segment_index: number;
  status: string;
  created_at: string;
  completed_at: string | null;
}

export interface ChunkProofSetResponse {
  id: string;
  proof_job_id: string;
  chunk_index: number;
  total_chunks: number;
  component_start: number;
  component_count: number;
  components_commit: string | null;
  status: string;
  created_at: string;
  segments?: SegmentProofResponse[];
}

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
  proof_archive_hash?: string | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  chunks?: ChunkProofSetResponse[];
}

// VERIFICATION
export type VerificationResult =
  | "verified"
  | "invalid"
  | "invalid_proof"
  | "cryptographic_false"
  | "structural_rejection"
  | "runtime_failure"
  | "environment_failure"
  | "authoritative_record_mismatch"
  | "record_mismatch"
  | "public_input_mismatch"
  | "unavailable"
  | "verification_unavailable";

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
  revoked_by?: string | null;
  sha256_fingerprint?: string | null;
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
