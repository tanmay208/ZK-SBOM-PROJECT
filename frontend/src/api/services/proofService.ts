import { apiClient } from "../client";
import { ProofJobResponse } from "../types";

export const proofService = {
  list: async ():Promise<ProofJobResponse[]> => {
    return apiClient<ProofJobResponse[]>("/api/v1/zkp", {
      method: "GET",
    });
  },
  
  generate: async (sbomUploadId: string, snapshotId: string, policyId: string):Promise<ProofJobResponse> => {
    return apiClient<ProofJobResponse>("/api/v1/zkp/generate", {
      method: "POST",
      data: {
        sbom_upload_id: sbomUploadId,
        snapshot_id: snapshotId,
        policy_id: policyId
      }
    });
  },

  getJob: async (id: string):Promise<ProofJobResponse> => {
    return apiClient<ProofJobResponse>(`/api/v1/zkp/jobs/${encodeURIComponent(id)}`, {
      method: "GET",
    });
  }
};
