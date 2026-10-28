import { apiClient } from "../client";
import { SBOMUploadResponse } from "../types";

export const sbomService = {
  upload: async (applicationName: string, vendor: string, format: string, content: string, filename?: string):Promise<SBOMUploadResponse> => {
    // The backend uses a JSON body envelope as specified in Stage 3.1 AMBIGUITY NOTE.
    return apiClient<SBOMUploadResponse>("/api/v1/sbom/upload", {
      method: "POST",
      data: {
        application_name: applicationName,
        vendor: vendor,
        format: format,
        content: content,
        filename: filename || null
      }
    });
  },
  
  list: async (params?: { skip?: number; limit?: number; all_tenants?: boolean }): Promise<SBOMUploadResponse[]> => {
    const query = new URLSearchParams();
    if (params?.skip !== undefined) query.set("skip", params.skip.toString());
    if (params?.limit !== undefined) query.set("limit", params.limit.toString());
    if (params?.all_tenants) query.set("all_tenants", "true");
    const qs = query.toString();
    return apiClient<SBOMUploadResponse[]>(`/api/v1/sbom${qs ? `?${qs}` : ""}`, {
      method: "GET",
    });
  },

  getById: async (uploadId: string): Promise<SBOMUploadResponse> => {
    return apiClient<SBOMUploadResponse>(`/api/v1/sbom/${encodeURIComponent(uploadId)}`, {
      method: "GET",
    });
  }
};
