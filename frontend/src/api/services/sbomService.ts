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
  
  list: async ():Promise<SBOMUploadResponse[]> => {
    return apiClient<SBOMUploadResponse[]>("/api/v1/sbom", {
      method: "GET",
    });
  }
};
