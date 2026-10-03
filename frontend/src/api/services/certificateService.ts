import { apiClient } from "../client";
import { VerificationCertificateResponse } from "../types";

export const certificateService = {
  list: async ():Promise<VerificationCertificateResponse[]> => {
    return apiClient<VerificationCertificateResponse[]>("/api/v1/verification/certificates", {
      method: "GET",
    });
  },
  
  getCertificate: async (id: string):Promise<VerificationCertificateResponse> => {
    return apiClient<VerificationCertificateResponse>(`/api/v1/verification/certificates/${encodeURIComponent(id)}`, {
      method: "GET",
    });
  },

  validateCertificate: async (id: string):Promise<{valid: boolean, reason: string, certificate_id: string, is_revoked: boolean | null, revoked_at: string | null}> => {
    return apiClient<{valid: boolean, reason: string, certificate_id: string, is_revoked: boolean | null, revoked_at: string | null}>(`/api/v1/verification/certificates/${encodeURIComponent(id)}/validate`, {
      method: "GET",
      skipAuth: true,
    });
  }
};
