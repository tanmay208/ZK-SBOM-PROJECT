import { apiClient } from "../client";
import {
  VerifyProofRequest,
  VerificationResponse,
  VerificationCertificateResponse,
  CreateProofShareRequest,
  ProofShareResponse,
} from "../types";

export const verificationService = {
  verify: async (data: VerifyProofRequest): Promise<VerificationResponse> => {
    return apiClient<VerificationResponse>("/api/v1/verification/verify", {
      method: "POST",
      data,
    });
  },

  listCertificates: async (skip: number = 0, limit: number = 50): Promise<VerificationCertificateResponse[]> => {
    return apiClient<VerificationCertificateResponse[]>("/api/v1/verification/certificates", {
      method: "GET",
      params: { skip: String(skip), limit: String(limit) },
    });
  },

  getCertificate: async (id: string): Promise<VerificationCertificateResponse> => {
    return apiClient<VerificationCertificateResponse>(`/api/v1/verification/certificates/${encodeURIComponent(id)}`, {
      method: "GET",
    });
  },

  createShare: async (data: CreateProofShareRequest): Promise<ProofShareResponse> => {
    return apiClient<ProofShareResponse>("/api/v1/verification/shares", {
      method: "POST",
      data,
    });
  },

  listShares: async (skip: number = 0, limit: number = 50): Promise<ProofShareResponse[]> => {
    return apiClient<ProofShareResponse[]>("/api/v1/verification/shares", {
      method: "GET",
      params: { skip: String(skip), limit: String(limit) },
    });
  },

  getShare: async (shareTokenOrId: string): Promise<ProofShareResponse> => {
    return apiClient<ProofShareResponse>(`/api/v1/verification/shares/${encodeURIComponent(shareTokenOrId)}`, {
      method: "GET",
    });
  },

  revokeShare: async (shareId: string): Promise<ProofShareResponse> => {
    return apiClient<ProofShareResponse>(`/api/v1/verification/shares/${encodeURIComponent(shareId)}/revoke`, {
      method: "POST",
    });
  },

  deleteShare: async (shareId: string): Promise<{ status: string; id: string; message: string }> => {
    return apiClient<{ status: string; id: string; message: string }>(
      `/api/v1/verification/shares/${encodeURIComponent(shareId)}`,
      {
        method: "DELETE",
      }
    );
  },
};
