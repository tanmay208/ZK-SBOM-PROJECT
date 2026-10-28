import { apiClient } from "../client";
import { PolicyResponse, PolicyCreateRequest } from "../types";

export type Policy = PolicyResponse;

export const policyService = {
  list: async (): Promise<PolicyResponse[]> => {
    return apiClient<PolicyResponse[]>("/api/v1/policy", {
      method: "GET",
    });
  },
  
  create: async (data: PolicyCreateRequest): Promise<PolicyResponse> => {
    return apiClient<PolicyResponse>("/api/v1/policy", {
      method: "POST",
      data,
    });
  },

  activate: async (policyId: string): Promise<PolicyResponse> => {
    return apiClient<PolicyResponse>(`/api/v1/policy/${encodeURIComponent(policyId)}/activate`, {
      method: "POST",
    });
  },
};

