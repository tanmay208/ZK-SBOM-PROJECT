import { apiClient } from "../client";
import {
  ApplicationResponse,
  ApplicationCreateRequest,
  ApplicationUpdateRequest,
  ApplicationListParams,
} from "../types";

export const applicationService = {
  list: async (params?: ApplicationListParams): Promise<ApplicationResponse[]> => {
    const query = new URLSearchParams();
    if (params?.skip !== undefined) query.set("skip", params.skip.toString());
    if (params?.limit !== undefined) query.set("limit", params.limit.toString());
    if (params?.include_archived !== undefined) {
      query.set("include_archived", params.include_archived ? "true" : "false");
    }
    if (params?.all_tenants !== undefined) {
      query.set("all_tenants", params.all_tenants ? "true" : "false");
    }
    const qs = query.toString();
    return apiClient<ApplicationResponse[]>(`/api/v1/applications${qs ? `?${qs}` : ""}`, {
      method: "GET",
    });
  },

  create: async (data: ApplicationCreateRequest): Promise<ApplicationResponse> => {
    return apiClient<ApplicationResponse>("/api/v1/applications", {
      method: "POST",
      data,
    });
  },

  get: async (id: string): Promise<ApplicationResponse> => {
    return apiClient<ApplicationResponse>(`/api/v1/applications/${encodeURIComponent(id)}`, {
      method: "GET",
    });
  },

  update: async (id: string, data: ApplicationUpdateRequest): Promise<ApplicationResponse> => {
    return apiClient<ApplicationResponse>(`/api/v1/applications/${encodeURIComponent(id)}`, {
      method: "PATCH",
      data,
    });
  },

  archive: async (id: string): Promise<ApplicationResponse> => {
    return apiClient<ApplicationResponse>(`/api/v1/applications/${encodeURIComponent(id)}/archive`, {
      method: "POST",
    });
  },

  reactivate: async (id: string): Promise<ApplicationResponse> => {
    return apiClient<ApplicationResponse>(`/api/v1/applications/${encodeURIComponent(id)}/reactivate`, {
      method: "POST",
    });
  },
};
