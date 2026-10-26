import { apiClient } from "../client";
import {
  AdminUser,
  AdminUserFilterParams,
  UserRoleUpdateRequest,
  UserStatusUpdateRequest,
} from "../types";

export const adminService = {
  listUsers: async (params?: AdminUserFilterParams): Promise<AdminUser[]> => {
    const queryParams: Record<string, string> = {};
    if (params?.skip !== undefined) {
      queryParams.skip = params.skip.toString();
    }
    if (params?.limit !== undefined) {
      queryParams.limit = params.limit.toString();
    }
    if (params?.role) {
      queryParams.role = params.role;
    }
    if (params?.is_active !== undefined) {
      queryParams.is_active = params.is_active.toString();
    }
    return apiClient<AdminUser[]>("/api/v1/admin/users", {
      method: "GET",
      params: Object.keys(queryParams).length > 0 ? queryParams : undefined,
    });
  },

  getUser: async (userId: string): Promise<AdminUser> => {
    return apiClient<AdminUser>(`/api/v1/admin/users/${userId}`, {
      method: "GET",
    });
  },

  updateUserRole: async (
    userId: string,
    payload: UserRoleUpdateRequest
  ): Promise<AdminUser> => {
    return apiClient<AdminUser>(`/api/v1/admin/users/${userId}/role`, {
      method: "PATCH",
      data: payload,
    });
  },

  updateUserStatus: async (
    userId: string,
    payload: UserStatusUpdateRequest
  ): Promise<AdminUser> => {
    return apiClient<AdminUser>(`/api/v1/admin/users/${userId}/status`, {
      method: "PATCH",
      data: payload,
    });
  },
};
