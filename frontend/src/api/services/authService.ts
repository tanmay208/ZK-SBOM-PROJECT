import { apiClient } from "../client";
import { User, AuthResponse, PasswordChangeRequest } from "../types";

export const authService = {
  login: async (username: string, password: string): Promise<AuthResponse> => {
    const params = new URLSearchParams();
    params.append("username", username);
    params.append("password", password);
    return apiClient<AuthResponse>("/api/v1/auth/login", {
      method: "POST",
      data: params,
    });
  },
  
  register: async (username: string, password: string): Promise<{ message: string; username: string; role: string }> => {
    const params = new URLSearchParams();
    params.append("username", username);
    params.append("password", password);
    return apiClient<{ message: string; username: string; role: string }>("/api/v1/auth/register", {
      method: "POST",
      data: params,
    });
  },

  me: async (): Promise<User> => {
    return apiClient<User>("/api/v1/auth/me", {
      method: "GET",
    });
  },

  changePassword: async (
    dataOrCurrentPassword: PasswordChangeRequest | string,
    newPasswordArg?: string
  ): Promise<{ message: string }> => {
    const payload =
      typeof dataOrCurrentPassword === "object"
        ? dataOrCurrentPassword
        : { current_password: dataOrCurrentPassword, new_password: newPasswordArg || "" };
    return apiClient<{ message: string }>("/api/v1/auth/change-password", {
      method: "POST",
      data: payload,
    });
  }
};
