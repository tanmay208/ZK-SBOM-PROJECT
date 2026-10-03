import { apiClient } from "../client";
import { DashboardMetrics } from "../types";

export const metricsService = {
  getMetrics: async ():Promise<DashboardMetrics> => {
    return apiClient<DashboardMetrics>("/api/v1/metrics", {
      method: "GET",
    });
  }
};
