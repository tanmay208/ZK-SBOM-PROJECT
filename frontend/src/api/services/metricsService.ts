import { apiClient } from "../client";
import { BackendMetricsResponse, DashboardMetrics } from "../types";

export const metricsService = {
  getMetrics: async (): Promise<DashboardMetrics> => {
    const raw = await apiClient<BackendMetricsResponse>("/api/v1/metrics", {
      method: "GET",
    });
    return {
      total_sboms: raw.total_sboms,
      total_jobs: raw.total_jobs,
      total_certificates: raw.total_certificates,
      total_verifications: raw.total_verifications,
      sbom_count: raw.total_sboms,
      proof_count: raw.total_jobs,
      verification_count: raw.total_verifications,
      certificate_count: raw.total_certificates,
    };
  }
};
