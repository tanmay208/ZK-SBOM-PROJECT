import { apiClient } from "../client";
import { VerifyProofRequest, VerificationResponse } from "../types";

export const verificationService = {
  verify: async (data: VerifyProofRequest):Promise<VerificationResponse> => {
    return apiClient<VerificationResponse>("/api/v1/verification/verify", {
      method: "POST",
      data,
    });
  }
};
