import { authTransport } from "./authTransport";
import { API_CONFIG } from "./config";
import { ApiError } from "./errors";

interface RequestConfig extends RequestInit {
  data?: unknown;
  params?: Record<string, string>;
  skipAuth?: boolean;
}

/**
 * Centralized HTTP Client.
 * Handles JSON/FormData, authorization header injection, and error normalization.
 */
export async function apiClient<T>(endpoint: string, config: RequestConfig = {}): Promise<T> {
  const { data, params, headers, skipAuth, ...customConfig } = config;
  const token = authTransport.getToken();

  const requestHeaders = new Headers(headers);
  
  if (token && !skipAuth) {
    requestHeaders.set("Authorization", `Bearer ${token}`);
  }

  // Handle FormData vs JSON
  if (data) {
    if (data instanceof FormData) {
      // Fetch automatically sets the correct Content-Type with the boundary for FormData.
      // Do not set Content-Type explicitly.
    } else if (data instanceof URLSearchParams) {
      requestHeaders.set("Content-Type", "application/x-www-form-urlencoded");
    } else {
      requestHeaders.set("Content-Type", "application/json");
    }
  }

  let url = `${API_CONFIG.BASE_URL}${endpoint}`;
  if (params) {
    const searchParams = new URLSearchParams(params);
    url += `?${searchParams.toString()}`;
  }

  const fetchConfig: RequestInit = {
    ...customConfig,
    headers: requestHeaders,
    body: data instanceof FormData || data instanceof URLSearchParams ? data : (data ? JSON.stringify(data) : undefined),
  };

  try {
    const response = await fetch(url, fetchConfig);

    if (!response.ok) {
      await handleApiError(response);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return {} as T;
    }

    return await response.json();
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError("Unable to connect to the server. Please check your network connection or try again later.", 0, "NETWORK_ERROR");
  }
}

async function handleApiError(response: Response): Promise<never> {
  let errorMessage = "Unknown API Error";
  let errorCode = "UNKNOWN_ERROR";

  try {
    const errorData = await response.json();
    // Support standard detail pattern from FastAPI
    if (errorData.detail) {
      if (typeof errorData.detail === "string") {
        errorMessage = errorData.detail;
      } else if (Array.isArray(errorData.detail)) {
        // Pydantic validation errors
        errorMessage = "Validation Error";
        errorCode = "VALIDATION_ERROR";
      }
    } else if (errorData.error) {
      errorMessage = errorData.error;
      errorCode = errorData.code || errorCode;
    }
  } catch {
    // Non-JSON error response
    errorMessage = response.statusText;
  }

  let retryAfter: number | undefined;

  // Intercept 401 and clear memory token
  if (response.status === 401) {
    authTransport.handleUnauthorized();
    errorCode = "UNAUTHORIZED";
  } else if (response.status === 403) {
    errorCode = "FORBIDDEN";
  } else if (response.status === 404) {
    errorCode = "NOT_FOUND";
  } else if (response.status === 409) {
    errorCode = "CONFLICT";
  } else if (response.status === 413) {
    errorCode = "PAYLOAD_TOO_LARGE";
  } else if (response.status === 422) {
    errorCode = "UNPROCESSABLE_ENTITY";
  } else if (response.status === 429) {
    errorCode = "TOO_MANY_REQUESTS";
    const retryHeader = response.headers?.get ? response.headers.get("Retry-After") : null;
    if (retryHeader) {
      const parsed = parseInt(retryHeader, 10);
      if (!isNaN(parsed) && parsed > 0) {
        retryAfter = parsed;
      }
    }
    if (retryAfter) {
      errorMessage = `Rate limit exceeded. Please retry after ${retryAfter} seconds.`;
    } else if (errorMessage === "Unknown API Error" || errorMessage === "Too Many Requests") {
      errorMessage = "Rate limit exceeded. Please try again later.";
    }
  } else if (response.status >= 500) {
    errorMessage = "An unexpected server error occurred. Please try again later.";
    errorCode = "SERVER_ERROR";
  }

  throw new ApiError(errorMessage, response.status, errorCode, retryAfter);
}
