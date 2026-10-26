export class ApiError extends Error {
  public status: number;
  public code: string;
  public retryAfter?: number;

  constructor(message: string, status: number, code: string = "UNKNOWN_ERROR", retryAfter?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}
