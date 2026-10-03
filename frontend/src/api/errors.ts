export class ApiError extends Error {
  public status: number;
  public code: string;

  constructor(message: string, status: number, code: string = "UNKNOWN_ERROR") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}
