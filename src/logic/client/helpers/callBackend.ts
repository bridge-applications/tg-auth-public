import type { z } from "zod";
import {
  ApiBaseResSchema,
  ApiStatus,
} from "../../../schemas/api/ApiBaseResSchema.js";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";
export interface EndpointSchema {
  req: z.ZodType | null;
  res: z.ZodType;
}
export interface ApiErrorResponse {
  message: string;
  code?: string;
  details?: unknown;
}
export class TelegramAuthApiError extends Error {
  constructor(
    public readonly code:
      | "REQUEST_VALIDATION"
      | "RESPONSE_VALIDATION"
      | "HTTP_ERROR"
      | "API_ERROR"
      | "TIMEOUT"
      | "NETWORK_ERROR",
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "TelegramAuthApiError";
  }
}

/** Never log request headers, payloads, cookies, or response bodies. */
export async function callBackend<T>(
  baseUrl: string,
  endpointPath: string,
  method: HttpMethod,
  schema: EndpointSchema,
  data?: unknown,
  headers: Record<string, string> = {},
  debug = false,
  timeoutMs = 15_000,
): Promise<T> {
  const request = schema.req?.safeParse(data);
  if (request && !request.success)
    throw new TelegramAuthApiError(
      "REQUEST_VALIDATION",
      "Authentication request failed validation",
    );
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${baseUrl}${endpointPath}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...headers,
      },
      credentials: "include",
      signal: controller.signal,
      ...(method !== "GET" && data !== undefined
        ? { body: JSON.stringify(request?.data ?? data) }
        : {}),
    });
    if (debug)
      console.debug("[tg-auth] Authentication response", {
        method,
        status: response.status,
      });
    if (!response.ok)
      throw new TelegramAuthApiError(
        "HTTP_ERROR",
        "Authentication HTTP request failed",
        response.status,
      );
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      if (controller.signal.aborted)
        throw new TelegramAuthApiError(
          "TIMEOUT",
          "Authentication request timed out",
        );
      throw new TelegramAuthApiError(
        "RESPONSE_VALIDATION",
        "Authentication response must be JSON",
        response.status,
      );
    }
    const base = ApiBaseResSchema.safeParse(body);
    if (!base.success)
      throw new TelegramAuthApiError(
        "RESPONSE_VALIDATION",
        "Authentication response failed validation",
        response.status,
      );
    if (base.data.status !== ApiStatus.SUCCESS || base.data.statusCode !== 200)
      throw new TelegramAuthApiError(
        "API_ERROR",
        "Authentication request was rejected",
        response.status,
      );
    const parsed = schema.res.safeParse(body);
    if (!parsed.success)
      throw new TelegramAuthApiError(
        "RESPONSE_VALIDATION",
        "Authentication response failed validation",
        response.status,
      );
    return parsed.data as T;
  } catch (error) {
    if (controller.signal.aborted)
      throw new TelegramAuthApiError(
        "TIMEOUT",
        "Authentication request timed out",
      );
    if (error instanceof TelegramAuthApiError) throw error;
    throw new TelegramAuthApiError(
      "NETWORK_ERROR",
      "Authentication request could not be completed",
    );
  } finally {
    clearTimeout(timeout);
  }
}
