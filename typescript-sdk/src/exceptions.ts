/**
 * Custom exceptions for the reeeductio SDK.
 */

import type { ApiError } from './types.js';

/**
 * Base error class for all reeeductio errors.
 */
export class ReeeductioError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReeeductioError';
  }
}

/**
 * Error during authentication (challenge/verify/refresh).
 */
export class AuthenticationError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

/**
 * Error due to insufficient permissions (403 Forbidden).
 */
export class AuthorizationError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

/**
 * Error due to invalid input or validation failure (400 Bad Request).
 */
export class ValidationError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Error when a resource is not found (404 Not Found).
 */
export class NotFoundError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

/**
 * Error due to chain conflict (409 Conflict).
 * This occurs when prev_hash doesn't match the current head.
 */
export class ChainError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'ChainError';
  }
}

/**
 * Error during blob operations.
 */
export class BlobError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'BlobError';
  }
}

/**
 * Error during WebSocket stream operations.
 */
export class StreamError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'StreamError';
  }
}

/**
 * Error from the API with structured error response.
 */
export class ApiRequestError extends ReeeductioError {
  public readonly statusCode: number;
  public readonly apiError?: ApiError;

  constructor(message: string, statusCode: number, apiError?: ApiError) {
    super(message);
    this.name = 'ApiRequestError';
    this.statusCode = statusCode;
    this.apiError = apiError;
  }
}

/**
 * Error during OPAQUE operations.
 */
export class OpaqueError extends ReeeductioError {
  constructor(message: string) {
    super(message);
    this.name = 'OpaqueError';
  }
}

/**
 * Error when OPAQUE is not enabled for a space (501 Not Implemented).
 */
export class OpaqueNotEnabledError extends OpaqueError {
  constructor(message: string = 'OPAQUE is not enabled for this space') {
    super(message);
    this.name = 'OpaqueNotEnabledError';
  }
}

/**
 * Error when rate limited during OPAQUE login (429 Too Many Requests).
 */
export class OpaqueRateLimitError extends OpaqueError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number) {
    super(message);
    this.name = 'OpaqueRateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Convert an API response error to the appropriate exception type.
 */
export function createApiError(statusCode: number, apiError?: ApiError): ReeeductioError {
  const message = apiError?.error || `HTTP ${statusCode}`;

  switch (statusCode) {
    case 400:
      return new ValidationError(message);
    case 401:
      return new AuthenticationError(message);
    case 403:
      return new AuthorizationError(message);
    case 404:
      return new NotFoundError(message);
    case 409:
      return new ChainError(message);
    case 413:
      return new BlobError(message);
    case 429: {
      const retryAfter = apiError?.details?.retry_after as number | undefined;
      return new OpaqueRateLimitError(message, retryAfter);
    }
    case 501:
      return new OpaqueNotEnabledError(message);
    default:
      return new ApiRequestError(message, statusCode, apiError);
  }
}
