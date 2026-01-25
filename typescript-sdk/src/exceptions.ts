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
    default:
      return new ApiRequestError(message, statusCode, apiError);
  }
}
