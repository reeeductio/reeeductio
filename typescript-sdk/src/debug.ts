/**
 * Debug logging helpers for the TypeScript SDK.
 *
 * Enable with REEEDUCTIO_SDK_LOG_LEVEL=debug (Node)
 * or set globalThis.REEEDUCTIO_SDK_LOG_LEVEL = 'debug'.
 */

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug' | 'trace';

const ORDER: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
  trace: 5,
};

type DebugFlag = boolean | string | number | null | undefined;
type GlobalConfig = {
  REEEDUCTIO_SDK_LOG_LEVEL?: LogLevel | string;
  REEEDUCTIO_SDK_DEBUG?: DebugFlag;
};

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on', 'debug']);

function coerceDebugFlag(value: DebugFlag): boolean {
  if (value === true) return true;
  if (value === false || value === null || value === undefined) return false;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') return TRUE_VALUES.has(value.toLowerCase());
  return false;
}

function normalizeLevel(value?: string | LogLevel | null): LogLevel | undefined {
  if (!value) return undefined;
  const lower = value.toString().toLowerCase();
  if (lower in ORDER) return lower as LogLevel;
  return undefined;
}

function readLogLevel(): LogLevel {
  const globalConfig = globalThis as GlobalConfig;
  const globalLevel = normalizeLevel(globalConfig.REEEDUCTIO_SDK_LOG_LEVEL);
  if (globalLevel) return globalLevel;

  if (typeof process !== 'undefined' && process?.env) {
    const envLevel =
      normalizeLevel(process.env.REEEDUCTIO_SDK_LOG_LEVEL) ??
      normalizeLevel(process.env.LOG_LEVEL);
    if (envLevel) return envLevel;

    if (coerceDebugFlag(process.env.REEEDUCTIO_SDK_DEBUG)) {
      return 'debug';
    }
  }

  if (coerceDebugFlag(globalConfig.REEEDUCTIO_SDK_DEBUG)) {
    return 'debug';
  }

  return 'silent';
}

function sanitizeValue(key: string, value: unknown): unknown {
  const keyLower = key.toLowerCase();
  if (
    keyLower.includes('token') ||
    keyLower.includes('signature') ||
    keyLower.includes('private') ||
    keyLower.includes('secret') ||
    keyLower.includes('authorization') ||
    keyLower.includes('challenge')
  ) {
    return '[redacted]';
  }

  if (value instanceof Uint8Array) {
    return `Uint8Array(${value.length})`;
  }

  if (ArrayBuffer.isView(value)) {
    return `${value.constructor.name}(${value.byteLength})`;
  }

  if (value instanceof ArrayBuffer) {
    return `ArrayBuffer(${value.byteLength})`;
  }

  if (typeof value === 'string' && value.length > 120) {
    return `${value.slice(0, 120)}…`;
  }

  return value;
}

function sanitizeDetails(details?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!details) return undefined;

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(details)) {
    sanitized[key] = sanitizeValue(key, value);
  }
  return sanitized;
}

function getConsoleForLevel(level: LogLevel): ((...args: unknown[]) => void) | undefined {
  if (typeof console === 'undefined') return undefined;
  switch (level) {
    case 'error':
      return console.error?.bind(console);
    case 'warn':
      return console.warn?.bind(console);
    case 'info':
      return console.info?.bind(console);
    case 'debug':
    case 'trace':
      return (console.debug ?? console.log)?.bind(console);
    default:
      return undefined;
  }
}

function shouldLog(messageLevel: LogLevel, activeLevel: LogLevel): boolean {
  if (activeLevel === 'silent') return false;
  return ORDER[messageLevel] <= ORDER[activeLevel];
}

export interface Logger {
  level: LogLevel;
  trace: (message: string, details?: Record<string, unknown>) => void;
  debug: (message: string, details?: Record<string, unknown>) => void;
  info: (message: string, details?: Record<string, unknown>) => void;
  warn: (message: string, details?: Record<string, unknown>) => void;
  error: (message: string, details?: Record<string, unknown>) => void;
}

export function getLogLevel(): LogLevel {
  return readLogLevel();
}

export function setLogLevel(level: LogLevel): void {
  (globalThis as GlobalConfig).REEEDUCTIO_SDK_LOG_LEVEL = level;
}

export function isDebugEnabled(): boolean {
  return shouldLog('debug', getLogLevel());
}

export function setDebugEnabled(enabled: boolean): void {
  setLogLevel(enabled ? 'debug' : 'silent');
}

export function createLogger(name: string, level: LogLevel = getLogLevel()): Logger {
  const log = (msgLevel: LogLevel, message: string, details?: Record<string, unknown>): void => {
    if (!shouldLog(msgLevel, level)) return;
    const writer = getConsoleForLevel(msgLevel);
    if (!writer) return;
    const prefix = `[reeeductio:${name}] ${msgLevel}:`;
    const safeDetails = sanitizeDetails(details);
    if (safeDetails) {
      writer(prefix, message, safeDetails);
    } else {
      writer(prefix, message);
    }
  };

  return {
    level,
    trace: (message, details) => log('trace', message, details),
    debug: (message, details) => log('debug', message, details),
    info: (message, details) => log('info', message, details),
    warn: (message, details) => log('warn', message, details),
    error: (message, details) => log('error', message, details),
  };
}

export function logMessage(
  scope: string,
  level: LogLevel,
  message: string,
  details?: Record<string, unknown>
): void {
  const logger = createLogger(scope);
  logger[level](message, details);
}

export function traceLog(scope: string, message: string, details?: Record<string, unknown>): void {
  logMessage(scope, 'trace', message, details);
}

export function debugLog(scope: string, message: string, details?: Record<string, unknown>): void {
  logMessage(scope, 'debug', message, details);
}

export function infoLog(scope: string, message: string, details?: Record<string, unknown>): void {
  logMessage(scope, 'info', message, details);
}

export function warnLog(scope: string, message: string, details?: Record<string, unknown>): void {
  logMessage(scope, 'warn', message, details);
}

export function errorLog(scope: string, message: string, details?: Record<string, unknown>): void {
  logMessage(scope, 'error', message, details);
}
