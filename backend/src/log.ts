/**
 * Logging with secret masking and an in-memory ring buffer. Adapted from the
 * Sophos tenant migration tool (MIT). Every line is masked twice: key=value
 * pairs that name a secret (an access token among them), "Bearer" values, and
 * every exact value registered with registerSecret (client IDs and secrets).
 */

const SECRET_KEY_REGEX = /("?(?:client[_-]?(?:secret|id)|authorization|token|password|api[_-]?key)"?\s*[:=]\s*"?)([^",\s]+)/gi;
const SECRET_FIELD_REGEX = /token|secret|password|authorization|api[_-]?key|clientid/i;
const MASK = "••••••••";
const RING_CAPACITY = 500;

const secretValues = new Set<string>();

export type LogLevel = "info" | "warn" | "error";

export interface LogEntry {
  ts: string;
  level: LogLevel;
  message: string;
  section?: string;
  detail?: Record<string, unknown>;
}

const ring: LogEntry[] = [];
let quiet = false;

function maskString(input: string): string {
  let out = input.replace(SECRET_KEY_REGEX, (_m, key) => `${key}${MASK}`);
  out = out.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, `Bearer ${MASK}`);
  for (const value of secretValues) out = out.split(value).join(MASK);
  return out;
}

/** Mask this exact value in every later log line and error response. */
export function registerSecret(value: string | null | undefined): void {
  if (typeof value === "string" && value.length >= 8) secretValues.add(value);
}

export function maskSecrets(input: string): string {
  return maskString(input);
}

/** Tests turn console output off; the ring buffer still fills. */
export function setQuiet(on: boolean): void {
  quiet = on;
}

function redactDetail(detail: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!detail) return detail;
  try {
    return JSON.parse(
      JSON.stringify(detail, (key, value) => {
        if (typeof value !== "string") return value;
        return key && SECRET_FIELD_REGEX.test(key) ? MASK : maskString(value);
      }),
    ) as Record<string, unknown>;
  } catch {
    return { unserialisable: true };
  }
}

function mask(input: unknown): string {
  if (typeof input === "string") return maskString(input);
  if (input instanceof Error) return maskString(input.message);
  try {
    return maskString(JSON.stringify(input));
  } catch {
    return String(input);
  }
}

function emit(level: LogLevel, parts: unknown[], meta?: Partial<LogEntry>): void {
  const ts = new Date().toISOString();
  const message = parts.map(mask).join(" ");
  const entry: LogEntry = { ts, level, message, section: meta?.section, detail: redactDetail(meta?.detail) };
  ring.push(entry);
  if (ring.length > RING_CAPACITY) ring.shift();
  if (quiet) return;
  const tag = meta?.section ? `[${meta.section}]` : "";
  const line = `[${ts}] ${level.padEnd(5)} ${tag} ${message}`.replace(/\s+/g, " ").trim();
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export const log = {
  info(...parts: unknown[]) {
    emit("info", parts);
  },
  warn(...parts: unknown[]) {
    emit("warn", parts);
  },
  error(...parts: unknown[]) {
    emit("error", parts);
  },
  emit(level: LogLevel, section: string, message: string, detail?: Record<string, unknown>): void {
    emit(level, [message], { section, detail });
  },
};

export function getRingBuffer(): LogEntry[] {
  return ring.map((e) => ({ ...e, message: maskString(e.message), detail: redactDetail(e.detail) }));
}

export function clearRingBuffer(): void {
  ring.length = 0;
}
