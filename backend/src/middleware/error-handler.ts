// Copied from sophos-tenant-migration-tool (https://github.com/Aaronjacobs000/sophos-tenant-migration-tool),
// MIT License, Copyright (c) 2026 Aaron Jacobs.
/**
 * Unified JSON error response for uncaught route errors.
 */

import type { Request, Response, NextFunction } from "express";
import { log, maskSecrets } from "../log.js";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const message = maskSecrets(err instanceof Error ? err.message : String(err));
  // body-parser marks its own errors (malformed JSON, a body over the limit) with a 4xx status.
  const status = (err as { status?: unknown } | null)?.status;
  if (typeof status === "number" && status >= 400 && status < 500) {
    if (!res.headersSent) res.status(status).json({ error: "bad_request", message: (err as { expose?: unknown }).expose ? message : "Bad request." });
    return;
  }
  log.error(`[${req.method} ${req.path}] ${message}`);
  if (res.headersSent) return;
  res.status(500).json({ error: "internal_error", message });
}
