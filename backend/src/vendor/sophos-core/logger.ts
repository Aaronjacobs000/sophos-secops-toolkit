// SPDX-License-Identifier: Apache-2.0
/**
 * Diagnostic logging for the core package. Silent unless the app installs a
 * logger. Nothing the package logs contains a token, a client secret or a
 * client ID: the messages carry identity IDs, counts, status codes and the
 * Sophos error text, which never echoes credentials.
 */

export interface SophosCoreLogger {
  debug(message: string): void;
  warn(message: string): void;
}

const silent: SophosCoreLogger = {
  debug() {},
  warn() {},
};

let current: SophosCoreLogger = silent;

/** Install a logger, or pass null to go back to silent. */
export function setLogger(logger: SophosCoreLogger | null): void {
  current = logger ?? silent;
}

export function log(): SophosCoreLogger {
  return current;
}
