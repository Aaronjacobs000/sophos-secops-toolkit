// SPDX-License-Identifier: Apache-2.0
/**
 * Query string and form encoding without URL or URLSearchParams. React
 * Native's built-in URLSearchParams has historically implemented only append
 * and toString, and URL has thrown on most getters, so the shipped path builds
 * strings directly rather than depend on a polyfill being installed.
 */

/**
 * The fetch function the clients call. Defaults to the global fetch, looked up
 * at call time; SecOps Toolkit passes its read-only, rate-limited transport.
 * (SecOps Toolkit local modification, 05/10/2026.)
 */
export type FetchLike = (input: string, init?: globalThis.RequestInit) => Promise<globalThis.Response>;

export const defaultFetch: FetchLike = (input, init) => globalThis.fetch(input, init);

/**
 * A redirect Sophos answered with, refused instead of followed. Following it
 * sends the request again to whatever address the Location header names: on
 * a 307 or 308 with the same body, which on the token request is the client
 * secret, and on an API call with the tenant ID header. SecOps Toolkit's
 * read-only transport refuses it; the clients never retry it. (SecOps Toolkit
 * local modification, 30/10/2026.)
 */
export class SophosRedirectError extends Error {
  constructor(
    readonly status: number,
    url: string,
    location: string | null
  ) {
    const target = redirectHost(url, location);
    super(
      `Sophos answered ${describe(url)} with a ${status} redirect${target ? ` to ${target}` : ""}. ` +
        "Redirects are never followed, so nothing was sent there."
    );
    this.name = "SophosRedirectError";
  }
}

/** Throws SophosRedirectError when the answer is a redirect. */
export function refuseRedirect(response: globalThis.Response, url: string): void {
  if (response.status < 300 || response.status > 399) return;
  response.body?.cancel().catch(() => {});
  throw new SophosRedirectError(response.status, url, response.headers.get("Location"));
}

/** Host and path of an absolute URL, or of a scheme-relative one ("//host/path"). */
const HOST_AND_PATH = /^(?:[a-z][a-z0-9+.-]*:)?\/\/([^/?#]*)([^?#]*)/i;

/** Host and path, without the query string. */
function describe(url: string): string {
  const match = HOST_AND_PATH.exec(url);
  return match ? `${match[1]}${match[2]}` : "the request";
}

/** The host a Location header points at; a relative one stays on the request's host. */
function redirectHost(url: string, location: string | null): string | null {
  if (!location) return null;
  const match = HOST_AND_PATH.exec(location) ?? HOST_AND_PATH.exec(url);
  return match?.[1] || null;
}

/** `${base}${path}` plus the params whose value is neither undefined nor "". */
export function buildUrl(
  base: string,
  path: string,
  params?: Record<string, string | undefined>
): string {
  const url = `${base}${path}`;
  const query = params
    ? Object.entries(params)
        .filter((entry): entry is [string, string] => entry[1] !== undefined && entry[1] !== "")
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join("&")
    : "";
  if (!query) return url;
  return `${url}${url.includes("?") ? "&" : "?"}${query}`;
}

/** application/x-www-form-urlencoded body. */
export function formEncode(fields: Record<string, string>): string {
  return Object.entries(fields)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}
