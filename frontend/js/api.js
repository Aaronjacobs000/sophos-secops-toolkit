// Calls to the toolkit's own local API. The page never talks to Sophos.

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

export const api = {
  get: (path) => call("GET", path),
  post: (path, body = {}) => call("POST", path, body),
  put: (path, body = {}) => call("PUT", path, body),
  patch: (path, body = {}) => call("PATCH", path, body),
  del: (path) => call("DELETE", path),
};

/** Server-sent events with automatic reconnect. */
export function stream(handlers) {
  let es = null;
  let retry = 1000;
  const open = () => {
    es = new EventSource("/api/stream");
    for (const [event, fn] of Object.entries(handlers)) {
      es.addEventListener(event, (e) => {
        try {
          fn(JSON.parse(e.data));
        } catch {
          fn(null);
        }
      });
    }
    es.onopen = () => {
      retry = 1000;
      handlers.open?.();
    };
    es.onerror = () => {
      es.close();
      handlers.lost?.();
      setTimeout(open, retry);
      retry = Math.min(retry * 2, 30000);
    };
  };
  open();
  return () => es?.close();
}

export const store = {
  get(key, fallback = null) {
    try {
      const v = localStorage.getItem(`secops:${key}`);
      return v === null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(`secops:${key}`, JSON.stringify(value));
    } catch {
      // Private windows and blocked storage: the preference just isn't remembered.
    }
  },
};
