// Line icons drawn for the toolkit (24 x 24, stroke currentColor). No product logos.

import { svgFromString } from "./dom.js";

const P = {
  endpoint: '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2.5 19h19"/>',
  server: '<rect x="4" y="3.5" width="16" height="7" rx="1.5"/><rect x="4" y="13.5" width="16" height="7" rx="1.5"/><path d="M8 7h.01M8 17h.01"/>',
  firewall: '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M3 9.5h18M3 14.5h18M9 4v5.5M15 9.5v5M9 14.5V20"/>',
  email: '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="m3.5 6 8.5 7 8.5-7"/>',
  identity: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c.8-3.6 3.6-5.5 7-5.5s6.2 1.9 7 5.5"/>',
  cloud: '<path d="M7 18.5h10.5a4 4 0 0 0 .4-8 6 6 0 0 0-11.5 1.6A3.3 3.3 0 0 0 7 18.5Z"/>',
  network: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><path d="M11 6.8 6 16.2M13 6.8l5 9.4M7 18h10"/>',
  integration: '<path d="M9 3v4M15 3v4M7 7h10v4a5 5 0 0 1-10 0V7ZM12 16v5"/>',
  radar: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 18 6"/>',
  mobile: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18.5h2"/>',
  tenant: '<path d="M4 20.5V6l8-3 8 3v14.5"/><path d="M9 20.5v-4h6v4M8.5 9h.01M12 9h.01M15.5 9h.01M8.5 12.5h.01M12 12.5h.01M15.5 12.5h.01"/>',
  shield: '<path d="M12 3 5 6v5.5c0 4.4 3 8 7 9.5 4-1.5 7-5.1 7-9.5V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>',
  team: '<circle cx="9" cy="8.5" r="3"/><path d="M3.5 19c.6-3 2.8-4.6 5.5-4.6S13.9 16 14.5 19"/><circle cx="17" cy="9.5" r="2.3"/><path d="M15.5 14.6c2.4-.3 4.4 1 5 3.9"/>',
  check: '<circle cx="12" cy="12" r="8.5"/><path d="m8 12.2 2.7 2.7L16 9.6"/>',
  open: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="2.5" fill="currentColor"/>',
  critical: '<path d="M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2Z"/><path d="M12 7.5v5.5M12 16.5h.01"/>',
  high: '<path d="M12 3.5 21.5 20h-19Z"/><path d="M12 10v4M12 17h.01"/>',
  medium: '<path d="m12 3 9 9-9 9-9-9Z"/>',
  low: '<circle cx="12" cy="12" r="6" fill="currentColor" stroke="none"/>',
  info: '<circle cx="12" cy="12" r="6"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  pause: '<path d="M9 5v14M15 5v14"/>',
  play: '<path d="M7 4.5v15l12-7.5Z"/>',
  wall: '<rect x="2.5" y="4" width="19" height="12.5" rx="1.5"/><path d="M8 20.5h8M12 16.5v4"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
  moon: '<path d="M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10Z"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  close: '<path d="M6 6l12 12M18 6 6 18"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.8-4.8"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2 5.5 5.5"/>',
  pin: '<path d="M12 21s-6.5-6.2-6.5-11a6.5 6.5 0 0 1 13 0c0 4.8-6.5 11-6.5 11Z"/><circle cx="12" cy="10" r="2.3"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>',
  cases: '<rect x="3.5" y="7" width="17" height="13" rx="1.5"/><path d="M9 7V4.5h6V7M3.5 12.5h17"/>',
  pulse: '<path d="M2.5 12h4l2.5-6 4 12 2.5-6h6"/>',
  grid: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.2"/>',
  flow: '<path d="M3 6c5 0 6 6 10 6M3 12h10M3 18c5 0 6-6 10-6"/><circle cx="17" cy="12" r="3.5"/>',
  warning: '<path d="M12 3.5 21.5 20h-19Z"/><path d="M12 10v4M12 17h.01"/>',
  offline: '<path d="M3 3l18 18M8.5 8.4A5.5 5.5 0 0 0 7 18.5h10M12.8 6.1a6 6 0 0 1 5.1 4.4 4 4 0 0 1 2.4 6.6"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  chevron: '<path d="m9 6 6 6-6 6"/>',
  down: '<path d="m6 9 6 6 6-6"/>',
  key: '<circle cx="8" cy="15" r="4.5"/><path d="m11.2 11.8 8.3-8.3M16 7l2.5 2.5M14 9l2 2"/>',
  trash: '<path d="M4 7h16M9 7V4.5h6V7M6.5 7l1 13h9l1-13"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="1.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 5.6A9.5 9.5 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-3 3.7M6.6 6.7C3.9 8.4 2.5 12 2.5 12S6 18.5 12 18.5c1.6 0 3-.4 4.2-1"/>',
  fullscreen: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  report: '<path d="M6 2.5h8.5L19 7v14.5H6Z"/><path d="M14 2.5V7h5M9.5 17v-3M12.5 17v-6M15.5 17v-4"/>',
  download: '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14"/>',
  isolate: '<rect x="6" y="6" width="12" height="12" rx="1.5"/><path d="M3 3l3 3M21 3l-3 3M3 21l3-3M21 21l-3-3"/>',
  spark: '<path d="M10 3.5c.6 3.6 2.4 5.4 6 6-3.6.6-5.4 2.4-6 6-.6-3.6-2.4-5.4-6-6 3.6-.6 5.4-2.4 6-6Z"/><path d="M18 14.5c.3 1.6 1.1 2.4 2.7 2.7-1.6.3-2.4 1.1-2.7 2.7-.3-1.6-1.1-2.4-2.7-2.7 1.6-.3 2.4-1.1 2.7-2.7Z"/>',
};

export function icon(name, size = 16, cls = "") {
  const body = P[name] ?? P.info;
  const el = svgFromString(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="ic ${cls}">${body}</svg>`,
  );
  return el;
}

export const SEV_ICON = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info", unset: "info" };

/** The icon for a data source label on the front page. */
export function sourceIcon(kind) {
  const k = (kind ?? "").toLowerCase();
  // Vendor, cloud and server names count as whole words only, as in sensorLabel, so Cloudflare is not a cloud.
  const text = ` ${k.split(/[^a-z0-9]+/).join(" ")} `;
  const named = (...names) => names.some((n) => text.includes(` ${n} `));
  // An identity provider or vault decides first, so Delinea Secret Server and Google Workspace are identity sources.
  if (k.includes("identity") || k.includes("itdr") || named("365", "entra", "okta", "duo", "google workspace", "cyberark", "delinea")) return "identity";
  // Third-party EDR reads by product name, so the vendor decides; Carbon Black Cloud is an endpoint source, not a cloud.
  if (k.includes("endpoint") || k.includes("computer") || k.includes("device") || named("crowdstrike", "sentinelone", "harfanglab", "carbon black")) return "endpoint";
  // Cloudflare is a reverse proxy and WAF in front of web apps; its HTTP logs carry allow and block actions.
  if (k.includes("firewall") || named("cloudflare", "waf", "fw", "fortigate")) return "firewall";
  if (k.includes("email") || k.includes("mail") || named("mimecast", "proofpoint", "abnormal")) return "email";
  if (k.includes("encrypt")) return "lock";
  // Cloud and SaaS names come before "server", so an Amazon S3 server access log is a cloud source.
  if (named("cloud", "aws", "amazon", "azure", "gcp", "salesforce", "box")) return "cloud";
  // Windows event logs and IIS logs come from Windows servers; DNS and DHCP logs are network sources.
  if (named("server", "windows", "iis")) return "server";
  if (k.includes("ndr") || k.includes("network") || k.includes("wireless") || named("dns", "dhcp")) return "network";
  if (k.includes("mobile")) return "mobile";
  if (k.includes("integration")) return "integration";
  if (k.includes("tenant")) return "tenant";
  return "radar";
}
