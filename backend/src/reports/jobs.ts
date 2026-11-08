/**
 * Report runs in this process: start one in the background, follow its
 * progress, and keep the last few documents in memory for the preview and
 * the exports. Nothing is written to disk. A run belongs to the provider
 * (credential or demo) that made it, so switching credentials hides it.
 */

import { randomUUID } from "node:crypto";
import type { Provider } from "../services/provider.js";
import type { Engine } from "../services/engine.js";
import type { Settings } from "../store/settings.js";
import { maskSecrets } from "../log.js";
import { DemoReportSource } from "./demo.js";
import { ReportInputError } from "./queries.js";
import { runReport, type CheckedRequest } from "./runner.js";
import { LiveReportSource, type ReportSource } from "./source.js";
import type { ReportDocument } from "./types.js";

export interface ReportRun {
  id: string;
  reportId: string;
  title: string;
  status: "running" | "done" | "failed";
  step: string;
  startedAt: number;
  finishedAt: number | null;
  error: string | null;
  document: ReportDocument | null;
  provider: Provider;
  /** Settles when the run ends, for the tests and a scheduler. */
  finished?: Promise<void>;
}

export const MAX_RUNNING = 2;
const KEEP = 20;

export function sourceFor(provider: Provider): ReportSource {
  return provider.kind === "live" ? new LiveReportSource(provider as unknown as Engine) : new DemoReportSource(provider);
}

function message(err: unknown): string {
  if (err instanceof ReportInputError) return err.message;
  const text = maskSecrets(err instanceof Error ? err.message : String(err));
  if (/Blocked by the read-only guard/.test(text)) return text;
  if (/403|forbidden|denied/i.test(text)) return "Sophos refused a read this report needs (HTTP 403): the credential's role or the tenant's licence does not cover it.";
  if (/did not finish within/i.test(text)) return "A search took longer than 3 minutes. It keeps running at Sophos; run the report again in a minute and it will pick the search up.";
  return text.slice(0, 400);
}

export class ReportJobs {
  private runs: ReportRun[] = [];

  running(provider: Provider): number {
    return this.runs.filter((r) => r.status === "running" && r.provider === provider).length;
  }

  start(provider: Provider, checked: CheckedRequest, settings: Settings, source: ReportSource = sourceFor(provider)): ReportRun {
    if (this.running(provider) >= MAX_RUNNING) throw new ReportInputError(`${MAX_RUNNING} reports are running already. Wait for one to finish.`);
    const run: ReportRun = { id: randomUUID(), reportId: checked.def.id, title: checked.def.title, status: "running", step: "Starting", startedAt: Date.now(), finishedAt: null, error: null, document: null, provider };
    this.runs.unshift(run);
    // Finished runs beyond the newest few are dropped; running ones are kept.
    const done = this.runs.filter((r) => r.status !== "running");
    if (done.length > KEEP) {
      const drop = new Set(done.slice(KEEP));
      this.runs = this.runs.filter((r) => !drop.has(r));
    }
    run.finished = runReport(checked, { source, settings, progress: (step) => (run.step = step) })
      .then((doc) => {
        run.document = doc;
        run.status = "done";
        run.step = "Done";
      })
      .catch((err: unknown) => {
        run.status = "failed";
        run.error = message(err);
        run.step = "Failed";
      })
      .finally(() => {
        run.finishedAt = Date.now();
      });
    return run;
  }

  get(id: string, provider: Provider): ReportRun | null {
    return this.runs.find((r) => r.id === id && r.provider === provider) ?? null;
  }

  list(provider: Provider): ReportRun[] {
    return this.runs.filter((r) => r.provider === provider);
  }

  clear(): void {
    this.runs = [];
  }
}

export function summaryOf(run: ReportRun) {
  return {
    id: run.id,
    reportId: run.reportId,
    title: run.title,
    subject: run.document?.subject ?? null,
    scope: run.document?.scope.label ?? null,
    status: run.status,
    step: run.step,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    error: run.error,
  };
}
