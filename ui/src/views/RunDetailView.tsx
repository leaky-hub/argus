import { useEffect, useState } from "react";
import { api, RunDetail, RunListItem } from "../api";
import { GateBadge } from "../components";
import { CompliancePanel } from "./CompliancePanel";
import { Findings } from "./Findings";

// RunDetailView is one run's own page inside the Runs tab: its gate, its
// compliance posture, an export, and its findings (with ticket tracking and
// remediation in the drawer). The Findings tab, by contrast, always shows the
// latest run — every current finding — so the two views don't collide.
//
// A baseline picker lets the reader choose which earlier run the "new vs known"
// delta is measured against (the immediately-previous run by default). Changing
// it refetches the run with ?baseline=<id>; the server recomputes newIds, so
// every NEW badge and the delta counter update to the chosen baseline. This is
// the console surface for the CLI's --baseline gating: see exactly what a run
// added since a reference point.
export function RunDetailView({
  detail,
  runLabel,
  targetId,
  origin,
  onBack,
  onSelectFramework,
  canExplain,
  canRemediate,
  canSuppress,
  onSuppress,
  framework,
  onFrameworkChange,
  severity,
  onSeverityChange,
  status,
  onStatusChange,
}: {
  detail: RunDetail;
  runLabel: string;
  targetId?: string;
  origin?: { targetId?: string; gitUrl?: string; commit?: string };
  onBack: () => void;
  onSelectFramework?: (id: string) => void;
  canExplain?: boolean;
  canRemediate?: boolean;
  canSuppress?: boolean;
  onSuppress?: (ruleId: string) => void;
  framework: string;
  onFrameworkChange: (v: string) => void;
  severity: string;
  onSeverityChange: (v: string) => void;
  status: string;
  onStatusChange: (v: string) => void;
}) {
  // "" means the default comparison (the immediately-previous run).
  const [baselineChoice, setBaselineChoice] = useState("");
  const [compared, setCompared] = useState<RunDetail | null>(null);
  const [comparing, setComparing] = useState(false);
  const [runs, setRuns] = useState<RunListItem[]>([]);

  // Load the run list once so the picker can offer every earlier run as a
  // baseline (labelled by timestamp). Failure just leaves the picker empty.
  useEffect(() => {
    let live = true;
    api
      .runs(targetId)
      .then((r) => live && setRuns(r.runs))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [targetId]);

  // A new run resets the comparison back to its default.
  useEffect(() => {
    setBaselineChoice("");
    setCompared(null);
  }, [detail.id]);

  // Refetch against the chosen baseline. "" restores the server default (the
  // parent-provided detail), so we drop the override rather than refetch.
  useEffect(() => {
    if (baselineChoice === "") {
      setCompared(null);
      return;
    }
    let live = true;
    setComparing(true);
    api
      .run(detail.id, targetId, baselineChoice)
      .then((d) => live && setCompared(d))
      .catch(() => live && setCompared(null))
      .finally(() => live && setComparing(false));
    return () => {
      live = false;
    };
  }, [baselineChoice, detail.id, targetId]);

  const view = compared ?? detail;
  const delta = view.delta;

  // Candidate baselines: every run older than this one (runs are newest-first).
  const thisIdx = runs.findIndex((r) => r.id === detail.id);
  const olderRuns = thisIdx >= 0 ? runs.slice(thisIdx + 1) : [];
  const baselineLabel = labelFor(runs, view.baselineId);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            ← All runs
          </button>
          <div>
            <div className="text-sm font-semibold">Run · {runLabel}</div>
            <div className="flex items-center gap-2 text-xs text-gray-500">
              <span>{view.total} findings</span>
              <GateBadge gate={view.gate} />
              {(delta.new > 0 || delta.resolved > 0) && (
                <span>
                  {delta.new > 0 && <span className="text-amber-600 dark:text-amber-400">+{delta.new} new</span>}
                  {delta.new > 0 && delta.resolved > 0 && " · "}
                  {delta.resolved > 0 && <span className="text-emerald-600 dark:text-emerald-400">-{delta.resolved} resolved</span>}
                  <span className="text-gray-400"> vs {baselineLabel}</span>
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {olderRuns.length > 0 && (
            <label className="flex items-center gap-1.5 text-xs text-gray-500">
              <span>Baseline</span>
              <select
                value={baselineChoice}
                onChange={(e) => setBaselineChoice(e.target.value)}
                disabled={comparing}
                className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200"
              >
                <option value="">Previous run</option>
                {olderRuns.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.createdAt.replace("T", " ").replace("Z", " UTC")}
                  </option>
                ))}
              </select>
            </label>
          )}
          <a
            href={api.exportUrl(view.id, "html", targetId)}
            target="_blank"
            rel="noopener"
            className="rounded-md border border-accent-200 bg-accent-50 px-2 py-1 text-xs font-medium text-accent-700 hover:bg-accent-100 dark:border-accent-800 dark:bg-accent-500/10 dark:text-accent-300 dark:hover:bg-accent-500/20"
          >
            ↗ Export report
          </a>
        </div>
      </div>

      {view.compliance && view.compliance.length > 0 && (
        <CompliancePanel compliance={view.compliance} onSelect={onSelectFramework} />
      )}

      <Findings
        detail={view}
        origin={origin}
        canExplain={canExplain}
        canRemediate={canRemediate}
        canSuppress={canSuppress}
        onSuppress={onSuppress}
        framework={framework}
        onFrameworkChange={onFrameworkChange}
        severity={severity}
        onSeverityChange={onSeverityChange}
        status={status}
        onStatusChange={onStatusChange}
      />
    </div>
  );
}

// labelFor renders a human label for the baseline a delta was computed against.
function labelFor(runs: RunListItem[], baselineId: string): string {
  if (!baselineId) return "previous run";
  const r = runs.find((x) => x.id === baselineId);
  if (!r) return "baseline";
  return r.createdAt.replace("T", " ").replace("Z", " UTC");
}
