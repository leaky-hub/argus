import { api, RunDetail } from "../api";
import { GateBadge } from "../components";
import { CompliancePanel } from "./CompliancePanel";
import { Findings } from "./Findings";

// RunDetailView is one run's own page inside the Runs tab: its gate, its
// compliance posture, an export, and its findings (with ticket tracking and
// remediation in the drawer). The Findings tab, by contrast, always shows the
// latest run — every current finding — so the two views don't collide.
export function RunDetailView({
  detail,
  runLabel,
  targetId,
  origin,
  onBack,
  onSelectFramework,
  canExplain,
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
  canSuppress?: boolean;
  onSuppress?: (ruleId: string) => void;
  framework: string;
  onFrameworkChange: (v: string) => void;
  severity: string;
  onSeverityChange: (v: string) => void;
  status: string;
  onStatusChange: (v: string) => void;
}) {
  const delta = detail.delta;
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
              <span>{detail.total} findings</span>
              <GateBadge gate={detail.gate} />
              {(delta.new > 0 || delta.resolved > 0) && (
                <span>
                  {delta.new > 0 && <span className="text-amber-600 dark:text-amber-400">+{delta.new} new</span>}
                  {delta.new > 0 && delta.resolved > 0 && " · "}
                  {delta.resolved > 0 && <span className="text-emerald-600 dark:text-emerald-400">-{delta.resolved} resolved</span>}
                  <span className="text-gray-400"> vs previous run</span>
                </span>
              )}
            </div>
          </div>
        </div>
        <a
          href={api.exportUrl(detail.id, "html", targetId)}
          target="_blank"
          rel="noopener"
          className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 hover:bg-blue-100 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-300 dark:hover:bg-blue-900/40"
        >
          ↗ Export report
        </a>
      </div>

      {detail.compliance && detail.compliance.length > 0 && (
        <CompliancePanel compliance={detail.compliance} onSelect={onSelectFramework} />
      )}

      <Findings
        detail={detail}
        origin={origin}
        canExplain={canExplain}
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
