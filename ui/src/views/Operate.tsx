import { useEffect, useState } from "react";
import { opsApi, Target, Job, JobOptions, ApiError, KNOWN_SCANNERS, PROFILES } from "../api";
import { Panel, Loading, ErrorNote, EmptyState } from "../components";
import { fmtTime } from "../theme";

export function Operate({ canLaunch, onOpenRun }: { canLaunch: boolean; onOpenRun: (runId: string) => void }) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Launcher state
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanners, setScanners] = useState<Set<string>>(new Set());
  const [profile, setProfile] = useState("");
  const [triage, setTriage] = useState<"default" | "on" | "off">("default");
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);

  // Expanded job state
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // One stable effect: initial load plus a fixed-interval poll (the queue
  // advances server-side). A transient poll failure never blanks the page —
  // only the first load surfaces as a full-screen error.
  useEffect(() => {
    let alive = true;
    let first = true;
    const load = async () => {
      try {
        const [t, j] = await Promise.all([opsApi.targets(), opsApi.jobs()]);
        if (!alive) return;
        setTargets(t.targets);
        setJobs(j.jobs);
        setSelectedTargetId((cur) => cur || t.targets[0]?.id || "");
        setError(null);
        setLoading(false);
      } catch (err) {
        if (!alive) return;
        if (first) {
          setError(err instanceof ApiError ? err.message : String(err));
          setLoading(false);
        }
      }
      first = false;
    };
    load();
    const interval = setInterval(load, 2500);
    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, []);

  // Reset scanners when target changes
  const handleTargetChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newId = e.target.value;
    setSelectedTargetId(newId);
    setScanners(new Set());
  };

  const toggleScanner = (scanner: string) => {
    setScanners((prev) => {
      const next = new Set(prev);
      if (next.has(scanner)) next.delete(scanner);
      else next.add(scanner);
      return next;
    });
  };

  const handleLaunch = async () => {
    if (!selectedTargetId || launching) return;
    setLaunching(true);
    setLaunchError(null);
    try {
      const options: JobOptions = {};
      if (scanners.size > 0) options.scanners = Array.from(scanners);
      if (profile) options.profile = profile;
      if (triage !== "default") options.triage = triage === "on";

      const job = await opsApi.launchScan(selectedTargetId, options);
      setJobs((prev) => [job, ...prev]);
    } catch (err) {
      setLaunchError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLaunching(false);
    }
  };

  if (loading) return <Loading what="data" />;
  if (error) return <ErrorNote error={error} />;

  const selectedTarget = targets.find((t) => t.id === selectedTargetId);
  const allowedScanners = selectedTarget?.scanners && selectedTarget.scanners.length > 0
    ? selectedTarget.scanners
    : KNOWN_SCANNERS;

  const queuedCount = jobs.filter((j) => j.status === "queued").length;
  const runningCount = jobs.filter((j) => j.status === "running").length;

  return (
    <div className="space-y-6">
      {canLaunch && (
        <Panel title="Launch scan">
          {targets.length === 0 ? (
            <EmptyState
              title="No targets registered"
              hint="An admin must register targets: appsec target add <path> --name <label> (or Admin → Targets)."
            />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {/* Target Select */}
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Target</label>
                <select
                  value={selectedTargetId}
                  onChange={handleTargetChange}
                  className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>

              {/* Scanners Checkboxes */}
              <div className="md:col-span-2">
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Scanners</label>
                <div className="flex flex-wrap gap-3">
                  {allowedScanners.map((s) => (
                    <label key={s} className="inline-flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={scanners.has(s)}
                        onChange={() => toggleScanner(s)}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800"
                      />
                      <span>{s}</span>
                    </label>
                  ))}
                </div>
                {scanners.size === 0 && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    None checked = target default (all allowed scanners run)
                  </p>
                )}
              </div>

              {/* Profile Select */}
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Profile</label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  <option value="">target default</option>
                  {PROFILES.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>

              {/* Triage Select */}
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">AI Triage</label>
                <select
                  value={triage}
                  onChange={(e) => setTriage(e.target.value as "default" | "on" | "off")}
                  className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  <option value="default">repo config</option>
                  <option value="on">enabled</option>
                  <option value="off">disabled</option>
                </select>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Model/provider always come from the repo's appsec.yml
                </p>
              </div>

              {/* Launch Button */}
              <div className="md:col-span-2 flex items-end justify-start">
                <button
                  onClick={handleLaunch}
                  disabled={!selectedTargetId || launching}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                >
                  {launching ? "Launching..." : "Launch Scan"}
                </button>
              </div>
            </div>
          )}
          {launchError && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{launchError}</p>}
        </Panel>
      )}

      <Panel title="Scan jobs" right={<span className="text-xs font-medium text-gray-500 dark:text-gray-400">
        {queuedCount} queued · {runningCount} running
      </span>}>
        {jobs.length === 0 ? (
          <EmptyState
            title="No scans launched yet"
            hint={canLaunch ? "Pick a target above and hit Launch." : "Operators and admins can launch scans."}
          />
        ) : (
          <div className="scroll-thin overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="text-xs uppercase text-gray-500">
                <tr>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Target</th>
                  <th className="py-2 pr-3">Launched by</th>
                  <th className="py-2 pr-3">Queued</th>
                  <th className="py-2 pr-3">Finished</th>
                  <th className="py-2 pr-3">Run</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <JobRow
                    key={job.id}
                    job={job}
                    expandedId={expandedId}
                    onToggle={() => setExpandedId(expandedId === job.id ? null : job.id)}
                    onOpenRun={onOpenRun}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
          One scan runs at a time; up to 10 queue behind it. Progress refreshes every few seconds.
        </p>
      </Panel>
    </div>
  );
}

function JobRow({
  job,
  expandedId,
  onToggle,
  onOpenRun,
}: {
  job: Job;
  expandedId: string | null;
  onToggle: () => void;
  onOpenRun: (id: string) => void;
}) {
  const isExpanded = expandedId === job.id;

  // Status Chip Logic
  let statusClass = "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300";
  let dotColor = "bg-gray-400";
  if (job.status === "queued") {
    statusClass = "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300";
    dotColor = "bg-gray-400";
  } else if (job.status === "running") {
    statusClass = "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300";
    dotColor = "bg-blue-500 animate-pulse";
  } else if (job.status === "done") {
    statusClass = "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300";
    dotColor = "bg-green-500";
  } else if (job.status === "failed") {
    statusClass = "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300";
    dotColor = "bg-red-500";
  }

  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-t border-gray-100 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50 ${isExpanded ? "bg-gray-50 dark:bg-gray-900" : ""}`}
      >
        <td className="py-2.5 pr-3">
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-semibold ${statusClass}`}>
            <span className={`h-2 w-2 rounded-full ${dotColor}`} />
            {job.status}
          </span>
        </td>
        <td className="py-2.5 pr-3 font-medium">{job.targetName}</td>
        <td className="py-2.5 pr-3 text-gray-600 dark:text-gray-400">{job.launchedBy}</td>
        <td className="py-2.5 pr-3 text-gray-600 dark:text-gray-400">
          {fmtTime(job.queuedAt)}
        </td>
        <td className="py-2.5 pr-3 text-gray-600 dark:text-gray-400">
          {job.finishedAt ? fmtTime(job.finishedAt) : "—"}
        </td>
        <td className="py-2.5 pr-3">
          {job.runId ? (
            <button
              onClick={(e) => { e.stopPropagation(); onOpenRun(job.runId!); }}
              className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
            >
              view run →
            </button>
          ) : job.status === "failed" ? (
            <span title={job.error || "Unknown error"} className="text-red-600 dark:text-red-400">
              failed
            </span>
          ) : (
            <span className="text-gray-400">—</span>
          )}
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={6} className="p-0">
            <div className="px-4 pb-4 pt-2">
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-gray-950 p-3 font-mono text-[11px] leading-relaxed text-gray-200">
                {job.progress.join("")}
              </pre>
              {job.error && (
                <p className="mt-2 text-xs text-red-600 dark:text-red-400">
                  Error: {job.error}
                </p>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
