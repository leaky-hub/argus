import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  opsApi,
  setCsrfToken,
  ApiError,
  MeResponse,
  UserInfo,
  RunDetail,
  RunsResponse,
  SummaryResponse,
  Target,
} from "./api";
import { Loading, ErrorNote, Wordmark } from "./components";
import { useToast, useConfirm } from "./toast";
import { fmtTime } from "./theme";
import { Overview } from "./views/Overview";
import { Findings } from "./views/Findings";
import { Runs } from "./views/Runs";
import { Login } from "./views/Login";
import { Operate } from "./views/Operate";
import { Admin } from "./views/Admin";

type Tab = "overview" | "findings" | "runs" | "operate" | "admin";

const ROLE_CHIP: Record<string, string> = {
  admin: "bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300",
  operator: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300",
  viewer: "bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
};

// UrlState is the app view encoded in the query string so a view is
// shareable, reload-safe, and back/forward-navigable.
type UrlState = { tab: Tab; target: string; run: string | null; fw: string; sev: string; status: string };

function readUrlState(): UrlState {
  const p = new URLSearchParams(window.location.search);
  const t = p.get("tab") ?? "";
  const tab = (["findings", "runs", "operate", "admin"].includes(t) ? t : "overview") as Tab;
  return {
    tab,
    target: p.get("target") ?? "",
    run: p.get("run"),
    fw: p.get("fw") ?? "all",
    sev: p.get("sev") ?? "all",
    status: p.get("st") ?? "all",
  };
}

function urlFromState(s: UrlState): string {
  const p = new URLSearchParams();
  if (s.tab !== "overview") p.set("tab", s.tab);
  if (s.target) p.set("target", s.target);
  if (s.run) p.set("run", s.run);
  if (s.fw !== "all") p.set("fw", s.fw);
  if (s.sev !== "all") p.set("sev", s.sev);
  if (s.status !== "all") p.set("st", s.status);
  const qs = p.toString();
  return qs ? `?${qs}` : window.location.pathname;
}

export function App() {
  const [initial] = useState(readUrlState);
  const [tab, setTab] = useState<Tab>(initial.tab);
  const [dark, setDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);

  const [me, setMe] = useState<MeResponse | null>(null);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [runs, setRuns] = useState<RunsResponse | null>(null);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [selectedRun, setSelectedRun] = useState<string | null>(initial.run);
  const [selectedRunTarget, setSelectedRunTarget] = useState<string | undefined>(initial.run ? initial.target || undefined : undefined);
  const [selectedRunCommit, setSelectedRunCommit] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [targets, setTargets] = useState<Target[]>([]);
  // "" = the served repo's own run store; otherwise a registered target's id.
  // Overview/Runs/Findings all read this store.
  const [activeTarget, setActiveTarget] = useState<string>(initial.target);
  const [rescanBusy, setRescanBusy] = useState(false);
  // Findings filters lifted here so the Overview panels can deep-link into a
  // filtered Findings view (every stat is a drill-down).
  const [findingsFramework, setFindingsFramework] = useState<string>(initial.fw);
  const [findingsSeverity, setFindingsSeverity] = useState<string>(initial.sev);
  const [findingsStatus, setFindingsStatus] = useState<string>(initial.status);

  // Keep the URL in lockstep with the view: pushState on navigation-significant
  // changes (tab/target/run) so Back works, replaceState for incidental filter
  // tweaks. A popstate re-applies the URL without re-pushing (navKey guard).
  const navKeyRef = useRef(`${initial.tab}|${initial.target}|${initial.run ?? ""}`);
  useEffect(() => {
    const s: UrlState = { tab, target: activeTarget, run: selectedRun, fw: findingsFramework, sev: findingsSeverity, status: findingsStatus };
    const url = urlFromState(s);
    const navKey = `${tab}|${activeTarget}|${selectedRun ?? ""}`;
    if (navKey !== navKeyRef.current) {
      navKeyRef.current = navKey;
      window.history.pushState(null, "", url);
    } else {
      window.history.replaceState(null, "", url);
    }
  }, [tab, activeTarget, selectedRun, findingsFramework, findingsSeverity, findingsStatus]);

  useEffect(() => {
    const onPop = () => {
      const s = readUrlState();
      navKeyRef.current = `${s.tab}|${s.target}|${s.run ?? ""}`; // so the sync effect replaces, not pushes
      setTab(s.tab);
      setActiveTarget(s.target);
      setSelectedRun(s.run);
      setSelectedRunTarget(s.run ? s.target || undefined : undefined);
      setFindingsFramework(s.fw);
      setFindingsSeverity(s.sev);
      setFindingsStatus(s.status);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  // Session expiry mid-use surfaces as a 401 on any call: drop back to the
  // login page instead of a dead error screen.
  const toast = useToast();
  const confirm = useConfirm();

  const onApiError = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) {
      setUser(null);
      setCsrfToken(null);
      return;
    }
    setError(String(e));
  }, []);

  // For action failures (not page loads): a toast, not a full-page error.
  const onActionError = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) return onApiError(e);
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    },
    [onApiError, toast],
  );

  // Boot: ask the server whether this console requires a login at all.
  useEffect(() => {
    opsApi
      .me()
      .then((m) => {
        setMe(m);
        if (m.authenticated && m.user) {
          setUser(m.user);
          setCsrfToken(m.csrfToken ?? null);
        }
      })
      .catch((e) => setError(String(e)));
  }, []);

  const authed = me !== null && (!me.authRequired || user !== null);

  // Load read data once authenticated (or immediately in zero-users mode).
  // Everything is scoped to the active target (empty = the served repo's own
  // store): Overview, Runs, and the run picker all follow it, so a scan
  // launched against a registered target shows up instead of vanishing into a
  // store nothing reads. Changing the target resets the selected run.
  useEffect(() => {
    if (!authed) return;
    const tgt = activeTarget || undefined;
    Promise.all([api.summary(tgt), api.runs(tgt)])
      .then(([s, r]) => {
        setSummary(s);
        setRuns(r);
        setSelectedRunTarget(tgt);
        setSelectedRun(s.latestId || r.runs?.[0]?.id || null);
      })
      .catch(onApiError);
  }, [authed, activeTarget, reloadKey, onApiError]);

  // Fetch targets when ops is enabled
  useEffect(() => {
    if (!authed || !me?.authRequired) return;
    opsApi.targets().then((r) => setTargets(r.targets)).catch(() => {});
  }, [authed, me?.authRequired, reloadKey]);

  useEffect(() => {
    if (!authed || !selectedRun) return;
    api.run(selectedRun, selectedRunTarget).then(setDetail).catch(onApiError);
  }, [authed, selectedRun, selectedRunTarget, onApiError]);

  const handleLogin = (u: UserInfo, csrf: string) => {
    setCsrfToken(csrf);
    setUser(u);
  };

  const handleLogout = () => {
    opsApi.logout().catch(() => undefined);
    setCsrfToken(null);
    setUser(null);
    setSummary(null);
    setRuns(null);
    setDetail(null);
    setSelectedRunTarget(undefined);
    setSelectedRunCommit(undefined);
    setTab("overview");
  };

  // A finished job links straight to its run: refresh the lists so the new
  // run exists in the picker, then open it in Findings.
  // Re-scan the active target: enqueue a job (options default; cloud targets
  // take none) and refresh the lists so the run appears when the queue
  // finishes. Closes the remediation loop — "re-scan to confirm the fix".
  const handleRescan = () => {
    if (!activeTarget || rescanBusy) return;
    setRescanBusy(true);
    opsApi
      .launchScan(activeTarget, {})
      .then(() => {
        toast({ kind: "success", message: "Re-scan queued — results will appear when it finishes." });
        // The run lands when the serial queue finishes; nudge a reload shortly.
        setTimeout(() => setReloadKey((k) => k + 1), 1500);
      })
      .catch(onActionError)
      .finally(() => setRescanBusy(false));
  };

  // Suppress a finding's rule: append its ruleId to the ACTIVE TARGET's
  // ignore list (admin, audited). Only registered targets have a
  // console-editable config; the served repo's own appsec.yml is not touched
  // from here. Preserves the rest of the target's config block.
  const handleSuppress = async (ruleId: string) => {
    const t = targets.find((t) => t.id === activeTarget);
    if (!t || !ruleId) return;
    const existing = t.config ?? {};
    const rules = existing.ignoreRules ?? [];
    if (rules.includes(ruleId)) {
      toast({ kind: "info", message: `Rule "${ruleId}" is already suppressed for this target.` });
      return;
    }
    const ok = await confirm({
      title: `Suppress rule "${ruleId}"?`,
      message: `Findings from this rule will stop appearing for target "${t.name}" (admin action, audited).`,
      confirmLabel: "Suppress",
      danger: true,
    });
    if (!ok) return;
    opsApi
      .updateTarget(activeTarget, { config: { ...existing, ignoreRules: [...rules, ruleId] } })
      .then((updated) => {
        setTargets((prev) => prev.map((x) => (x.id === updated.id ? updated : x)));
        setReloadKey((k) => k + 1);
        toast({ kind: "success", message: `Rule "${ruleId}" suppressed.` });
      })
      .catch(onActionError);
  };

  const handleDeleteRun = async (runId: string) => {
    const ok = await confirm({
      title: "Delete this run from history?",
      message: "This cannot be undone.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    opsApi
      .deleteRun(runId, activeTarget || undefined)
      .then(() => {
        if (selectedRun === runId) setSelectedRun(null);
        setReloadKey((k) => k + 1);
        toast({ kind: "success", message: "Run deleted." });
      })
      .catch(onActionError);
  };

  // Deep-links from Overview panels into a filtered Findings view. Each sets
  // its own filter and resets the others so the drill-down is clean.
  const drillTo = (which: "framework" | "severity" | "status", value: string) => {
    setFindingsFramework(which === "framework" ? value : "all");
    setFindingsSeverity(which === "severity" ? value : "all");
    setFindingsStatus(which === "status" ? value : "all");
    setTab("findings");
  };
  const openFramework = (id: string) => drillTo("framework", id);

  const openRun = (runId: string, targetId?: string, commit?: string) => {
    // Switch the whole app to that run's target so Overview/Runs agree with
    // the finding drawer, then open it with filters cleared.
    setActiveTarget(targetId ?? "");
    setSelectedRun(runId);
    setSelectedRunTarget(targetId);
    setSelectedRunCommit(commit);
    setFindingsFramework("all");
    setFindingsSeverity("all");
    setFindingsStatus("all");
    setReloadKey((k) => k + 1);
    setTab("findings");
  };

  if (error) return <ErrorNote error={error} />;
  if (me === null) return <Loading what="console" />;
  if (me.authRequired && !user) return <Login onLogin={handleLogin} />;
  if (!summary || !runs) return <Loading what="console" />;

  const role = user?.role ?? "";
  const opsEnabled = me.authRequired; // zero users = the read-only console
  const canLaunch = role === "operator" || role === "admin";
  const canExplain = opsEnabled && (role === "operator" || role === "admin");

  // Build origin for Findings if a target-scoped run is selected
  let origin: { targetId?: string; gitUrl?: string; commit?: string } | undefined;
  if (selectedRunTarget) {
    const t = targets.find((t) => t.id === selectedRunTarget);
    if (t) {
      origin = { targetId: t.id, gitUrl: t.url, commit: selectedRunCommit };
    } else {
      origin = { targetId: selectedRunTarget, commit: selectedRunCommit };
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "findings", label: "Findings" },
    { id: "runs", label: "Runs" },
    ...(opsEnabled ? [{ id: "operate" as Tab, label: "Operate" }] : []),
    ...(opsEnabled && role === "admin" ? [{ id: "admin" as Tab, label: "Admin" }] : []),
  ];
  const activeTab = tabs.some((t) => t.id === tab) ? tab : "overview";

  return (
    <div className="mx-auto min-h-full max-w-7xl px-4 pb-16">
      <header className="sticky top-0 z-10 -mx-4 mb-4 border-b border-gray-200 bg-gray-50/90 px-4 py-3 backdrop-blur dark:border-gray-800 dark:bg-gray-950/90">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Wordmark size={22} className="text-lg" />
            <span className="rounded bg-gray-200 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-gray-600 dark:bg-gray-800 dark:text-gray-300">
              console
            </span>
          </div>

          <nav className="flex gap-1">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                  activeTab === t.id
                    ? "bg-blue-600 text-white"
                    : "text-gray-600 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-800"
                }`}
              >
                {t.label}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            {opsEnabled && targets.length > 0 && (
              <label className="hidden items-center gap-1 text-xs text-gray-500 lg:flex">
                Target
                <select
                  value={activeTarget}
                  onChange={(e) => setActiveTarget(e.target.value)}
                  className="max-w-[200px] rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
                  title="Which run history to show across Overview, Runs, and Findings"
                >
                  <option value="">This repo</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}{t.type === "cloud" ? " (cloud)" : t.type === "git" ? " (git)" : ""}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {runs.runs.length > 0 && (
              <label className="hidden items-center gap-1 text-xs text-gray-500 md:flex">
                Run
                <select
                  value={selectedRun ?? ""}
                  onChange={(e) => {
                    setSelectedRun(e.target.value);
                    setSelectedRunCommit(undefined);
                  }}
                  className="max-w-[190px] rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
                >
                  {runs.runs.map((r) => (
                    <option key={r.id} value={r.id}>
                      {fmtTime(r.createdAt)} ({r.total})
                    </option>
                  ))}
                </select>
              </label>
            )}
            {user && (
              <div className="flex items-center gap-2 text-xs">
                <span className="font-medium">{user.username}</span>
                <span className={`rounded px-1.5 py-0.5 font-semibold ${ROLE_CHIP[role] || ROLE_CHIP.viewer}`}>
                  {role}
                </span>
                <button
                  onClick={handleLogout}
                  className="rounded-lg border border-gray-300 px-2 py-1 text-xs text-gray-600 hover:bg-gray-200 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
                >
                  Sign out
                </button>
              </div>
            )}
            <button
              onClick={() => setDark((d) => !d)}
              className="rounded-lg border border-gray-300 px-2 py-1 text-sm dark:border-gray-700"
              title="Toggle theme"
            >
              {dark ? "☀️" : "🌙"}
            </button>
          </div>
        </div>
      </header>

      <main>
        {activeTab === "overview" && (
          <Overview
            summary={summary}
            onSelectFramework={openFramework}
            onSelectSeverity={(sev) => drillTo("severity", sev)}
            onSelectStatus={(st) => drillTo("status", st)}
          />
        )}
        {activeTab === "findings" &&
          (detail ? (
            <Findings
              detail={detail}
              origin={origin}
              canExplain={canExplain}
              canSuppress={role === "admin" && !!activeTarget}
              onSuppress={handleSuppress}
              framework={findingsFramework}
              onFrameworkChange={setFindingsFramework}
              severity={findingsSeverity}
              onSeverityChange={setFindingsSeverity}
              status={findingsStatus}
              onStatusChange={setFindingsStatus}
            />
          ) : (
            <Loading what="findings" />
          ))}
        {activeTab === "runs" && (
          <Runs
            runs={runs}
            selectedId={selectedRun}
            onSelect={(id) => {
              setSelectedRun(id);
              setTab("findings");
            }}
            activeTarget={activeTarget}
            canLaunch={canLaunch}
            canDelete={role === "admin"}
            rescanBusy={rescanBusy}
            onRescan={handleRescan}
            onDeleteRun={handleDeleteRun}
          />
        )}
        {activeTab === "operate" && opsEnabled && <Operate canLaunch={canLaunch} onOpenRun={openRun} />}
        {activeTab === "admin" && role === "admin" && <Admin selfUsername={user?.username ?? ""} />}
      </main>

      <footer className="mt-8 text-center text-[11px] text-gray-400">
        {opsEnabled
          ? "Local-first · authenticated console · actions audited to .appsec/audit.jsonl · finding data rendered inert"
          : "Local-first · read-only (no users configured — bootstrap: bulwark user add) · finding data rendered inert"}
      </footer>
    </div>
  );
}
