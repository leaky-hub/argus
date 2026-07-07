import { useEffect, useState } from "react";
import { opsApi, SettingsView, SettingsInput, TriageSettings, ApiError } from "../api";
import { Panel } from "../components";

const inputClass =
  "w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500";
const labelClass = "mb-1 block text-xs uppercase text-gray-500 dark:text-gray-400";
const hintClass = "mt-1 text-xs text-gray-500 dark:text-gray-400";

export function ConsoleSettingsPanel(): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [view, setView] = useState<SettingsView | null>(null);

  const [githubRepo, setGithubRepo] = useState("");
  const [githubTokenEnv, setGithubTokenEnv] = useState("");
  const [scanProfile, setScanProfile] = useState("standard");
  const [failSeverity, setFailSeverity] = useState("high");
  const [remediationEnabled, setRemediationEnabled] = useState(false);

  const defaultTriage: TriageSettings = {
    enabled: false,
    provider: "ollama",
    model: "",
    endpoint: "",
    maxFindings: 0,
    excludeFp: false,
  };

  const [triage, setTriage] = useState<TriageSettings>(defaultTriage);

  function seed(v: SettingsView) {
    setView(v);
    setGithubRepo(v.githubRepo || "");
    setGithubTokenEnv(v.githubTokenEnv || "");
    setScanProfile(v.scanProfile || "");
    setFailSeverity(v.failSeverity || "");
    setRemediationEnabled(v.remediationEnabled ?? false);
    setTriage(v.triage || defaultTriage);
  }

  useEffect(() => {
    opsApi
      .getSettings()
      .then((v) => seed(v))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load settings"))
      .finally(() => setLoading(false));
  }, []);

  async function handleSave() {
    setSaved(false);
    setError(null);
    setBusy(true);
    try {
      const input: SettingsInput = {
        githubRepo: githubRepo || undefined,
        githubTokenEnv: githubTokenEnv || undefined,
        triage: { ...triage },
        scanProfile: scanProfile || undefined,
        failSeverity: failSeverity || undefined,
        remediationEnabled: remediationEnabled,
      };
      const resp = await opsApi.saveSettings(input);
      seed(resp);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save settings");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Panel title="Integrations & scanning"><div className="text-sm text-gray-500">Loading…</div></Panel>;

  return (
    <Panel title="Integrations & scanning">
      <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">
        Configure external integrations, AI triage, and scanning defaults.
      </p>

      <div className="space-y-4">
        {/* GitHub Issue Sync */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">GitHub issue sync</div>
          <div className="space-y-4 mt-2">
            <div>
              <label className={labelClass}>Repository</label>
              <input type="text" placeholder="owner/name" value={githubRepo} onChange={(e) => setGithubRepo(e.target.value)} className={inputClass} />
              <p className={hintClass}>Empty disables sync.</p>
            </div>

            <div>
              <label className={labelClass}>Token env var name</label>
              <input type="text" placeholder="GITHUB_TOKEN" value={githubTokenEnv} onChange={(e) => setGithubTokenEnv(e.target.value)} className={inputClass} />
              <div className="mt-1">
                {view?.githubTokenSet ? (
                  <span className="text-xs text-green-600 dark:text-green-400">✓ Token set on the server</span>
                ) : (
                  <span className="text-xs text-amber-600 dark:text-amber-400">Token not set — export the named variable</span>
                )}
              </div>
              <p className={hintClass}>The token is read from this environment variable, never stored.</p>
            </div>
          </div>
        </div>

        {/* AI Triage */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">AI triage</div>
          <div className="space-y-4 mt-2">
            <div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={triage.enabled} onChange={(e) => setTriage({ ...triage, enabled: e.target.checked })} />
                Enable AI triage
              </label>
            </div>

            <div>
              <label className={labelClass}>Provider</label>
              <select value={triage.provider} onChange={(e) => setTriage({ ...triage, provider: e.target.value })} className={inputClass}>
                <option value="ollama">ollama</option>
                <option value="anthropic">anthropic</option>
              </select>
              <p className={hintClass}>Ollama is local; Anthropic needs ANTHROPIC_API_KEY in the environment.</p>
            </div>

            {triage.provider === "anthropic" && (
              <div>
                <div className="mt-1">
                  {view?.anthropicKeySet ? (
                    <span className="text-xs text-green-600 dark:text-green-400">✓ ANTHROPIC_API_KEY set</span>
                  ) : (
                    <span className="text-xs text-amber-600 dark:text-amber-400">ANTHROPIC_API_KEY not set</span>
                  )}
                </div>
              </div>
            )}

            <div>
              <label className={labelClass}>Model</label>
              <input type="text" placeholder="qwen3.6:35b-a3b" value={triage.model} onChange={(e) => setTriage({ ...triage, model: e.target.value })} className={inputClass} />
            </div>

            <div>
              <label className={labelClass}>Endpoint</label>
              <input type="text" placeholder="http://localhost:11434" value={triage.endpoint} onChange={(e) => setTriage({ ...triage, endpoint: e.target.value })} className={inputClass} />
            </div>

            <div>
              <label className={labelClass}>Max findings</label>
              <input type="number" min={0} value={triage.maxFindings} onChange={(e) => setTriage({ ...triage, maxFindings: Number(e.target.value) || 0 })} className={inputClass} />
            </div>

            <div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={triage.excludeFp} onChange={(e) => setTriage({ ...triage, excludeFp: e.target.checked })} />
                Drop LLM-marked false positives from the report and gate
              </label>
            </div>
          </div>
        </div>

        {/* Scanning */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Scanning</div>
          <div className="space-y-4 mt-2">
            <div>
              <label className={labelClass}>Scan profile</label>
              <select value={scanProfile} onChange={(e) => setScanProfile(e.target.value)} className={inputClass}>
                <option value="">default (standard)</option>
                <option value="fast">fast</option>
                <option value="standard">standard</option>
                <option value="max">max</option>
              </select>
            </div>

            <div>
              <label className={labelClass}>Fail severity</label>
              <select value={failSeverity} onChange={(e) => setFailSeverity(e.target.value)} className={inputClass}>
                <option value="">default (high)</option>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
                <option value="none">none</option>
              </select>
            </div>

            <div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={remediationEnabled} onChange={(e) => setRemediationEnabled(e.target.checked)} />
                Allow admins to apply curated cloud remediations
              </label>
            </div>
          </div>
        </div>

        {saved && <div className="text-sm text-green-600 dark:text-green-400">Saved.</div>}
        {error && <div className="text-sm text-red-600 dark:text-red-400">{error}</div>}

        <div className="flex gap-3 pt-2">
          <button onClick={handleSave} disabled={busy} className="rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50">
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Panel>
  );
}
