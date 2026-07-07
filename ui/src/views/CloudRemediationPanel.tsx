import { useEffect, useState } from "react";
import { opsApi, CloudRemediation, CloudRemediateResult, ApiError } from "../api";
import { useConfirm, useToast } from "../toast";

// The curated cloud-remediation panel on a cloud finding. It lists the vetted
// fixes that apply (informational, for anyone), and, when remediation is
// enabled in config and the viewer is an admin, offers a dry-run preview and
// an approved apply. The command text shown is exactly what runs; nothing here
// is LLM-authored. A successful apply never marks the finding fixed: the panel
// says to re-scan. Credentials follow the provider: AWS takes a named write
// profile; Azure and GCP run with the operator's local az/gcloud login, scoped
// by the account already validated into the command.

function CommandBlock({ argv }: { argv: string[][] }) {
  return (
    <pre className="scroll-thin mt-1 overflow-x-auto rounded bg-gray-900 px-2 py-1.5 text-[11px] leading-relaxed text-gray-100 dark:bg-black/40">
      {argv.map((cmd, i) => (
        <div key={i}>{cmd.join(" ")}</div>
      ))}
    </pre>
  );
}

export function CloudRemediationPanel({ finding, runId, targetId, canApply }: {
  finding: string;
  runId: string;
  targetId?: string;
  canApply: boolean; // admin
}) {
  const [rems, setRems] = useState<CloudRemediation[] | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [profiles, setProfiles] = useState<string[]>([]);
  const [profile, setProfile] = useState("");
  const [busy, setBusy] = useState<string | null>(null); // "<id>:<mode>" while running
  const [result, setResult] = useState<Record<string, CloudRemediateResult>>({});
  const confirm = useConfirm();
  const toast = useToast();

  useEffect(() => {
    let live = true;
    opsApi
      .cloudRemediations({ targetId, runId, findingId: finding })
      .then((r) => {
        if (!live) return;
        setRems(r.remediations);
        setEnabled(r.enabled);
      })
      .catch(() => live && setRems([]));
    return () => { live = false; };
  }, [finding, runId, targetId]);

  // Derive provider and CLI tool from the first remediation.
  const provider = rems?.[0]?.provider ?? "aws";
  const cli = provider === "azure" ? "az" : provider === "gcp" ? "gcloud" : "aws";

  // Load the discovered write profiles once, only when apply is possible and provider is AWS.
  useEffect(() => {
    if (!canApply || !enabled || !rems || provider !== "aws") return;
    opsApi.cloudProfiles().then((r) => setProfiles(r.providers.find((p) => p.provider === "aws")?.profiles ?? [])).catch(() => {});
  }, [canApply, enabled, rems, provider]);

  const run = async (rem: CloudRemediation, mode: "dryrun" | "apply") => {
    if (provider === "aws" && !profile) {
      toast({ kind: "error", message: "Pick a write profile first." });
      return;
    }
    if (mode === "apply") {
      const ok = await confirm({
        title: `Apply "${rem.title}"?`,
        message: provider === "aws"
          ? `This runs the shown command against your cloud account using the "${profile}" profile. ${rem.reversible ? "It's reversible." : "Review carefully."} The finding stays until a re-scan confirms the fix.`
          : `This runs the shown command against your cloud account using your local ${cli} login. ${rem.reversible ? "It's reversible." : "Review carefully."} The finding stays until a re-scan confirms the fix.`,
        confirmLabel: "Apply",
        danger: !rem.reversible,
      });
      if (!ok) return;
    }
    setBusy(`${rem.id}:${mode}`);
    try {
      const res = await opsApi.cloudRemediate({ targetId, runId, findingId: finding, remediationId: rem.id, mode, profile: provider === "aws" ? profile : undefined });
      setResult((prev) => ({ ...prev, [rem.id]: res }));
      if (mode === "apply") toast({ kind: "success", message: res.reScanHint });
    } catch (e) {
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  };

  if (rems === null) return <p className="text-xs text-gray-400">Checking curated fixes…</p>;
  if (rems.length === 0) return null;

  return (
    <div className="space-y-3">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Curated remediation</div>

      {canApply && enabled && provider === "aws" && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-gray-500">Write profile</span>
          <select value={profile} onChange={(e) => setProfile(e.target.value)} className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800">
            <option value="">choose…</option>
            {profiles.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <span className="text-gray-400">separate from the read-only audit profile</span>
        </div>
      )}

      {canApply && enabled && provider !== "aws" && (
        <p className="text-[11px] text-gray-400">Runs with your local {cli} login. The account scope is already part of the command shown. No profile is sent.</p>
      )}

      {rems.map((rem) => (
        <div key={rem.id} className="rounded-md border border-gray-200 p-2.5 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">{rem.title}</span>
            {rem.reversible && <span className="rounded border border-emerald-400/50 px-1 text-[10px] text-emerald-600 dark:text-emerald-400">reversible</span>}
          </div>
          <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-400">{rem.description}</p>
          <div className="mt-2 text-[10px] font-semibold uppercase tracking-wide text-gray-400">Command</div>
          <CommandBlock argv={rem.apply} />
          {rem.permissions.length > 0 && (
            <p className="mt-1 text-[11px] text-gray-400">Needs: <span className="font-mono">{rem.permissions.join(", ")}</span></p>
          )}

          {canApply && enabled ? (
            <div className="mt-2 flex items-center gap-2">
              <button onClick={() => run(rem, "dryrun")} disabled={busy !== null} className="rounded-md border border-gray-300 px-2 py-0.5 text-[11px] font-medium hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800">
                {busy === `${rem.id}:dryrun` ? "Previewing…" : "Preview (dry-run)"}
              </button>
              <button onClick={() => run(rem, "apply")} disabled={busy !== null} className="rounded-md bg-accent-600 px-2 py-0.5 text-[11px] font-medium text-white hover:bg-accent-700 disabled:opacity-50">
                {busy === `${rem.id}:apply` ? "Applying…" : "Apply"}
              </button>
            </div>
          ) : (
            <p className="mt-2 text-[11px] text-gray-400">
              {canApply ? "Set remediation.enabled in appsec.yml to apply from the console." : "An admin can apply this fix."}
            </p>
          )}

          {result[rem.id] && (
            <div className="mt-2">
              <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                {result[rem.id].applied ? "Applied. Re-scan to confirm" : "Dry-run output"}
              </div>
              {result[rem.id].results.map((cr, i) => (
                <pre key={i} className="scroll-thin mt-1 overflow-x-auto rounded bg-gray-100 px-2 py-1 text-[11px] dark:bg-gray-800">{cr.error ? `error: ${cr.error}\n${cr.output}` : cr.output || "(no output)"}</pre>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
