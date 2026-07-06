import { Severity } from "./api";

// Severity → hex, matching tailwind.config.js `sev` ramp, for recharts (which
// needs literal colors, not classes). Severity is the one saturated channel in
// the app, so these are the only strong hues on a chart.
export const SEV_COLOR: Record<Severity, string> = {
  critical: "#c92a30",
  high: "#d95d10",
  medium: "#c98a10",
  low: "#2f74c0",
  info: "#6b7386",
};

// Tailwind classes for severity chips.
export const SEV_CHIP: Record<Severity, string> = {
  critical: "bg-red-700 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-amber-600 text-white",
  low: "bg-blue-600 text-white",
  info: "bg-gray-500 text-white",
};

// OWASP category palette (10 distinct hues, colorblind-considerate ordering).
export const OWASP_COLORS = [
  "#2563eb", "#7c3aed", "#db2777", "#dc2626", "#ea580c",
  "#ca8a04", "#16a34a", "#0891b2", "#4f46e5", "#9333ea",
];

// Finding-category palette. Keys are the model's category constants
// (SAST/SECRET/SCA/IAC/DAST); unknown categories get neutral fallbacks in the
// components, never dropped.
export const CATEGORY_LABEL: Record<string, string> = {
  SAST: "Code (SAST)",
  SECRET: "Secrets",
  SCA: "Dependencies (SCA)",
  IAC: "Infrastructure (IaC)",
  DAST: "Dynamic (DAST)",
  CLOUD: "Cloud posture",
};

// Category chips are neutral so severity stays the one saturated channel in
// the finding list. The per-category hue survives as a dot in charts and the
// breakdown (CATEGORY_COLOR), where color encodes proportion, not urgency.
const NEUTRAL_CHIP = "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300";
export const CATEGORY_CHIP: Record<string, string> = {
  SAST: NEUTRAL_CHIP,
  SECRET: NEUTRAL_CHIP,
  SCA: NEUTRAL_CHIP,
  IAC: NEUTRAL_CHIP,
  DAST: NEUTRAL_CHIP,
  CLOUD: NEUTRAL_CHIP,
};

export const CATEGORY_COLOR: Record<string, string> = {
  SAST: "#4f46e5",
  SECRET: "#e11d48",
  SCA: "#0891b2",
  IAC: "#0d9488",
  DAST: "#9333ea",
  CLOUD: "#0284c7",
};

export const VERDICT_LABEL: Record<string, string> = {
  "true-positive": "True positive",
  "false-positive": "False positive",
  uncertain: "Uncertain",
};

// Finding workflow disposition (human judgment). "open" is the default and
// has no chip. Distinct palette from the LLM verdict chips so the two are not
// confused.
export const DISPOSITION_LABEL: Record<string, string> = {
  "in-progress": "In progress",
  "accepted-risk": "Accepted risk",
  "false-positive": "False positive",
  fixed: "Fixed",
};
export const DISPOSITION_CHIP: Record<string, string> = {
  "in-progress": "bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300",
  "accepted-risk": "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300",
  "false-positive": "bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300",
  fixed: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300",
};

// LLM triage verdicts are advisory, so they read calm rather than loud: a
// neutral chip with a self-explanatory label, never a saturated fill that
// competes with the deterministic severity.
export const VERDICT_CHIP: Record<string, string> = {
  "true-positive": NEUTRAL_CHIP,
  "false-positive": NEUTRAL_CHIP,
  uncertain: NEUTRAL_CHIP,
};

export function fmtTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function riskColor(score: number): string {
  if (score >= 9) return "#c92a30";
  if (score >= 7) return "#d95d10";
  if (score >= 4) return "#c98a10";
  return "#2f74c0";
}
