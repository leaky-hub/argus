import { Finding } from "./api";

// Client-side finding export to CSV and JSON. The findings are already in the
// browser, so exporting a single finding or a bulk selection is a local Blob
// download — no round trip. The run-level report (HTML/SARIF/JSON) stays a
// server export; this is finding-grained.

function locationOf(f: Finding): string {
  const l = f.location;
  if (l.file) return l.startLine ? `${l.file}:${l.startLine}` : l.file;
  return l.resource ?? "";
}

// CSV columns, in order. Each value is a plain string; joins use "|" so a single
// cell never needs nested quoting for multi-value fields.
const COLUMNS: { header: string; get: (f: Finding) => string }[] = [
  { header: "id", get: (f) => f.id },
  { header: "severity", get: (f) => f.severity },
  { header: "risk", get: (f) => (f.riskScore != null ? f.riskScore.toFixed(1) : "") },
  { header: "category", get: (f) => f.category },
  { header: "tool", get: (f) => (f.tools && f.tools.length ? f.tools.join("|") : f.tool) },
  { header: "title", get: (f) => f.displayName ?? f.title },
  { header: "location", get: (f) => locationOf(f) },
  { header: "rule", get: (f) => f.ruleId ?? "" },
  { header: "cwe", get: (f) => (f.cwes ?? []).join("|") },
  { header: "cve", get: (f) => f.cve ?? "" },
  { header: "verdict", get: (f) => f.triage?.verdict ?? "" },
  { header: "controls", get: (f) => (f.complianceControls ?? []).join("|") },
];

// csvCell quotes a value when it contains a comma, quote, or newline (RFC 4180),
// doubling embedded quotes. A leading =/+/-/@ is prefixed to defuse spreadsheet
// formula injection from hostile finding text.
function csvCell(value: string): string {
  let v = value ?? "";
  if (/^[=+\-@]/.test(v)) v = "'" + v;
  if (/[",\n\r]/.test(v)) v = '"' + v.replace(/"/g, '""') + '"';
  return v;
}

export function findingsToCSV(findings: Finding[]): string {
  const rows = [COLUMNS.map((c) => c.header).join(",")];
  for (const f of findings) rows.push(COLUMNS.map((c) => csvCell(c.get(f))).join(","));
  return rows.join("\r\n");
}

export function findingsToJSON(findings: Finding[]): string {
  return JSON.stringify(findings, null, 2);
}

// download triggers a browser save of content as filename. Uses a Blob URL and
// the download attribute (a save, not a navigation), revoked after the click.
export function download(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// A short, filesystem-safe stamp for export filenames (no Date locale surprises).
function stamp(): string {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
}

export function exportFindingsCSV(findings: Finding[], base = "argus-findings"): void {
  download(`${base}-${stamp()}.csv`, "text/csv;charset=utf-8", findingsToCSV(findings));
}
export function exportFindingsJSON(findings: Finding[], base = "argus-findings"): void {
  download(`${base}-${stamp()}.json`, "application/json", findingsToJSON(findings));
}
