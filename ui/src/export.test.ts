import { describe, expect, it } from "vitest";
import { findingsToCSV, findingsToJSON } from "./export";
import { Finding } from "./api";

// The CSV export renders hostile finding text into a file the user will open
// in Excel/Sheets/Numbers. These tests pin the two safety properties: RFC 4180
// quoting (a crafted title cannot add rows or columns) and formula defusing
// (a title cannot execute as =/+/-/@ or tab/CR-prefixed formula).

function mk(over: Partial<Finding>): Finding {
  return {
    id: "fp-1",
    severity: "high",
    category: "sast",
    tool: "semgrep",
    tools: ["semgrep"],
    title: "plain",
    location: { file: "a.py", startLine: 3 },
    ...over,
  } as unknown as Finding;
}

function row(f: Finding): string {
  // Row 0 is the header; row 1 is the finding.
  return findingsToCSV([f]).split("\r\n")[1];
}

describe("findingsToCSV", () => {
  it("emits the fixed header and CRLF row separators", () => {
    const csv = findingsToCSV([mk({})]);
    expect(csv.startsWith("id,severity,risk,category,tool,title,location,rule,cwe,cve,verdict,controls")).toBe(true);
    expect(csv.split("\r\n")).toHaveLength(2);
  });

  it("quotes commas, doubles quotes, and contains newlines to one row", () => {
    const evil = 'a,b"c\nd\re';
    const csv = findingsToCSV([mk({ title: evil })]);
    // Still exactly one data row: the newline lives inside a quoted cell.
    expect(csv.split("\r\n").filter((l) => l.includes("fp-1"))).toHaveLength(1);
    expect(row(mk({ title: evil }))).toContain('"a,b""c\nd\re"');
  });

  it("defuses every formula lead-in, including tab and CR", () => {
    for (const lead of ["=", "+", "-", "@", "\t", "\r"]) {
      const cell = row(mk({ title: lead + "HYPERLINK(1)" })).split(",")[5];
      // The written cell must not begin (quoted or bare) with the raw lead-in.
      const inner = cell.startsWith('"') ? cell.slice(1) : cell;
      expect(inner.startsWith("'"), `lead ${JSON.stringify(lead)} not defused: ${JSON.stringify(cell)}`).toBe(true);
    }
  });

  it("defuses a formula that also needs quoting", () => {
    const cell = row(mk({ title: '=1+1,"x"' }));
    expect(cell).toContain("'=1+1");
    // And the embedded quotes are doubled inside a quoted cell.
    expect(cell).toContain('""x""');
  });

  it("does not mangle ordinary text", () => {
    expect(row(mk({ title: "SQL injection in login" }))).toContain("SQL injection in login");
  });

  it("joins multi-value fields with | so cells never nest quoting", () => {
    const r = row(mk({ tools: ["semgrep", "codeql"], cwes: ["CWE-89", "CWE-20"] } as Partial<Finding>));
    expect(r).toContain("semgrep|codeql");
    expect(r).toContain("CWE-89|CWE-20");
  });

  it("renders resource-only locations (cloud findings)", () => {
    const r = row(mk({ location: { resource: "arn:aws:s3:::bucket" } } as Partial<Finding>));
    expect(r).toContain("arn:aws:s3:::bucket");
  });
});

describe("findingsToJSON", () => {
  it("round-trips exactly what the API already gave the browser — no extras", () => {
    const f = mk({ title: "x" });
    expect(JSON.parse(findingsToJSON([f]))).toEqual([f]);
  });
});
