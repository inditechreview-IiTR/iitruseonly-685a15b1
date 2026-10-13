import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { parseEvidence, verifyFinding } from "@/lib/dfint";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "IITRUSEONLY — DFINT Evidence Parser" },
      {
        name: "description",
        content:
          "Extract traceable indicators from untrusted evidence with exact source locations.",
      },
      { property: "og:title", content: "IITRUSEONLY — DFINT Evidence Parser" },
      { property: "og:description", content: "Traceable, observation-only indicator extraction." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

const SAMPLE =
  "Report 2026-10-11\nBeacon to https://cdn.bad-actor.net/p.js from 192.168.4.20\nContact: ops@bad-actor.net\nHash 44d88612fea8a8f36de82e1278abb02f";

function Index() {
  const [file, setFile] = useState("evidence.txt");
  const [text, setText] = useState(SAMPLE);
  const result = useMemo(() => parseEvidence(text, file), [text, file]);

  return (
    <main className="min-h-screen bg-background px-6 py-10 font-mono text-foreground">
      <div className="mx-auto max-w-5xl space-y-6">
        <header>
          <h1 className="text-2xl font-bold">DFINT Evidence Parser</h1>
          <p className="text-sm text-muted-foreground">
            Observations only. Every finding links to file, line, column and offset. Input is
            treated as untrusted data and never executed.
          </p>
        </header>
        <input
          value={file}
          onChange={(e) => setFile(e.target.value)}
          maxLength={255}
          className="w-full rounded border border-input bg-background px-3 py-2 text-sm"
          aria-label="Source file name"
        />
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          className="w-full rounded border border-input bg-background p-3 text-sm"
          aria-label="Evidence text"
        />
        <p className="text-xs text-muted-foreground">
          v{result.version} · {result.inputLength} chars · {result.lineCount} lines ·{" "}
          {result.findings.length} findings
          {result.errors.map((e) => ` · ${e}`)}
        </p>
        <div className="overflow-x-auto rounded border border-border">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted text-muted-foreground">
              <tr>
                <th className="p-2">Type</th>
                <th className="p-2">Value</th>
                <th className="p-2">Location</th>
                <th className="p-2">Offset</th>
                <th className="p-2">Verified</th>
              </tr>
            </thead>
            <tbody>
              {result.findings.map((f) => (
                <tr key={`${f.location.offset}-${f.type}`} className="border-t border-border">
                  <td className="p-2">{f.type}</td>
                  <td className="break-all p-2">{f.value}</td>
                  <td className="p-2">
                    {f.location.file}:{f.location.line}:{f.location.column}
                  </td>
                  <td className="p-2">
                    {f.location.offset}+{f.location.length}
                  </td>
                  <td className="p-2">{verifyFinding(text, f) ? "yes" : "NO"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
