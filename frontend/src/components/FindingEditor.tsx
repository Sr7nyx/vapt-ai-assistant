"use client";
import { ReactNode, useState } from "react";
import Modal from "./Modal";
import { Spinner } from "./Loading";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
const STATUSES = ["Draft", "Open", "Confirmed", "Retest Passed", "Retest Failed", "Accepted Risk", "Closed"];

type F = Record<string, unknown>;

export default function FindingEditor({
  finding,
  onSave,
  onClose,
}: {
  finding: F;
  onSave: (f: F) => Promise<void> | void;
  onClose: () => void;
}) {
  const [f, setF] = useState<F>({ ...finding });
  const [saving, setSaving] = useState(false);

  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));
  const val = (k: string) => (f[k] as string) ?? "";

  const save = async () => {
    setSaving(true);
    try {
      await onSave(f);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title="Edit finding"
      onClose={onClose}
      footer={
        <>
          <button className="btn-sm" onClick={onClose}>Cancel</button>
          <button className="btn" onClick={save} disabled={saving}>
            {saving ? (
              <span className="flex items-center gap-2">
                <Spinner /> Saving
              </span>
            ) : (
              "Save"
            )}
          </button>
        </>
      }
    >
      <div className="grid gap-3">
        <Field label="Title">
          <input className="input" value={val("title")} onChange={(e) => set("title", e.target.value)} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Severity">
            <select className="input" value={val("severity")} onChange={(e) => set("severity", e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Status">
            <select className="input" value={val("status")} onChange={(e) => set("status", e.target.value)}>
              {STATUSES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="CWE">
            <input className="input" value={val("cwe")} onChange={(e) => set("cwe", e.target.value)} />
          </Field>
          <Field label="CVSS">
            <input className="input" value={val("cvss")} onChange={(e) => set("cvss", e.target.value)} />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Affected host">
            <input className="input" value={val("affected_host")} onChange={(e) => set("affected_host", e.target.value)} />
          </Field>
          <Field label="Affected URL">
            <input className="input" value={val("affected_url")} onChange={(e) => set("affected_url", e.target.value)} />
          </Field>
        </div>
        <Field label="Description">
          <textarea className="input min-h-24" value={val("description")} onChange={(e) => set("description", e.target.value)} />
        </Field>
        <Field label="Evidence">
          <textarea className="input min-h-24 font-mono text-xs" value={val("evidence")} onChange={(e) => set("evidence", e.target.value)} />
        </Field>
        <Field label="Impact">
          <textarea className="input min-h-20" value={val("impact")} onChange={(e) => set("impact", e.target.value)} />
        </Field>
        <Field label="Remediation">
          <textarea className="input min-h-20" value={val("remediation")} onChange={(e) => set("remediation", e.target.value)} />
        </Field>
        <Field label="References">
          <input className="input" value={val("references_data")} onChange={(e) => set("references_data", e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-muted text-xs">{label}</span>
      {children}
    </label>
  );
}
