"use client";
import { useState } from "react";
import Modal from "./Modal";
import { Spinner } from "./Loading";

const OUTCOMES = ["Fixed", "Open", "Partially Fixed", "Regressed", "Accepted Risk"];

export default function RetestModal({
  title,
  onSubmit,
  onClose,
}: {
  title: string;
  onSubmit: (payload: {
    retest_status: string;
    retester: string;
    retest_date: string;
    retest_evidence: string;
    note: string;
  }) => Promise<void>;
  onClose: () => void;
}) {
  const [retest_status, setStatus] = useState(OUTCOMES[0]);
  const [retester, setRetester] = useState("");
  const [retest_date, setDate] = useState("");
  const [retest_evidence, setEvidence] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    setSaving(true);
    try {
      await onSubmit({ retest_status, retester, retest_date, retest_evidence, note });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title="Record retest"
      onClose={onClose}
      footer={
        <>
          <button className="btn-sm" onClick={onClose}>Cancel</button>
          <button className="btn" onClick={submit} disabled={saving}>
            {saving ? (
              <span className="flex items-center gap-2">
                <Spinner /> Saving
              </span>
            ) : (
              "Save retest"
            )}
          </button>
        </>
      }
    >
      <div className="grid gap-3">
        <div className="text-sm text-muted">{title}</div>
        <label className="grid gap-1">
          <span className="text-muted text-xs">Outcome</span>
          <select className="input" value={retest_status} onChange={(e) => setStatus(e.target.value)}>
            {OUTCOMES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="grid gap-1">
            <span className="text-muted text-xs">Retester</span>
            <input className="input" value={retester} onChange={(e) => setRetester(e.target.value)} />
          </label>
          <label className="grid gap-1">
            <span className="text-muted text-xs">Date</span>
            <input className="input" type="date" value={retest_date} onChange={(e) => setDate(e.target.value)} />
          </label>
        </div>
        <label className="grid gap-1">
          <span className="text-muted text-xs">Evidence</span>
          <textarea className="input min-h-20 font-mono text-xs" value={retest_evidence} onChange={(e) => setEvidence(e.target.value)} />
        </label>
        <label className="grid gap-1">
          <span className="text-muted text-xs">Note</span>
          <textarea className="input min-h-16" value={note} onChange={(e) => setNote(e.target.value)} />
        </label>
      </div>
    </Modal>
  );
}
