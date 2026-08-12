"""Self-contained HTML report.

Why this format earns its place next to DOCX and PDF: it opens in anything, it can
be sent as one file, and it is the only export where evidence stays readable --
a request/response pane survives here and does not survive a Word table.

Everything is inline. No stylesheet, no font, no script, no image request. A report
that phones out is one a client's security team is right to be unhappy about, and
it also means the file still renders in five years when whatever CDN it referenced
is gone.

The palette is the application's, so a report looks like the tool that produced it.
"""
import html
import re
from datetime import datetime, timezone

SEVERITY_COLOUR = {
    "Critical": "#e06c75",
    "High": "#e5a04c",
    "Medium": "#5fb3ac",
    "Low": "#5c6b7a",
    "Informational": "#3d4854",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _e(value):
    return html.escape("" if value is None else str(value))


def _severity_chip(sev):
    colour = SEVERITY_COLOUR.get(sev, "#5c6b7a")
    return f'<span class="chip" style="border-color:{colour};color:{colour}">{_e(sev)}</span>'


def _counts(findings):
    counts = {}
    for f in findings:
        key = str(f.get("severity") or "Unknown")
        counts[key] = counts.get(key, 0) + 1
    return [(s, counts[s]) for s in SEVERITY_ORDER if s in counts]


def _bar(findings):
    total = len(findings) or 1
    segments = "".join(
        f'<span style="width:{c / total * 100:.2f}%;background:{SEVERITY_COLOUR.get(s, "#5c6b7a")}"></span>'
        for s, c in _counts(findings)
    )
    legend = " ".join(
        f'<span class="lg"><i style="background:{SEVERITY_COLOUR.get(s, "#5c6b7a")}"></i>'
        f'{_e(s)} <b>{c}</b></span>'
        for s, c in _counts(findings)
    )
    return f'<div class="bar">{segments}</div><div class="legend">{legend}</div>'


def _block(label, value, mono=False):
    """A labelled section, omitted entirely when empty. Empty headings in a client
    deliverable read as unfinished work rather than as absent data."""
    text = str(value or "").strip()
    if not text:
        return ""
    cls = "pre" if mono else "prose"
    return f'<div class="blk"><div class="lbl">{_e(label)}</div><div class="{cls}">{_e(text)}</div></div>'


def _verification(finding):
    """The deterministic check, when one ran. This is the part of the report that
    distinguishes it, so it is stated plainly rather than buried in remarks."""
    v = finding.get("_verification") or {}
    if not isinstance(v, dict) or not v.get("status") or v["status"] == "INSUFFICIENT":
        return ""
    refuted = v["status"] == "REFUTED"
    colour = "#e06c75" if refuted else "#7ee787"
    label = "CONTRADICTED BY EVIDENCE" if refuted else "VERIFIED BY DETERMINISTIC CHECK"
    where = f" on {_e(v.get('exchange_id'))}" if v.get("exchange_id") else ""
    return (
        f'<div class="ver" style="border-color:{colour}">'
        f'<div class="lbl" style="color:{colour}">{label}{where}</div>'
        f'<div class="prose">{_e(v.get("summary"))}</div>'
        f'<div class="note">Checked by parsing the evidence, not by asking a model.</div>'
        f"</div>"
    )


def _delta(finding):
    d = finding.get("_delta") or {}
    state = d.get("state")
    if state == "regressed":
        return ('<span class="chip" style="border-color:#e06c75;color:#e06c75">REGRESSED</span>')
    if state == "new":
        return '<span class="chip">NEW</span>'
    return ""


CSS = """
:root{--bg:#0a0e0c;--sur:#141d17;--bd:#25332a;--tx:#cfe0d2;--mu:#7f9386;--ac:#7ee787}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
  font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
.wrap{max-width:1100px;margin:0 auto;padding:40px 28px 80px}
h1{font-size:26px;font-weight:500;margin:0 0 4px;letter-spacing:.02em}
h2{font-size:11px;font-weight:500;letter-spacing:.22em;color:var(--mu);margin:44px 0 14px;
  padding-bottom:6px;border-bottom:1px solid var(--bd)}
h2::before{content:"> ";color:var(--ac)}
h3{font-size:15px;font-weight:500;margin:0}
a{color:var(--ac)}
.sub{color:var(--mu);font-size:12px;margin-bottom:28px}
.meta{display:flex;flex-wrap:wrap;gap:26px;margin:18px 0 6px}
.meta div span{display:block;font-size:10px;letter-spacing:.2em;color:var(--mu)}
.meta div b{font-weight:500;font-size:15px}
.bar{display:flex;height:8px;border-radius:99px;overflow:hidden;background:#ffffff0d;margin:6px 0 10px}
.bar span{display:block}
.legend{display:flex;flex-wrap:wrap;gap:16px;font-size:12px;color:var(--mu)}
.legend i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}
.legend b{color:var(--tx);font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-weight:500;font-size:10px;letter-spacing:.18em;color:var(--mu);
  padding:0 10px 8px 0;border-bottom:1px solid var(--bd)}
td{padding:9px 10px 9px 0;border-bottom:1px solid #25332a66;vertical-align:top}
.chip{display:inline-block;border:1px solid var(--bd);border-radius:4px;
  padding:1px 7px;font-size:10px;letter-spacing:.1em;white-space:nowrap}
.f{border:1px solid var(--bd);border-radius:8px;background:var(--sur);
  padding:20px 22px;margin:0 0 16px}
.fh{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;margin-bottom:6px}
.fid{color:var(--mu);font-size:12px}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 14px}
.blk{margin:0 0 12px}
.lbl{font-size:10px;letter-spacing:.2em;color:var(--mu);margin-bottom:4px}
.prose{white-space:pre-wrap;word-wrap:break-word}
.pre{white-space:pre-wrap;word-break:break-all;font-size:12px;background:var(--bg);
  border:1px solid var(--bd);border-radius:6px;padding:10px 12px;max-height:400px;overflow:auto}
.ver{border-left:2px solid;padding:8px 0 8px 12px;margin:0 0 14px}
.note{font-size:11px;color:var(--mu);margin-top:4px}
.foot{margin-top:60px;padding-top:16px;border-top:1px solid var(--bd);
  color:var(--mu);font-size:11px}
@media print{
  body{background:#fff;color:#111}
  .f{background:#fff;border-color:#ccc;break-inside:avoid}
  .pre{background:#f6f6f6;border-color:#ddd;max-height:none}
  h2{color:#444;border-color:#ccc}
  .sub,.lbl,.note,.fid,.legend{color:#555}
  a{color:#111}
}
"""


def export_to_html(project, findings, exec_summary, methodology, filepath):
    """Write a single self-contained HTML file."""
    project = project or {}
    findings = list(findings or [])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (order.get(str(f.get("severity")), 99), str(f.get("title") or "")))

    rows = "".join(
        f"<tr><td>{i + 1}</td><td>{_severity_chip(f.get('severity'))}</td>"
        f"<td>{_e(f.get('title'))} {_delta(f)}</td>"
        f"<td>{_e(f.get('status') or '')}</td>"
        f"<td class='fid'>{_e(f.get('affected_url') or f.get('affected_host') or '')}</td></tr>"
        for i, f in enumerate(findings)
    )

    details = ""
    for i, f in enumerate(findings):
        tags = "".join(
            f'<span class="chip">{_e(t)}</span>'
            for t in [f.get("cwe"), f.get("category"), f.get("environment"),
                      f.get("cvss"), f.get("status")]
            if t
        )
        details += f"""
        <div class="f">
          <div class="fh">
            <span class="fid">{i + 1:02d}</span>
            {_severity_chip(f.get('severity'))}
            <h3>{_e(f.get('title'))}</h3>
            {_delta(f)}
          </div>
          <div class="fid">{_e(f.get('affected_url') or f.get('affected_host') or '')}</div>
          <div class="tags">{tags}</div>
          {_verification(f)}
          {_block('Description', f.get('description'))}
          {_block('Evidence', f.get('evidence'), mono=True)}
          {_block('Impact', f.get('impact'))}
          {_block('Reproduction', f.get('steps'), mono=True)}
          {_block('Remediation', f.get('remediation'))}
          {_block('References', f.get('references_data'))}
        </div>"""

    counts = _counts(findings)
    crit_high = sum(c for s, c in counts if s in ("Critical", "High"))

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(project.get('name') or 'Security assessment')} &mdash; findings</title>
<style>{CSS}</style></head>
<body><div class="wrap">

<h1>{_e(project.get('name') or 'Security assessment')}</h1>
<div class="sub">
  {_e(project.get('client') or 'Client not recorded')} &middot; generated {generated}
  {(' &middot; tester ' + _e(project.get('tester'))) if project.get('tester') else ''}
</div>

<div class="meta">
  <div><span>FINDINGS</span><b>{len(findings)}</b></div>
  <div><span>CRITICAL / HIGH</span><b>{crit_high}</b></div>
  <div><span>SCOPE</span><b>{_e(project.get('scope') or 'not recorded')}</b></div>
</div>

{_bar(findings) if findings else ''}

{('<h2>Executive summary</h2><div class="prose">' + _e(exec_summary) + '</div>') if exec_summary else ''}
{('<h2>Methodology</h2><div class="prose">' + _e(methodology) + '</div>') if methodology else ''}

<h2>Findings</h2>
<table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Status</th><th>Asset</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5">No findings in scope.</td></tr>'}</tbody></table>

<h2>Detail</h2>
{details or '<div class="prose">No findings in scope.</div>'}

<div class="foot">
  Generated by vapt.console. Severity is computed from the CVSS vector rather than
  taken from a model, and findings marked as verified were checked by parsing their
  evidence in code. Findings marked contradicted are retained deliberately: they were
  included by explicit decision after the export pre-flight flagged them.
</div>

</div></body></html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return filepath
