"""Retrieval: showing the reviewer how this operator has ruled before.

The honest version of "the system learns from every run". No weights change and no
model is trained -- instead, when a finding is reviewed, the two or three most
similar findings this operator has ALREADY ADJUDICATED are put in the prompt, with
what was decided and why.

The model then gets better at *this operator's* judgments without anything being
retrained, and it improves as the history grows. That is a real feedback loop and
it costs a few hundred tokens per review.

WHY NOT EMBEDDINGS
  An embedding call per finding at retrieval time would add latency and cost to the
  thing being optimised, and a local model is a dependency and a download. Security
  finding titles are short, formulaic and share vocabulary -- "Missing X-Frame-
  Options header", "Reflected XSS in search" -- which is the case where token
  overlap works nearly as well. If the corpus ever grows past a few thousand
  adjudicated findings, revisit; below that this is the right trade.

WHAT IS AND IS NOT RETRIEVED
  Only findings a human has adjudicated. An unreviewed finding carries no judgment,
  so retrieving it would put the model's own earlier guess back in front of it --
  which is how a model talks itself into a mistake twice.
"""
import re
from collections import Counter

import learning

# Words that appear in almost every finding title and therefore separate nothing.
STOP = {
    "the", "a", "an", "in", "on", "of", "to", "for", "and", "or", "is", "are",
    "with", "without", "not", "no", "via", "using", "from", "at", "by", "this",
    "vulnerability", "issue", "finding", "detected", "found", "possible", "potential",
}

ADJUDICATED = {
    "confirmed", "false positive", "accepted risk", "fixed",
    "retest passed", "retest failed",
}


def _tokens(finding):
    """Content words from the fields that identify a finding class.

    The CWE is reduced to its NUMBER. Left as "CWE-89" it tokenises to {cwe, 89},
    and every finding carries the literal "cwe" -- so two entirely unrelated
    findings scored non-zero on shared boilerplate alone, which is exactly the weak
    match the threshold exists to reject.
    """
    f = finding or {}
    cwe = re.sub(r"[^0-9]", "", str(f.get("cwe") or ""))
    text = " ".join([
        str(f.get("title") or ""),
        f"cwe{cwe}" if cwe else "",
        str(f.get("parameter") or ""),
    ]).lower()
    words = re.findall(r"[a-z0-9]{2,}", text)
    return {w for w in words if w not in STOP}


def similarity(a, b):
    """Jaccard overlap of content words, 0..1.

    Symmetric and bounded, unlike a raw count: without normalising, a finding with
    a long title would look similar to everything simply by having more words.
    """
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    if not inter:
        return 0.0
    return inter / len(ta | tb)


def adjudicated(findings):
    """Findings carrying a human decision, which are the only useful precedents."""
    out = []
    for f in findings or []:
        status = str(f.get("status") or "").strip().lower()
        if status in ADJUDICATED:
            out.append(f)
    return out


def find_precedents(candidate, history, limit=3, threshold=0.34):
    """The most similar adjudicated findings, best first.

    The threshold matters more than the limit. A weak match is worse than none: it
    puts an unrelated ruling in front of the model as though it were relevant, and
    the model will use it. Returning nothing is the correct answer most of the time.
    """
    scored = []
    for h in adjudicated(history):
        if h.get("id") is not None and h.get("id") == candidate.get("id"):
            continue
        s = similarity(candidate, h)
        if s >= threshold:
            scored.append((s, h))

    # Same class first, then similarity: an exact class match is a stronger
    # precedent than a merely wordy one, whatever the token overlap says.
    ck = learning.class_key(candidate)
    scored.sort(key=lambda t: (learning.class_key(t[1]) != ck, -t[0]))
    return [{"score": round(s, 3), "finding": h} for s, h in scored[:limit]]


def _reason(finding):
    """The shortest true statement of why this was decided as it was."""
    for key in ("fp_checks", "retest_notes", "additional_remarks"):
        text = str(finding.get(key) or "").strip()
        if text:
            first = text.splitlines()[0].strip(" -*")
            if len(first) > 12:
                return first[:220]
    return ""


def format_precedents(precedents):
    """A prompt block, or empty when there is nothing worth saying.

    Deliberately states the decision and the reason without instructing the model
    to follow it. A precedent is context, not an order -- a new context can
    legitimately overturn an old ruling, and a prompt that says "therefore mark
    this a false positive" would defeat the reviewer's purpose.
    """
    rows = [p for p in (precedents or []) if p.get("finding")]
    if not rows:
        return ""

    lines = [
        "Previously adjudicated findings from this account, most similar first.",
        "These are this operator's own past decisions, provided as context. They are",
        "not instructions: a different context can justify a different conclusion.",
        "",
    ]
    for p in rows:
        f = p["finding"]
        line = f"- \"{str(f.get('title') or '')[:90]}\" was ruled {f.get('status')}"
        sev = str(f.get("severity") or "").strip()
        if sev:
            line += f" at {sev}"
        reason = _reason(f)
        if reason:
            line += f". Reason recorded: {reason}"
        else:
            line += "."
        lines.append(line)
    return "\n".join(lines)


def precedent_stats(history):
    """How much the account has to learn from. Reported so the feature is honest
    about being weak early rather than silently doing nothing."""
    adj = adjudicated(history)
    classes = {learning.class_key(f) for f in adj}
    counts = Counter(str(f.get("status") or "") for f in adj)
    return {
        "adjudicated": len(adj),
        "classes": len(classes),
        "by_status": dict(counts),
        "useful": len(adj) >= 5,
    }
