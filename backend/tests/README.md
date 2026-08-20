# Tests

Fast, offline unit tests for the parts of the pipeline where a silent failure
would be most damaging: the SSRF guard, the scanner parsers, risk and framework
mapping, verification-signal parsing, reviewer evidence slicing, the deterministic
verdict engine, and per-request model isolation.

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

No network, no database, and no LLM calls: DNS is stubbed, and every fixture is
inline in the test file. The suite runs in about a second. **398 tests.**

## What each file covers

| File | Covers | Why it matters |
| --- | --- | --- |
| `test_learning.py` | Calibration excludes the engine's own changes, thin buckets are reported as thin, contested classes form no prior, verifier gaps rank by reach | A confidence measured against the engine's agreement with itself always looks good, and a rate from three findings is worse than none. |
| `test_precedent.py` | Only adjudicated findings are retrieved, weak matches return nothing, the prompt block states decisions without instructing | Retrieving an unreviewed finding shows the model its own earlier guess, which is how it repeats a mistake. A precedent is context, not an order. |
| `test_attack_map.py` | That every weakness class maps to at least one technique, every technique names a tactic, and an unknown class returns NOTHING | A guessed ATT&CK id reads as authoritative and survives into a client's threat model, so refusing to map is the safe answer. |
| `test_retest.py` | Round coverage, outcome tally, and that remediation is measured against what was retested | Measuring against every finding would report an incomplete round as a poor remediation rate, which is the wrong conclusion from the same data. |
| `test_finding_identity.py` | What identity must IGNORE across scans: severity, status, session ids, object ids | Treating a re-rated finding as new erases its history at the moment it got worse, and treating a rotated session id as a different URL makes every rescan look like a fresh set. |
| `test_report_html.py` | That the report is self-contained and that user text is escaped | A report fetching a remote stylesheet is one a client's security team is right to object to, and a report about XSS must not contain XSS. |
| `test_llm_config.py` | Provider allowlist, https-only, credential rejection, private/loopback/metadata address blocking, lane-config sanitizing | Users supply their own provider URL, which makes the server issue outbound requests to a user-controlled host. Unconstrained, that is an SSRF primitive. |
| `test_scan_import.py` | Burp, ZAP, Nessus, Nmap, and CSV parsing; severity normalization; CWE extraction; dedup; noise summary; malformed input | Parsers take untrusted scanner output. A wrong severity or a fabricated CWE propagates all the way into a client report. |
| `test_risk_map.py` | CVSS computation, risk priority, KEV escalation, OWASP/PCI/CWE/ATT&CK mapping | CVSS is computed in code, not taken from the model. Findings with no reliable signal must stay explicitly unmapped rather than be guessed. |
| `test_qa_utils.py` | Evidence-grounding, severity-mismatch, prompt-injection, reviewer-verdict, and review-summary parsing | These signals are what stop an unverified finding from reaching a report looking like a fact. |
| `test_review_slice.py` | Reviewer evidence slicing and the excerpt disclosure | The reviewer sees only the input slice bearing on a finding; the slice must keep that finding's own evidence, and the reviewer must be told when it is an excerpt so trimmed context is not read as missing evidence. |
| `test_evidence_model.py` | Parsing raw text into HTTP exchanges, and binding a finding to the one it is about | Searching a whole submission is only sound when it holds one exchange. With several it produced false confirmations and false refutations from the component the verdict engine trusts above the reviewer. |
| `test_verifiers_extended.py` | The six classes the structured evidence model unlocked: open redirect, JWT algorithm, cacheable authenticated response, error disclosure, session fixation, rate limiting | Each needs the request or a pair of exchanges, so none was practical before evidence was parsed. Every one is tested against a true positive AND a case it must refute, because a verifier that can only agree is decoration. |
| `test_verdict_engine.py` | Deterministic status + confidence, and the asymmetric guardrails | Confidence must be earned from signals agreeing, never manufactured. A well-evidenced finding must never be auto-dismissed, and an ungrounded one never auto-confirmed. |
| `test_audit.py` | Field diffing, value clipping, and that a failing audit write cannot break the operation it records | Findings are mutable and the engine writes to them automatically; a trail that misses changes, or that takes the edit down with it when it fails, is worse than none. |
| `test_audit_actor.py` | Actor formatting, annotation stripping, and capture of the engine's rationale | Display-only annotations must never reach the database, and the engine's reasoning has to survive the commit or there is no answer to "why is this Confirmed?". |
| `test_input_guard.py` | A labelled corpus of things that must pass and must be refused, including the same rude string accepted inside a payload and refused on its own | The filter keys on structure, not tone. A version that rejected hostile strings would refuse real proof-of-concept evidence, and a version that accepted anything would spend two model calls proving that "hello" is not a vulnerability. |
| `test_schema_init.py` | Startup: that RLS is enabled only when the connecting role can bypass it, that a schema error still fails loudly, and that rows are read by column name | init() runs on every boot and is the one place that can take the service down before it serves a request. Enabling RLS against a role that cannot bypass it would leave the app up, healthy, and reading zero rows from every table. |
| `test_usage_window.py` | That the usage window is applied in SQL as a bound, integer-coerced parameter, and that zero means all time | The window reaches a query builder, so it is worth pinning that it arrives parameterized rather than interpolated. |
| `test_lane_config.py` | Lane resolution precedence, thread isolation, cross-provider key isolation | Jobs run in worker threads carrying different users' API keys; a module-global override, or a key reused across providers, would send one credential where another belongs. |

`test_review_slice.py` and `test_lane_config.py` import the LLM client, which
needs `pydantic` and the OpenAI SDK; `test_audit.py` and `test_usage_window.py`
import the Postgres driver. All are in `requirements.txt` and all skip cleanly if
absent.

## Regressions pinned here

Bugs found while writing these tests, now pinned so they cannot return quietly:

- **ZAP severity collapse.** ZAP writes `riskdesc` as `"High (Medium)"` (risk and
  confidence together). Normalizing the whole string fell through to
  `Informational`, quietly demoting every High alert into the noise bucket the
  import filter hides by default.
- **Burp CWE loss.** Burp reports the CWE in `vulnerabilityClassifications`,
  which the parser did not read, so Burp findings arrived with no CWE and were
  left unmapped to OWASP, PCI, and ATT&CK.
- **Cross-provider key leak.** Setting the reviewer lane to a second provider
  without its own key fell back to the extraction key, sending (for example) a
  Groq key to Cerebras -- a 401 surfaced mid-job instead of a clear missing-config
  message. The key now stays within its provider.
- **Wrong lane's key in the connection test.** `/llm/test` resolved the key as
  the extraction key regardless of the lane under test, so checking the reviewer
  reported a false 401. It now resolves the tested lane's own key.

## The evaluation harness

The verdict engine also has a labelled evaluation in `eval/` (repo root), run
separately:

```bash
cd eval
pytest                 # smoke test + the no-dangerous-dismissal gate
python run_eval.py      # precision / recall / FP-reduction / grounding accuracy
```

It scores the deterministic decision layer against a hand-labelled set with 95%
Wilson intervals, and exits non-zero if the engine ever dismisses a real finding.
See `eval/README.md` for what it does and does not measure.

## Conventions

Test names state the behaviour being protected, not the function being called,
and non-obvious assertions carry a comment explaining the consequence of the
behaviour breaking. A test that cannot say why it exists is a test nobody will
maintain.
