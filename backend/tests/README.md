# Tests

Fast, offline unit tests for the parts of the pipeline where a silent failure
would be most damaging: the SSRF guard, the scanner parsers, risk and framework
mapping, verification-signal parsing, and per-request model isolation.

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

No network, no database, and no LLM calls: DNS is stubbed, and every fixture is
inline in the test file. The suite runs in about a second.

## What each file covers

| File | Covers | Why it matters |
| --- | --- | --- |
| `test_llm_config.py` | Provider allowlist, https-only, credential rejection, private/loopback/metadata address blocking, lane-config sanitizing | Users supply their own provider URL, which makes the server issue outbound requests to a user-controlled host. Unconstrained, that is an SSRF primitive. |
| `test_scan_import.py` | Burp, ZAP, Nessus, Nmap, and CSV parsing; severity normalization; CWE extraction; dedup; noise summary; malformed input | Parsers take untrusted scanner output. A wrong severity or a fabricated CWE propagates all the way into a client report. |
| `test_risk_map.py` | CVSS computation, risk priority, OWASP/PCI/CWE/ATT&CK mapping | CVSS is computed in code, not taken from the model. Findings with no reliable signal must stay explicitly unmapped rather than be guessed. |
| `test_qa_utils.py` | Evidence-grounding, severity-mismatch, prompt-injection, and reviewer-verdict parsing | These signals are what stop an unverified finding from reaching a report looking like a fact. |
| `test_lane_config.py` | Lane resolution precedence and thread isolation | Jobs run in worker threads carrying different users' API keys. A module-global override would let one user's key bill another user's job. |

`test_lane_config.py` imports the LLM client, which needs `pydantic` and the
OpenAI SDK from `requirements.txt`; it skips cleanly if they are absent.

## Regressions pinned here

Two parser bugs were found while writing these tests and are now pinned:

- **ZAP severity collapse.** ZAP writes `riskdesc` as `"High (Medium)"` (risk and
  confidence together). Normalizing the whole string fell through to
  `Informational`, quietly demoting every High alert into the noise bucket that
  the import filter hides by default.
- **Burp CWE loss.** Burp reports the CWE in `vulnerabilityClassifications`,
  which the parser did not read, so Burp findings arrived with no CWE and were
  therefore left unmapped to OWASP, PCI, and ATT&CK.

## Conventions

Test names state the behaviour being protected, not the function being called,
and non-obvious assertions carry a comment explaining the consequence of the
behaviour breaking. A test that cannot say why it exists is a test nobody will
maintain.
