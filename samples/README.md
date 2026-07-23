# Sample data

Synthetic files for trying the tool without pointing it at anything real. Every
host here is an RFC 2606 reserved `.test` domain and every address is from the
RFC 5737 documentation ranges. **No real system was scanned and no client data
appears in any of these files.**

Use these for demos, screenshots, and manual testing. They are also what the
import flow was exercised against.

## Scanner imports

Upload any of these under **Import**, then run AI triage before committing.

| File | Format | Parses to | Notes |
| --- | --- | --- | --- |
| `burp-suite-report.xml` | Burp Suite XML | 5 candidates | 2 High, 1 Medium, 1 Low, 1 informational |
| `zap-report.json` | OWASP ZAP JSON | 5 alerts | 2 High, 1 Medium, 1 Low, 1 informational |
| `nessus-scan.nessus` | Nessus | 5 items | 1 Critical (CVE-2022-3602), 2 filtered as noise |
| `nmap-scan.xml` | Nmap XML | 4 open ports | All informational: an open port is an observation, not a vulnerability |
| `generic-findings.csv` | CSV | 6 findings | Manual findings including IDOR, SSRF, and JWT algorithm confusion |

You can upload several at once. The importer normalizes severities, maps CWEs,
and deduplicates on `(title, host, url, parameter)`, so the same issue found at
two different URLs stays as two findings.

## Analyzer evidence

`analyzer-evidence.txt` contains five sections of synthetic HTTP evidence:
broken object-level authorization, SQL injection, SSRF against a metadata
endpoint, JWT algorithm confusion, and a set of response headers for header
analysis. Paste the whole file into the **Analyzer**, or one section at a time.

## What these are designed to demonstrate

The sample set deliberately mixes findings that should survive review with
findings that should not, so triage has something real to do:

**Should hold up.** The SQL injection carries differential responses and a
time-based delay. The IDOR was tested with two provisioned accounts. The SSRF
returned metadata content. The JWT bypass returned administrative data with an
unsigned token. These have evidence attached to them.

**Should be challenged.** The frameable-response finding is on a static terms
page with no forms and no authenticated state. The host-header injection is
reported at *Tentative* confidence against a static CDN asset. The directory
listing is on an empty directory. Missing security headers are reported against
static assets. These are the findings a report should either drop or downgrade,
and they are the ones the reviewer lane is there to catch.

Running triage on the Burp or ZAP file is the quickest way to see the difference
between a finding with evidence behind it and a finding that merely pattern
matched.
