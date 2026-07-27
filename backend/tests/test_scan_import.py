"""Scanner import: parsing, normalization, deduplication, and noise filtering.

These run entirely offline on small inline fixtures. The parsers are the part of
the system most likely to be fed hostile or malformed input, so malformed files
must degrade rather than raise.
"""
import xml.etree.ElementTree as ET

import pytest

import scan_import


def xml_root(text):
    return ET.fromstring(text)


class TestSeverityNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", "Critical"),
            ("CRITICAL", "Critical"),
            ("High", "High"),
            ("HIGH", "High"),
            ("med", "Medium"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Informational"),
            ("Info", "Informational"),
            ("informational", "Informational"),
        ],
    )
    def test_known_values(self, raw, expected):
        assert scan_import.canon_severity(raw) == expected

    @pytest.mark.parametrize("raw", ["", None, "wat", "purple"])
    def test_unknown_defaults_to_informational(self, raw):
        """Unrecognized input must not silently become High."""
        assert scan_import.canon_severity(raw) == "Informational"

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("High (Medium)", "High"),
            ("Medium (High)", "Medium"),
            ("Low (Low)", "Low"),
            ("Informational (Low)", "Informational"),
        ],
    )
    def test_zap_risk_and_confidence_form(self, raw, expected):
        """Regression: ZAP writes riskdesc as "risk (confidence)". Reading the
        whole string fell through to Informational, quietly demoting every High
        alert into the noise bucket."""
        assert scan_import.canon_severity(raw) == expected


class TestCweExtraction:
    """A fabricated CWE is worse than no CWE: it looks authoritative in a report
    and sends the reader to the wrong remediation."""

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("CWE-79 reflected xss", "CWE-79"),
            ("cwe 89", "CWE-89"),
            ("See CWE-352 for detail", "CWE-352"),
        ],
    )
    def test_extracts_real_cwe(self, text, expected):
        assert scan_import._first_cwe(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "HTTP 500 internal server error",  # status code, not a CWE
            "plugin 12345 fired",              # scanner plugin id
            "Port 8080 open",                  # port number
            "Found 79 instances",              # bare count
            "",
        ],
    )
    def test_bare_numbers_never_become_cwes(self, text):
        assert scan_import._first_cwe(text) == ""

    def test_dedicated_field_accepts_bare_number(self):
        """In a column that means 'CWE', a bare number is unambiguous."""
        assert scan_import._cwe_from_field("79") == "CWE-79"
        assert scan_import._cwe_from_field("CWE-89") == "CWE-89"

    @pytest.mark.parametrize("raw", ["", "n/a", "none", None])
    def test_dedicated_field_rejects_non_values(self, raw):
        assert scan_import._cwe_from_field(raw) == ""


class TestBurpParser:
    BURP = """<?xml version="1.0"?>
    <issues>
      <issue>
        <name>SQL injection</name>
        <host ip="10.0.0.1">https://target.test</host>
        <path>/api/search</path>
        <severity>High</severity>
        <confidence>Certain</confidence>
        <issueDetail>Parameter q is injectable</issueDetail>
        <vulnerabilityClassifications>CWE-89: SQL Injection</vulnerabilityClassifications>
      </issue>
      <issue>
        <name>Strict transport security not enforced</name>
        <host>https://target.test</host>
        <path>/</path>
        <severity>Information</severity>
        <confidence>Certain</confidence>
      </issue>
    </issues>"""

    def test_extracts_issues(self):
        out = scan_import.parse_burp(xml_root(self.BURP))
        assert len(out) == 2
        assert out[0]["title"] == "SQL injection"
        assert out[0]["severity"] == "High"

    def test_maps_cwe_from_classification(self):
        """Regression: Burp reports the CWE in vulnerabilityClassifications. Only
        reading issueBackground and the title left every Burp finding without a
        CWE, which then left it unmapped to OWASP, PCI, and ATT&CK."""
        out = scan_import.parse_burp(xml_root(self.BURP))
        assert out[0]["cwe"] == "CWE-89"

    def test_builds_asset_url(self):
        out = scan_import.parse_burp(xml_root(self.BURP))
        assert "target.test" in out[0]["affected_url"]
        assert "/api/search" in out[0]["affected_url"]

    def test_tags_source(self):
        out = scan_import.parse_burp(xml_root(self.BURP))
        assert all(c["source"] for c in out)


class TestZapParser:
    ZAP_JSON = {
        "site": [
            {
                "@name": "https://target.test",
                "alerts": [
                    {
                        "alert": "Cross Site Scripting (Reflected)",
                        "riskdesc": "High (Medium)",
                        "cweid": "79",
                        "desc": "<p>Reflected XSS</p>",
                        "solution": "<p>Encode output</p>",
                        "instances": [{"uri": "https://target.test/search", "param": "q"}],
                    }
                ],
            }
        ]
    }

    def test_parses_alerts(self):
        out = scan_import.parse_zap_json(self.ZAP_JSON)
        assert len(out) == 1
        assert out[0]["severity"] == "High"

    def test_severity_survives_compound_riskdesc(self):
        """A High alert must stay High even when riskcode is absent and only the
        compound riskdesc is available."""
        report = {
            "site": [
                {
                    "@name": "https://target.test",
                    "alerts": [{"alert": "SQLi", "riskdesc": "High (Medium)", "cweid": "89"}],
                }
            ]
        }
        assert scan_import.parse_zap_json(report)[0]["severity"] == "High"

    def test_cwe_from_dedicated_field(self):
        out = scan_import.parse_zap_json(self.ZAP_JSON)
        assert out[0]["cwe"] == "CWE-79"

    def test_html_stripped_from_description(self):
        out = scan_import.parse_zap_json(self.ZAP_JSON)
        assert "<p>" not in out[0].get("description", "")

    def test_empty_report_is_not_an_error(self):
        assert scan_import.parse_zap_json({"site": []}) == []


class TestNessusParser:
    NESSUS = """<?xml version="1.0"?>
    <NessusClientData_v2><Report><ReportHost name="10.0.0.5">
      <ReportItem port="443" severity="3" pluginID="12345"
                  pluginName="TLS Version 1.0 Protocol Detection">
        <description>The remote service accepts TLS 1.0.</description>
        <solution>Disable TLS 1.0.</solution>
        <cwe>327</cwe>
      </ReportItem>
      <ReportItem port="0" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
        <description>Informational plugin output.</description>
      </ReportItem>
    </ReportHost></Report></NessusClientData_v2>"""

    def test_extracts_items(self):
        out = scan_import.parse_nessus(xml_root(self.NESSUS))
        assert len(out) == 2

    def test_numeric_severity_mapped(self):
        out = scan_import.parse_nessus(xml_root(self.NESSUS))
        by_title = {c["title"]: c for c in out}
        assert by_title["TLS Version 1.0 Protocol Detection"]["severity"] == "High"
        assert by_title["Nessus Scan Information"]["severity"] == "Informational"

    def test_host_recorded(self):
        out = scan_import.parse_nessus(xml_root(self.NESSUS))
        assert any("10.0.0.5" in (c.get("affected_host") or "") for c in out)

    def test_plugin_id_not_mistaken_for_cwe(self):
        """pluginID 19506 must not surface as CWE-19506."""
        out = scan_import.parse_nessus(xml_root(self.NESSUS))
        info = [c for c in out if c["title"] == "Nessus Scan Information"][0]
        assert info.get("cwe", "") in ("", None)


class TestNmapParser:
    NMAP = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="10.0.0.9" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    def test_reports_open_ports(self):
        out = scan_import.parse_nmap(xml_root(self.NMAP))
        assert len(out) >= 1
        assert any("22" in c["title"] for c in out)

    def test_closed_ports_excluded(self):
        out = scan_import.parse_nmap(xml_root(self.NMAP))
        assert not any("443" in c["title"] for c in out)

    def test_open_ports_are_informational_not_vulnerabilities(self):
        """An open port is an observation. Rating it High would flood the report."""
        out = scan_import.parse_nmap(xml_root(self.NMAP))
        assert all(c["severity"] in ("Informational", "Low") for c in out)


class TestCsvParser:
    CSV = (
        "Title,Severity,Host,URL,CWE,Description\n"
        "Directory listing,Medium,target.test,https://target.test/uploads/,548,Listing enabled\n"
        "Missing header,Low,target.test,https://target.test/,,No CSP\n"
    )

    def test_parses_rows(self):
        out = scan_import.parse_csv(self.CSV)
        assert len(out) == 2

    def test_maps_columns(self):
        out = scan_import.parse_csv(self.CSV)
        assert out[0]["title"] == "Directory listing"
        assert out[0]["severity"] == "Medium"
        assert out[0]["cwe"] == "CWE-548"

    def test_blank_cwe_stays_blank(self):
        out = scan_import.parse_csv(self.CSV)
        assert out[1]["cwe"] == ""

    def test_empty_csv_is_not_an_error(self):
        assert scan_import.parse_csv("") == []
        assert scan_import.parse_csv("Title,Severity\n") == []


class TestFormatDetection:
    """detect_and_parse returns (format_name, candidates, warnings)."""

    def test_detects_burp(self):
        fmt, candidates, warnings = scan_import.detect_and_parse("burp.xml", TestBurpParser.BURP.encode())
        assert "Burp" in fmt
        assert candidates
        assert warnings == []

    def test_detects_nessus(self):
        fmt, candidates, _ = scan_import.detect_and_parse("scan.nessus", TestNessusParser.NESSUS.encode())
        assert "Nessus" in fmt
        assert candidates

    def test_detects_csv(self):
        fmt, candidates, _ = scan_import.detect_and_parse("findings.csv", TestCsvParser.CSV.encode())
        assert "CSV" in fmt.upper()
        assert len(candidates) == 2

    def test_detects_nmap(self):
        fmt, candidates, _ = scan_import.detect_and_parse("scan.xml", TestNmapParser.NMAP.encode())
        assert "Nmap" in fmt
        assert candidates

    def test_har_reported_as_unsupported_with_a_reason(self):
        """HAR is proxy traffic, not findings. Silently returning nothing would
        look like a clean scan, so it has to explain itself."""
        fmt, candidates, warnings = scan_import.detect_and_parse("traffic.har", b'{"log": {"entries": []}}')
        assert "unsupported" in fmt.lower()
        assert candidates == []
        assert warnings and "HAR" in warnings[0]

    def test_malformed_xml_degrades_gracefully(self):
        _, candidates, warnings = scan_import.detect_and_parse("broken.xml", b"<issues><issue>unclosed")
        assert candidates == []
        assert warnings

    def test_empty_file_degrades_gracefully(self):
        _, candidates, _ = scan_import.detect_and_parse("empty.xml", b"")
        assert candidates == []

    def test_binary_garbage_does_not_raise(self):
        _, candidates, _ = scan_import.detect_and_parse("junk.xml", bytes(range(256)))
        assert candidates == []


class TestDeduplication:
    """dedupe returns (candidates, removed_count)."""

    BASE = dict(
        title="XSS",
        severity="High",
        affected_host="target.test",
        affected_url="https://target.test/a",
        parameter="q",
        source="burp",
    )

    def test_identical_findings_collapse(self):
        kept, removed = scan_import.dedupe([dict(self.BASE), dict(self.BASE)])
        assert len(kept) == 1
        assert removed == 1

    def test_same_issue_different_url_kept_separate(self):
        """Two injectable endpoints are two findings: collapsing them hides an
        affected asset from the report."""
        kept, removed = scan_import.dedupe([dict(self.BASE), dict(self.BASE, affected_url="https://target.test/b")])
        assert len(kept) == 2
        assert removed == 0

    def test_same_url_different_parameter_kept_separate(self):
        kept, _ = scan_import.dedupe([dict(self.BASE), dict(self.BASE, parameter="lang")])
        assert len(kept) == 2

    def test_different_host_kept_separate(self):
        kept, _ = scan_import.dedupe([dict(self.BASE), dict(self.BASE, affected_host="other.test")])
        assert len(kept) == 2

    def test_empty_input(self):
        kept, removed = scan_import.dedupe([])
        assert kept == []
        assert removed == 0


class TestSummaryAndOrdering:
    CANDIDATES = [
        {"title": "Info item", "severity": "Informational", "noise": True},
        {"title": "Critical item", "severity": "Critical"},
        {"title": "Medium item", "severity": "Medium"},
        {"title": "High item", "severity": "High"},
    ]

    def test_summary_counts(self):
        s = scan_import.summarize(self.CANDIDATES)
        assert s["total"] == 4
        assert s["noise"] >= 1
        assert s["actionable"] == s["total"] - s["noise"]

    def test_sorted_most_severe_first(self):
        ordered = scan_import.sort_candidates(self.CANDIDATES)
        assert ordered[0]["severity"] == "Critical"
        assert [c["severity"] for c in ordered][:3] == ["Critical", "High", "Medium"]

    def test_summary_of_empty(self):
        s = scan_import.summarize([])
        assert s["total"] == 0
