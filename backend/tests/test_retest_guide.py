"""Retest-guide generation.

The guide is derived from a finding on demand, never stored, so these tests pin the
two properties that make it trustworthy: the commands carry the finding's real
target values, and they never carry anything the finding did not supply -- no
invented host, port or endpoint, and no secret from raw evidence.
"""
import retest_guide as rg


def find(**kw):
    base = {
        "title": "", "description": "", "category": "", "cwe": "",
        "severity": "Medium", "affected_host": "", "affected_url": "",
        "http_method": "", "parameter": "", "evidence": "",
    }
    base.update(kw)
    return base


def _all_commands(guide):
    return "\n".join(c["command"] for c in guide["commands"])


class TestTargetExtraction:
    def test_port_from_https_scheme(self):
        t = rg.extract_target(find(affected_url="https://a.example.com/x"))
        assert t["host"] == "a.example.com"
        assert t["port"] == "443"

    def test_explicit_port_in_url_wins(self):
        t = rg.extract_target(find(affected_url="https://a.example.com:8443/x"))
        assert t["port"] == "8443"

    def test_host_port_in_affected_host(self):
        t = rg.extract_target(find(affected_host="10.0.0.9:2222"))
        assert t["host"] == "10.0.0.9"
        assert t["port"] == "2222"

    def test_bare_host_has_no_inferred_port(self):
        # A hostname with no scheme implies no port -- it must not be guessed.
        t = rg.extract_target(find(affected_host="10.0.0.9"))
        assert t["port"] == ""


class TestTlsCertificate:
    def test_expired_cert_builds_openssl_and_nmap(self):
        g = rg.build_guide(find(
            title="Expired/Untrusted TLS Certificate",
            cwe="CWE-295", category="Network Security",
            affected_host="shop.example.com",
            affected_url="https://shop.example.com/",
        ))
        assert g["kind"] == "network"
        cmds = _all_commands(g)
        assert "openssl s_client -connect shop.example.com:443" in cmds
        assert "ssl-cert" in cmds
        # No placeholders: host and port were both resolvable.
        assert g["placeholders"] == []
        assert g["pass_fail"]
        assert g["expected_vulnerable"] and g["expected_remediated"]

    def test_missing_host_becomes_placeholder(self):
        g = rg.build_guide(find(
            title="Untrusted TLS certificate", cwe="CWE-295",
            category="Network Security",
        ))
        cmds = _all_commands(g)
        assert rg.PLACEHOLDER_HOST in cmds
        phs = [p["placeholder"] for p in g["placeholders"]]
        assert rg.PLACEHOLDER_HOST in phs


class TestWeakSsh:
    def test_ssh_algos_with_default_port(self):
        g = rg.build_guide(find(
            title="Weak SSH Key Exchange Algorithms (diffie-hellman-group1-sha1)",
            category="Network Security", affected_host="192.0.2.10",
        ))
        assert g["class"] == "ssh"
        cmds = _all_commands(g)
        assert "nmap -Pn -p 22 --script ssh2-enum-algos 192.0.2.10" in cmds
        # The pass criterion must be about the *named* algorithms.
        assert "no longer offered" in g["pass_fail"]

    def test_ssh_classifies_without_cwe(self):
        # risk_map has no ssh keyword; the retest signal must still catch it.
        g = rg.build_guide(find(title="OpenSSH weak MAC algorithms",
                                 affected_host="host.example"))
        assert g["class"] == "ssh"


class TestWebFindings:
    def test_missing_headers_uses_curl_and_url(self):
        g = rg.build_guide(find(
            title="Missing Security Headers (HSTS, CSP)", cwe="CWE-693",
            category="Web Application/API Vulnerability",
            affected_url="https://app.example.com/login",
        ))
        assert g["kind"] == "web"
        cmds = _all_commands(g)
        assert "curl -sSI" in cmds
        assert "https://app.example.com/login" in cmds

    def test_reflected_xss_uses_benign_probe_not_executing_payload(self):
        g = rg.build_guide(find(
            title="Reflected Cross-Site Scripting", cwe="CWE-79",
            category="Web Application/API Vulnerability",
            affected_url="https://app.example.com/search",
            http_method="GET", parameter="q",
        ))
        assert g["class"] == "xss"
        cmds = _all_commands(g)
        # The finding's real parameter is used.
        assert "q=" in cmds
        # A benign marker, never a live payload like <script>alert(1)</script>.
        assert "rt5PROBE" in cmds
        assert "alert(" not in cmds

    def test_missing_parameter_becomes_placeholder(self):
        g = rg.build_guide(find(
            title="Reflected XSS", cwe="CWE-79",
            affected_url="https://app.example.com/x",
        ))
        cmds = _all_commands(g)
        assert rg.PLACEHOLDER_PARAM in cmds

    def test_sql_injection_is_non_destructive(self):
        g = rg.build_guide(find(
            title="SQL Injection", cwe="CWE-89",
            affected_url="https://app.example.com/item", parameter="id",
        ))
        assert g["class"] == "injection"
        cmds = _all_commands(g).lower()
        # Differential/error probes only -- never destructive SQL.
        assert "drop table" not in cmds
        assert "delete from" not in cmds
        assert "and '1'='1" in cmds

    def test_access_control_needs_two_principals(self):
        g = rg.build_guide(find(
            title="IDOR", cwe="CWE-639",
            affected_url="https://api.example.com/orders/1001", http_method="GET",
        ))
        assert g["class"] == "access_control"
        joined = " ".join(g["prerequisites"]).lower()
        assert "principal" in joined or "account" in joined
        # Token is a placeholder to fill at test time, never taken from evidence.
        assert "<TOKEN_B>" in _all_commands(g)


class TestNoFabrication:
    def test_no_target_yields_placeholders_not_invented_values(self):
        g = rg.build_guide(find(title="Some TLS certificate issue", cwe="CWE-295"))
        cmds = _all_commands(g)
        # Nothing that looks like a made-up host or IP.
        assert "example.com" not in cmds.replace("evil.example", "")
        assert rg.PLACEHOLDER_HOST in cmds

    def test_unknown_class_falls_back_without_specialised_commands(self):
        g = rg.build_guide(find(title="Something unusual and unmapped",
                                 affected_url="https://x.example.com/y"))
        # Generic reproducer, not a fabricated specialised tool invocation.
        assert g["class"] in ("unclassified", "misconfig")
        assert g["commands"]


class TestPlaceholdersMatchCommands:
    def test_template_supplied_default_is_not_reported_as_placeholder(self):
        # The SSH template fills in port 22 itself. Telling the tester to replace
        # <PORT> in a command that already reads 22 would be actively confusing.
        g = rg.build_guide(find(title="Weak SSH algorithms",
                                 category="Network Security",
                                 affected_host="192.0.2.10"))
        assert "-p 22" in _all_commands(g)
        assert g["placeholders"] == []

    def test_token_placeholder_is_surfaced(self):
        # A placeholder a template introduces directly must still be listed.
        g = rg.build_guide(find(title="IDOR", cwe="CWE-639",
                                 affected_url="https://api.example.com/orders/1001",
                                 http_method="GET"))
        assert "<TOKEN_B>" in [p["placeholder"] for p in g["placeholders"]]

    def test_every_listed_placeholder_appears_in_the_guide(self):
        for f in (find(), find(title="Untrusted certificate", cwe="CWE-295"),
                  find(title="Reflected XSS", cwe="CWE-79",
                       affected_url="https://a.example/x"),
                  find(title="CSRF", cwe="CWE-352", affected_url="https://a.example/pay")):
            g = rg.build_guide(f)
            blob = _all_commands(g)
            for p in g["placeholders"]:
                assert p["placeholder"] in blob
                assert p["means"]


class TestRedaction:
    def test_request_body_is_redacted_in_xss_guide(self):
        evidence = (
            "POST /search HTTP/1.1\n"
            "Host: app.example.com\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "q=test&api_key=SUPERSECRETVALUE12345"
        )
        g = rg.build_guide(find(
            title="Reflected XSS", cwe="CWE-79",
            affected_url="https://app.example.com/search",
            http_method="POST", parameter="q", evidence=evidence,
        ))
        blob = rg.copy_all_text(g)
        # The captured secret must not survive into the guide.
        assert "SUPERSECRETVALUE12345" not in blob
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in blob

    def test_copy_all_lists_placeholders_to_replace(self):
        g = rg.build_guide(find(title="Untrusted certificate", cwe="CWE-295"))
        blob = rg.copy_all_text(g)
        assert "Replace these placeholders" in blob
        assert rg.PLACEHOLDER_HOST in blob


class TestStructure:
    def test_guide_always_complete(self):
        # Every finding, however sparse, gets a fully-populated guide.
        for f in (find(), find(title="x"), find(affected_host="h")):
            g = rg.build_guide(f)
            for key in ("objective", "commands", "expected_vulnerable",
                        "expected_remediated", "pass_fail", "evidence_to_capture"):
                assert g[key], f"missing {key} for {f}"
            assert isinstance(g["commands"], list) and g["commands"]

    def test_copy_all_is_plain_text_with_commands(self):
        g = rg.build_guide(find(
            title="Weak SSH algorithms", affected_host="10.0.0.5",
        ))
        blob = rg.copy_all_text(g)
        assert "ssh2-enum-algos" in blob
        assert "Objective:" in blob
        assert "Pass/Fail:" in blob
