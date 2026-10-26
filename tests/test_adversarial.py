"""
Adversarial robustness test suite for PhishGuard URL classifier.

Tests evasion techniques commonly used by phishing actors:
- Homograph / IDN attacks
- Punycode encoding
- URL obfuscation (percent-encoding, hex escapes)
- Subdomain abuse and typosquatting patterns
- IP-literal hosts
- Credential embedding (@-sign trick)
- Redirect bait structure
- Excessively long paths and query strings

Each test checks that the feature extractor either:
  (a) correctly encodes the suspicious signal as a non-zero feature, OR
  (b) raises ValueError for structurally invalid input (also correct behaviour).

These tests do NOT require a trained model — they validate that the feature
pipeline captures the signals a model can learn from.
"""
from __future__ import annotations

import pytest

from phishguard.features import extract_url_features

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def features(url: str) -> dict:
    """Return features or raise ValueError — callers decide which is expected."""
    return extract_url_features(url)


# ---------------------------------------------------------------------------
# 1. IP-literal host (common in phishing, rare in legit sites)
# ---------------------------------------------------------------------------

class TestIPLiteralHost:
    def test_ipv4_detected(self):
        f = features("http://192.0.2.1/login.php?user=admin")
        assert f["is_domain_ip"] == 1.0

    def test_ipv4_in_path_not_flagged(self):
        # IP only in path, not host — should NOT trigger is_domain_ip
        f = features("https://example.com/redirect?to=192.0.2.1")
        assert f["is_domain_ip"] == 0.0

    def test_ipv6_literal_detected(self):
        f = features("http://[2001:db8::1]/secure/login")
        assert f["is_domain_ip"] == 1.0


# ---------------------------------------------------------------------------
# 2. @-sign credential embedding  (http://legit.com@evil.com/path)
# ---------------------------------------------------------------------------

class TestAtSignTrick:
    def test_at_sign_in_url_flagged(self):
        f = features("http://secure.bank.com@192.0.2.99/account")
        assert f["has_at_symbol"] == 1.0
        assert f["is_domain_ip"] == 1.0  # real host is the IP

    def test_at_sign_absent_for_clean_url(self):
        f = features("https://bank.example.com/login")
        assert f["has_at_symbol"] == 0.0


# ---------------------------------------------------------------------------
# 3. Punycode / IDN homograph attack
# ---------------------------------------------------------------------------

class TestPunycode:
    def test_punycode_prefix_detected(self):
        # xn--e1afmkfd.com is a Cyrillic lookalike domain
        f = features("https://xn--e1afmkfd.com/login")
        assert f["has_punycode"] == 1.0

    def test_nested_punycode_subdomain(self):
        f = features("https://xn--pple-43d.xn--e1afmkfd.com/secure")
        assert f["has_punycode"] == 1.0

    def test_clean_ascii_domain_not_flagged(self):
        f = features("https://apple.com/store")
        assert f["has_punycode"] == 0.0


# ---------------------------------------------------------------------------
# 4. Subdomain abuse / typosquatting structure
# ---------------------------------------------------------------------------

class TestSubdomainAbuse:
    def test_deep_subdomain_chain(self):
        # e.g. login.secure.account.evil.com — 3 subdomains
        f = features("http://login.secure.account.evil.com/verify")
        assert f["no_of_subdomain"] >= 3

    def test_apex_domain_has_zero_subdomains(self):
        f = features("https://example.com/page")
        assert f["no_of_subdomain"] == 0.0

    def test_single_subdomain(self):
        f = features("https://mail.example.com/inbox")
        assert f["no_of_subdomain"] == 1.0


# ---------------------------------------------------------------------------
# 5. Percent-encoding / obfuscation evasion
# ---------------------------------------------------------------------------

class TestObfuscation:
    def test_percent_encoded_path_flagged(self):
        # %2F, %3A are common obfuscation chars
        f = features("http://evil.com/%2Flogin%2Faccount%3Fuser%3Dadmin")
        assert f["has_obfuscation"] == 1.0
        assert f["no_of_obfuscated_char"] >= 4

    def test_clean_url_not_obfuscated(self):
        f = features("https://example.com/search?q=hello")
        assert f["has_obfuscation"] == 0.0

    def test_obfuscation_ratio_is_nonzero(self):
        f = features("http://evil.com/%41%42%43")  # %41=%A, %42=B, %43=C
        assert f["obfuscation_ratio"] > 0.0


# ---------------------------------------------------------------------------
# 6. Excessively long URL (padding / evasion)
# ---------------------------------------------------------------------------

class TestURLLength:
    def test_very_long_url_captured(self):
        padding = "a" * 300
        f = features(f"http://evil.com/login?token={padding}")
        assert f["url_length"] > 300
        assert f["query_length"] > 300

    def test_url_over_limit_rejected(self):
        with pytest.raises(ValueError, match="too long"):
            features("http://evil.com/" + "x" * 4100)


# ---------------------------------------------------------------------------
# 7. Non-HTTP schemes (must be rejected, not silently misclassified)
# ---------------------------------------------------------------------------

class TestSchemeRejection:
    @pytest.mark.parametrize("url", [
        "javascript:alert(document.cookie)",
        "data:text/html,<script>alert(1)</script>",
        "ftp://files.evil.com/malware.exe",
        "file:///etc/passwd",
        "vbscript:msgbox('xss')",
    ])
    def test_non_http_scheme_rejected(self, url: str):
        with pytest.raises(ValueError):
            features(url)


# ---------------------------------------------------------------------------
# 8. Control-character injection (HTTP header smuggling / log poisoning)
# ---------------------------------------------------------------------------

class TestControlCharacterInjection:
    @pytest.mark.parametrize("url", [
        "https://example.com/path\nX-Injected: header",
        "https://example.com/path\rContent-Length: 0",
        "https://example.com/\x00null",
        "https://example.com/path\x1bESC",
    ])
    def test_control_chars_rejected(self, url: str):
        with pytest.raises(ValueError, match="control"):
            features(url)


# ---------------------------------------------------------------------------
# 9. Hyphen abuse (typosquatting pattern: paypa1-secure-login.com)
# ---------------------------------------------------------------------------

class TestHyphenAbuse:
    def test_hyphen_heavy_domain_counted(self):
        f = features("http://paypal-secure-login-verify.com/account")
        assert f["hyphen_count"] >= 3

    def test_clean_domain_low_hyphens(self):
        f = features("https://well-known.example.com/page")
        assert f["hyphen_count"] <= 2


# ---------------------------------------------------------------------------
# 10. Dot count in host (subdomain depth proxy)
# ---------------------------------------------------------------------------

class TestDotCount:
    def test_many_dots_in_deep_subdomain(self):
        f = features("http://a.b.c.d.evil.com/x")
        assert f["dot_count"] >= 5

    def test_apex_has_one_dot(self):
        f = features("https://example.com/")
        assert f["dot_count"] == 1.0


# ---------------------------------------------------------------------------
# 11. Feature schema contract (regression guard)
# ---------------------------------------------------------------------------

class TestFeatureSchemaContract:
    REQUIRED_SECURITY_FEATURES = {
        "is_domain_ip", "has_obfuscation", "has_at_symbol",
        "has_punycode", "no_of_subdomain", "hyphen_count",
        "obfuscation_ratio", "is_https",
    }

    def test_all_security_features_present(self):
        f = features("https://example.com/path?q=1")
        missing = self.REQUIRED_SECURITY_FEATURES - set(f)
        assert not missing, f"Missing security features: {missing}"

    def test_all_values_are_numeric(self):
        f = features("http://192.0.2.1/login?user=admin&pass=x")
        for name, val in f.items():
            assert isinstance(val, float), f"Feature '{name}' is {type(val)}, expected float"
