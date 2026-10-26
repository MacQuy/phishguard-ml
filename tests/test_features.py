import pytest
from phishguard.features import FEATURE_NAMES, extract_url_features, features_frame

def test_feature_schema_is_stable():
    features = extract_url_features("https://example.com/path?q=1")
    assert list(features) == FEATURE_NAMES
    assert features["is_https"] == 1.0
    assert features["no_of_question_marks"] == 1.0

def test_ip_host_is_detected():
    assert extract_url_features("http://192.0.2.1/login")["is_domain_ip"] == 1.0

def test_punycode_is_detected():
    assert extract_url_features("https://xn--e1afmkfd.example")["has_punycode"] == 1.0

def test_empty_url_rejected():
    with pytest.raises(ValueError):
        extract_url_features("  ")

def test_non_http_scheme_rejected():
    with pytest.raises(ValueError):
        extract_url_features("javascript:alert(1)")

def test_control_characters_rejected():
    with pytest.raises(ValueError):
        extract_url_features("https://example.com/\nheader")

def test_frame_column_order():
    frame = features_frame(["example.com", "https://example.org"] )
    assert list(frame.columns) == FEATURE_NAMES
    assert frame.shape == (2, len(FEATURE_NAMES))
