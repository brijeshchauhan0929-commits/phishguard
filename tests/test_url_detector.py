import pytest
from detectors.url_detector import URLPhishingDetector

@pytest.fixture
def detector():
    return URLPhishingDetector()

def test_safe_url(detector):
    result = detector.analyze('https://accounts.google.com/signin/v2/identifier')
    assert result['risk_score'] < 35
    assert result['risk_level'] == 'LOW RISK'
    assert result['risk_badge'] == 'success'
    assert result['passed_count'] > 0

def test_typosquatting_phishing_url(detector):
    result = detector.analyze('http://paypa1-security-verification.xyz/login.php')
    assert result['risk_score'] >= 70
    assert result['risk_level'] == 'PHISHING LIKELY'
    assert result['risk_badge'] == 'danger'
    assert result['concern_count'] >= 2

def test_raw_ip_address_url(detector):
    result = detector.analyze('http://192.168.1.100/login/bank')
    assert result['risk_score'] >= 50
    flag_names = [c['id'] for c in result['potential_concerns']]
    assert 'ip_address' in flag_names

def test_url_shortener(detector):
    result = detector.analyze('https://bit.ly/3x8Qz9A')
    flag_names = [c['id'] for c in result['potential_concerns']]
    assert 'url_shortener' in flag_names

def test_punycode_homograph(detector):
    result = detector.analyze('http://xn--pple-43d.com/login')
    flag_names = [c['id'] for c in result['potential_concerns']]
    assert 'punycode_homograph' in flag_names
