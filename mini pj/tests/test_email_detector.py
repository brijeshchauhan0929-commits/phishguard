import pytest
from detectors.email_detector import EmailThreatDetector

@pytest.fixture
def detector():
    return EmailThreatDetector()

def test_safe_email(detector):
    sender = 'GitHub Team <notifications@github.com>'
    subject = 'Your repository was updated'
    body = 'Hello Brijesh, your recent pull request was successfully merged into main.'
    result = detector.analyze(sender, subject, body)
    assert result['risk_score'] < 35
    assert result['risk_level'] == 'LOW RISK'

def test_urgent_phishing_email(detector):
    sender = 'PayPal Security <support@phish-domain-alert.xyz>'
    subject = 'URGENT: Unauthorized Account Access Detected - 24 Hours to Respond'
    body = 'Dear Customer, your funds will be suspended immediately unless you verify your password at http://paypa1-security-verification.xyz/login.'
    result = detector.analyze(sender, subject, body)
    assert result['risk_score'] >= 70
    assert result['risk_level'] == 'PHISHING LIKELY'
    assert result['concern_count'] >= 3

def test_ceo_fraud_gift_card(detector):
    sender = 'CEO John Doe <ceo.executive.direct@gmail.com>'
    subject = 'Urgent assistance needed - Gift Card Request'
    body = 'Hi, please purchase 5 apple gift cards right away and send the codes back to me.'
    result = detector.analyze(sender, subject, body)
    assert result['risk_score'] >= 50
    flag_ids = [ind['id'] for ind in result['indicators']]
    assert 'financial_scam' in flag_ids
