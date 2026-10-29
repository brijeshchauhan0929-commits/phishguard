import pytest
from app import app
import database

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            database.init_db()
        yield client

def test_landing_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'PHISHGUARD' in response.data
    assert b'Detect Phishing.' in response.data
    assert b'Chauhan Brijesh Ramayan' in response.data
    assert b'Jagruti Raut' in response.data

def test_scanner_get_and_post(client):
    response = client.get('/scanner')
    assert response.status_code == 200
    assert b'URL Phishing Scanner' in response.data

    post_resp = client.post('/scanner', data={'url': 'https://accounts.google.com/signin'})
    assert post_resp.status_code == 200
    assert b'Inspection Result' in post_resp.data

def test_email_get_and_post(client):
    response = client.get('/email')
    assert response.status_code == 200
    assert b'Email Threat Analyzer' in response.data

    post_resp = client.post('/email', data={
        'sender': 'Alerts <alert@test.xyz>',
        'subject': 'Urgent notification',
        'body': 'Click here immediately to verify account'
    })
    assert post_resp.status_code == 200
    assert b'Email Inspection Result' in post_resp.data

def test_awareness_page(client):
    response = client.get('/awareness')
    assert response.status_code == 200
    assert b'Awareness &amp; Defense Hub' in response.data or b'Awareness & Defense Hub' in response.data

def test_quiz_page_and_api(client):
    response = client.get('/quiz')
    assert response.status_code == 200
    assert b'quizApp' in response.data

    api_resp = client.post('/api/quiz/submit', json={
        'score': 10,
        'total': 10,
        'percentage': 100.0,
        'rating': 'Cyber Defender (Expert)',
        'answers': []
    })
    assert api_resp.status_code == 200
    assert api_resp.get_json()['status'] == 'success'

def test_reports_view_and_export(client):
    response = client.get('/reports')
    assert response.status_code == 200
    assert b'Security Inspection Reports' in response.data

    export_resp = client.get('/reports/export')
    assert export_resp.status_code == 200
    assert 'text/csv' in export_resp.headers['Content-Type']
