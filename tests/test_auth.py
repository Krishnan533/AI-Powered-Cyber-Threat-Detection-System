import os
import pytest
from backend.app import create_app
from backend.extensions import db
from backend.models.user import User

@pytest.fixture
def app():
    # Force sqlite in-memory for unit testing
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        # Seed test user
        user = User(username='testadmin', role='Admin')
        user.set_password('AdminSecPass123!')
        db.session.add(user)
        db.session.commit()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_login_view(client):
    """Test login HTML page rendering."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b"AUTHENTICATE" in response.data

def test_login_api_success(client):
    """Test successful JSON endpoint login."""
    response = client.post('/api/auth/login', json={
        'username': 'testadmin',
        'password': 'AdminSecPass123!'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['user']['username'] == 'testadmin'

def test_login_api_failure(client):
    """Test login failure with invalid password."""
    response = client.post('/api/auth/login', json={
        'username': 'testadmin',
        'password': 'WrongPassword123'
    })
    assert response.status_code == 401
    data = response.get_json()
    assert data['success'] is False

def test_login_required_routing(client):
    """Test redirect on login-restricted dashboard view."""
    response = client.get('/dashboard')
    # Unauthenticated request redirects to /login
    assert response.status_code == 302
    assert '/login' in response.headers['Location']
