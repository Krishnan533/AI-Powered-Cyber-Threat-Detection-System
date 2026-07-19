import pytest
from flask import g
from backend.app import create_app
from backend.extensions import db
from backend.models.user import User
from backend.utils.jwt_helper import generate_jwt_token, decode_jwt_token

@pytest.fixture
def app():
    # Force testing configuration
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        # Seed user
        admin = User(username='jwtadmin', role='Admin')
        admin.set_password('AdminSecPass123!')
        db.session.add(admin)
        db.session.commit()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_jwt_token_generation_and_decoding(app):
    """Test generating a JWT token and decoding it successfully."""
    with app.app_context():
        user = User.query.filter_by(username='jwtadmin').first()
        token = generate_jwt_token(user.id, user.username, user.role)
        assert token is not None
        
        # Decode and verify payload
        payload = decode_jwt_token(token)
        assert payload is not None
        assert payload['user_id'] == user.id
        assert payload['username'] == 'jwtadmin'
        assert payload['role'] == 'Admin'

def test_jwt_invalid_token():
    """Test decoding an invalid token returns None."""
    payload = decode_jwt_token("invalid.token.value")
    assert payload is None

def test_jwt_bearer_authentication_api(app, client):
    """Test accessing a protected API endpoint using JWT Bearer authentication."""
    with app.app_context():
        user = User.query.filter_by(username='jwtadmin').first()
        token = generate_jwt_token(user.id, user.username, user.role)
    
    # Attempt to access blocked-ips API with JWT (should succeed with 200)
    response = client.get('/api/blocked-ips', headers={
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'blocked_ips' in data

def test_jwt_bearer_authentication_api_invalid_token(client):
    """Test accessing protected API with invalid token returns 401."""
    response = client.get('/api/blocked-ips', headers={
        'Authorization': 'Bearer invalid.token'
    })
    # Since it lacks a valid session OR valid JWT, it should be unauthorized (401)
    assert response.status_code == 401
