import pytest
from backend.app import create_app
from backend.extensions import db
from backend.models.user import User
from backend.models.blocked_ip import BlockedIP

@pytest.fixture
def app():
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        # Seed test profiles
        admin = User(username='admin', role='Admin')
        admin.set_password('AdminPass123!')
        
        analyst = User(username='analyst', role='Analyst')
        analyst.set_password('AnalystPass456!')
        
        viewer = User(username='viewer', role='Viewer')
        viewer.set_password('ViewerPass789!')
        
        db.session.add_all([admin, analyst, viewer])
        
        # Seed a blocked IP
        block = BlockedIP(ip_address='10.20.30.40', reason='Test block', blocked_by='admin')
        db.session.add(block)
        
        db.session.commit()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_blocked_ips_query(client):
    """Test retrieving blocked IP lists. Authenticated user check."""
    # Login first
    client.post('/api/auth/login', json={'username': 'viewer', 'password': 'ViewerPass789!'})
    
    response = client.get('/api/blocked-ips')
    assert response.status_code == 200
    data = response.get_json()
    assert data['total'] == 1
    assert data['blocked_ips'][0]['ip_address'] == '10.20.30.40'

def test_manual_block_authorization(client):
    """Verify that Analyst/Admin can block, but Viewer is unauthorized."""
    # Test Viewer block block
    client.post('/api/auth/login', json={'username': 'viewer', 'password': 'ViewerPass789!'})
    response = client.post('/api/blocked-ips', json={'ip_address': '1.2.3.4', 'reason': 'Viewer manual block'})
    assert response.status_code == 403 # Access forbidden
    
    # Test Analyst block authorization
    client.post('/api/auth/login', json={'username': 'analyst', 'password': 'AnalystPass456!'})
    response = client.post('/api/blocked-ips', json={'ip_address': '1.2.3.4', 'reason': 'Analyst manual block', 'duration_hours': 2})
    assert response.status_code == 201 # Created
    
def test_unblock_admin_restriction(client):
    """Verify that only Admin can unblock IPs."""
    # Add block
    client.post('/api/auth/login', json={'username': 'analyst', 'password': 'AnalystPass456!'})
    client.post('/api/blocked-ips', json={'ip_address': '5.6.7.8', 'reason': 'To unblock'})
    
    # Get ID
    resp = client.get('/api/blocked-ips')
    block_id = resp.get_json()['blocked_ips'][0]['id']
    
    # Analyst attempt delete
    response = client.delete(f'/api/blocked-ips/{block_id}')
    assert response.status_code == 403
    
    # Admin attempt delete
    client.post('/api/auth/login', json={'username': 'admin', 'password': 'AdminPass123!'})
    response = client.delete(f'/api/blocked-ips/{block_id}')
    assert response.status_code == 200
