import pytest
from backend.app import create_app
from backend.extensions import db
from backend.models.user import User
from backend.models.system_setting import SystemSetting

@pytest.fixture
def app():
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        # Seed default test users
        admin = User(username='admin', role='Admin')
        admin.set_password('AdminPass123!')
        
        analyst = User(username='analyst', role='Analyst')
        analyst.set_password('AnalystPass456!')
        
        viewer = User(username='viewer', role='Viewer')
        viewer.set_password('ViewerPass789!')
        
        db.session.add_all([admin, analyst, viewer])
        db.session.commit()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_admin_user_management_crud(client):
    """Test full CRUD operations on users under Admin role."""
    # Login as admin
    client.post('/api/auth/login', json={'username': 'admin', 'password': 'AdminPass123!'})
    
    # 1. Read users list
    response = client.get('/api/users')
    assert response.status_code == 200
    users = response.get_json()
    assert len(users) == 3
    
    # 2. Create user
    response = client.post('/api/users', json={
        'username': 'newuser',
        'password': 'NewUserPass123!',
        'role': 'Analyst'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['success'] is True
    assert data['user']['username'] == 'newuser'
    
    new_user_id = data['user']['id']
    
    # 3. Update user role
    response = client.put(f'/api/users/{new_user_id}', json={
        'role': 'Viewer'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['user']['role'] == 'Viewer'
    
    # 4. Delete user
    response = client.delete(f'/api/users/{new_user_id}')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True

def test_analyst_unauthorized_user_management(client):
    """Verify Analyst role is blocked from admin User Management routes."""
    client.post('/api/auth/login', json={'username': 'analyst', 'password': 'AnalystPass456!'})
    
    # Attempt get users
    response = client.get('/api/users')
    assert response.status_code == 403
    
    # Attempt create user
    response = client.post('/api/users', json={
        'username': 'attacker',
        'password': 'AttackerPass123!',
        'role': 'Admin'
    })
    assert response.status_code == 403

def test_settings_endpoints(client):
    """Test get and update system settings."""
    # Login as Analyst (who is authorized to view/edit settings)
    client.post('/api/auth/login', json={'username': 'analyst', 'password': 'AnalystPass456!'})
    
    # Get settings
    response = client.get('/api/settings')
    assert response.status_code == 200
    settings = response.get_json()
    assert 'DDOS_THRESHOLD' in settings
    
    # Update setting
    response = client.post('/api/settings', json={
        'DDOS_THRESHOLD': '150',
        'PORTSCAN_THRESHOLD': '20'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    
    # Check that settings updated in DB
    response = client.get('/api/settings')
    settings = response.get_json()
    assert settings['DDOS_THRESHOLD'] == '150'
    assert settings['PORTSCAN_THRESHOLD'] == '20'

def test_viewer_settings_blocked(client):
    """Verify Viewer role is blocked from updating settings."""
    client.post('/api/auth/login', json={'username': 'viewer', 'password': 'ViewerPass789!'})
    
    # Attempt get settings
    response = client.get('/api/settings')
    assert response.status_code == 403
    
    # Attempt update settings
    response = client.post('/api/settings', json={
        'DDOS_THRESHOLD': '200'
    })
    assert response.status_code == 403
