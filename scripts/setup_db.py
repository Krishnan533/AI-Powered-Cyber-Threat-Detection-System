import os
import sys
from dotenv import load_dotenv

# Ensure backend directory is in path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)

load_dotenv()

from backend.app import create_app
from backend.extensions import db
from backend.models.user import User
from backend.models.system_log import SystemLog
from backend.utils.helpers import log_system

def setup_database():
    """Initializes schema and runs user seeds if the user table is empty."""
    print("Initializing Database tables...")
    app = create_app()
    
    with app.app_context():
        try:
            # Create all tables (reads models metadata)
            db.create_all()
            print("SQLAlchemy: Schema tables initialized successfully.")
            
            # Check if users already seeded to prevent duplication
            if User.query.count() == 0:
                print("Seeding administrative credentials...")
                
                # Admin account
                admin = User(username='admin', role='Admin')
                admin.set_password('AdminPass123!')
                db.session.add(admin)
                
                # Analyst account
                analyst = User(username='analyst', role='Analyst')
                analyst.set_password('AnalystPass456!')
                db.session.add(analyst)
                
                # Viewer account
                viewer = User(username='viewer', role='Viewer')
                viewer.set_password('ViewerPass789!')
                db.session.add(viewer)
                
                db.session.commit()
                print("Default credentials seeded successfully:")
                print("  - admin / AdminPass123! [Admin]")
                print("  - analyst / AnalystPass456! [Analyst]")
                print("  - viewer / ViewerPass789! [Viewer]")
                
                # Log system diagnostic
                log_system('INFO', "System Database seeded with initial credentials.")
            else:
                print("Database already seeded. Skipping credentials load.")
                
        except Exception as e:
            print(f"Error initializing database: {e}")
            sys.exit(1)

if __name__ == '__main__':
    setup_database()
