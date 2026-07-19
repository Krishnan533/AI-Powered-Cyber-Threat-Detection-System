from backend.extensions import db

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'

    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            'key': self.key,
            'value': self.value
        }
