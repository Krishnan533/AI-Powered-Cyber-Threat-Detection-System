from flask import request, jsonify, session, current_app
from backend.models.system_setting import SystemSetting
from backend.extensions import db
from backend.utils.helpers import log_audit, log_system

class SettingsController:
    """Handles query and update operations for global system configuration settings (Admin/Analyst role)."""

    @staticmethod
    def get_settings():
        """Fetches all system configuration settings as a key-value dictionary."""
        try:
            settings = SystemSetting.query.all()
            settings_dict = {s.key: s.value for s in settings}
            return jsonify(settings_dict), 200
        except Exception as e:
            log_system('ERROR', f"Failed to get settings: {e}")
            return jsonify({'error': 'Failed to fetch settings configurations.'}), 500

    @staticmethod
    def update_settings():
        """Updates system configuration settings in the database and current_app.config."""
        try:
            data = request.get_json() or {}
            username = session.get('username', 'System')
            user_id = session.get('user_id')

            for key, value in data.items():
                setting = SystemSetting.query.filter_by(key=key).first()
                if not setting:
                    setting = SystemSetting(key=key, value=str(value))
                    db.session.add(setting)
                else:
                    setting.value = str(value)
                
                # Dynamic update of Flask config
                if key in ('MAIL_PORT', 'DDOS_THRESHOLD', 'PORTSCAN_THRESHOLD', 'BRUTEFORCE_THRESHOLD'):
                    try:
                        current_app.config[key] = int(value)
                    except ValueError:
                        current_app.config[key] = value
                elif key in ('MAIL_USE_TLS', 'MAIL_USE_SSL', 'SNIFFER_SIMULATION', 'SEND_EMAIL_NOTIFICATIONS'):
                    current_app.config[key] = str(value).lower() in ('true', '1', 't')
                elif key == 'SNIFFER_SIMULATION_INTERVAL':
                    try:
                        current_app.config[key] = float(value)
                    except ValueError:
                        current_app.config[key] = 0.5
                else:
                    current_app.config[key] = str(value)

            db.session.commit()

            log_audit(
                action="SYSTEM_SETTINGS_UPDATE",
                user_id=user_id,
                details=f"User {username} updated system settings keys: {', '.join(data.keys())}."
            )
            log_system('INFO', f"System settings updated by {username}: {list(data.keys())}")

            return jsonify({
                'success': True,
                'message': 'System settings updated successfully.'
            }), 200

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"Failed to update settings: {e}")
            return jsonify({'success': False, 'message': f"Failed to save settings: {e}"}), 500
