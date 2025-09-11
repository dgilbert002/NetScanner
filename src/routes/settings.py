from flask import Blueprint, jsonify, request
from src.models.user import db
from src.models.settings import AppSettings

settings_bp = Blueprint('settings_bp', __name__, url_prefix='/api/settings')


@settings_bp.route('', methods=['GET'])
def get_settings():
    s = AppSettings.get_or_create_defaults()
    return jsonify(s.to_dict())


@settings_bp.route('', methods=['POST'])
def update_settings():
    data = request.get_json(force=True)
    s = AppSettings.get_or_create_defaults()
    if 'session_idle_seconds' in data:
        try:
            s.session_idle_seconds = max(10, int(data['session_idle_seconds']))
        except Exception:
            pass
    if 'ndpi_mode' in data:
        mode = str(data['ndpi_mode']).lower()
        if mode in ('off', 'fallback', 'on'):
            s.ndpi_mode = mode
    db.session.commit()
    return jsonify(s.to_dict())


