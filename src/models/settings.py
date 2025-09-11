from datetime import datetime
from src.models.user import db


class AppSettings(db.Model):
    __tablename__ = 'app_settings'

    id = db.Column(db.Integer, primary_key=True, default=1)
    # Sessionizer closes a session after this many seconds of inactivity
    session_idle_seconds = db.Column(db.Integer, nullable=False, default=90)
    # nDPI usage mode: 'off' | 'fallback' | 'on'
    ndpi_mode = db.Column(db.String(16), nullable=False, default='fallback')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            'session_idle_seconds': int(self.session_idle_seconds or 90),
            'ndpi_mode': self.ndpi_mode or 'fallback',
        }

    @staticmethod
    def get_or_create_defaults() -> "AppSettings":
        settings = AppSettings.query.get(1)
        if settings is None:
            settings = AppSettings(id=1, session_idle_seconds=90, ndpi_mode='fallback')
            db.session.add(settings)
            db.session.commit()
        return settings


