from datetime import datetime
from src.models.user import db


class HnCategory(db.Model):
    __tablename__ = 'hn_categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.String(255))
    is_system = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    apps = db.relationship('HnApp', backref='category', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_system': self.is_system,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class HnApp(db.Model):
    __tablename__ = 'hn_apps'

    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('hn_categories.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(120))
    is_system = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    rules = db.relationship('HnRule', backref='app', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'category_id': self.category_id,
            'name': self.name,
            'slug': self.slug,
            'is_system': self.is_system,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class HnRule(db.Model):
    __tablename__ = 'hn_rules'

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey('hn_apps.id'), nullable=False)
    type = db.Column(db.String(16), nullable=False)  # domain|ip|cidr|sni|regex
    value = db.Column(db.String(255), nullable=False)
    source = db.Column(db.String(32), default='manual')  # manual|auto|ndpi
    confidence = db.Column(db.Float, default=1.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'app_id': self.app_id,
            'type': self.type,
            'value': self.value,
            'source': self.source,
            'confidence': self.confidence,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


def bootstrap_defaults():
    """Ensure default 'Uncategorized' category and 'Unknown' app exist."""
    print('bootstrap_defaults()')
    unc = HnCategory.query.filter_by(name='Uncategorized').first()
    if not unc:
        unc = HnCategory(name='Uncategorized', description='Default category', is_system=True)
        db.session.add(unc)
        db.session.commit()
    unk = HnApp.query.filter_by(name='Unknown').first()
    if not unk:
        unk = HnApp(category_id=unc.id, name='Unknown', slug='unknown', is_system=True)
        db.session.add(unk)
        db.session.commit()
    return unc, unk


