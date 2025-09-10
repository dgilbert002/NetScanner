"""
Device Groups Model for organizing devices
"""

from src.models.user import db
from datetime import datetime
import json

class DeviceGroup(db.Model):
    """Model for device groups"""
    __tablename__ = 'device_groups'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Group settings
    color = db.Column(db.String(7), default='#3498db')  # Hex color for UI
    icon = db.Column(db.String(50), default='folder')   # Icon name for UI
    is_active = db.Column(db.Boolean, default=True)
    
    # Group metadata - renamed from 'metadata' which is reserved in SQLAlchemy
    group_metadata = db.Column(db.Text)  # JSON string for flexible data
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'color': self.color,
            'icon': self.icon,
            'is_active': self.is_active,
            'metadata': json.loads(self.group_metadata) if self.group_metadata else {},
            'device_count': len(self.devices) if hasattr(self, 'devices') else 0
        }

class DeviceGroupMembership(db.Model):
    """Many-to-many relationship between devices and groups"""
    __tablename__ = 'device_group_memberships'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('device_groups.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.String(100))  # Username who added the device
    
    # Create unique constraint to prevent duplicate memberships
    __table_args__ = (
        db.UniqueConstraint('device_id', 'group_id', name='unique_device_group'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'group_id': self.group_id,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'added_by': self.added_by
        }
