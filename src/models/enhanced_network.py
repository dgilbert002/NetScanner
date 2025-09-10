from src.models.user import db
from datetime import datetime
import json

class User(db.Model):
    """Model for user management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')  # admin, user, guest
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # User preferences
    time_zone = db.Column(db.String(50), default='UTC')
    notification_preferences = db.Column(db.Text)  # JSON string
    
    # Relationships
    devices = db.relationship('Device', backref='assigned_user', lazy=True)
    user_sessions = db.relationship('UserSession', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active,
            'time_zone': self.time_zone,
            'device_count': len(self.devices),
            'notification_preferences': json.loads(self.notification_preferences) if self.notification_preferences else {}
        }

class Device(db.Model):
    """Enhanced model for network devices with user assignment"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))  # Support IPv6
    hostname = db.Column(db.String(255))
    vendor = db.Column(db.String(255))
    device_type = db.Column(db.String(50))  # phone, laptop, iot, etc.
    operating_system = db.Column(db.String(100))
    device_name = db.Column(db.String(100))  # User-friendly name
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # User assignment
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Device metadata
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    
    # Relationships
    traffic_sessions_src = db.relationship('TrafficSession', foreign_keys='TrafficSession.src_mac', backref='source_device')
    traffic_sessions_dst = db.relationship('TrafficSession', foreign_keys='TrafficSession.dst_mac', backref='destination_device')
    website_visits = db.relationship('WebsiteVisit', backref='device')
    
    def to_dict(self):
        return {
            'id': self.id,
            'mac_address': self.mac_address,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'operating_system': self.operating_system,
            'device_name': self.device_name,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_active': self.is_active,
            'user_id': self.user_id,
            'assigned_user': self.assigned_user.username if self.assigned_user else None,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'serial_number': self.serial_number
        }

class TrafficSession(db.Model):
    """Enhanced model for network traffic sessions"""
    __tablename__ = 'traffic_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    src_mac = db.Column(db.String(17), db.ForeignKey('devices.mac_address'))
    dst_mac = db.Column(db.String(17), db.ForeignKey('devices.mac_address'))
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))  # TCP, UDP, ICMP, etc.
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    packet_count = db.Column(db.Integer, default=0)
    
    # Enhanced fields
    application = db.Column(db.String(100))  # Identified application
    application_category = db.Column(db.String(50))
    classification_confidence = db.Column(db.Float)
    is_encrypted = db.Column(db.Boolean, default=False)
    flow_duration = db.Column(db.Integer)  # in seconds
    
    def to_dict(self):
        return {
            'id': self.id,
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packet_count': self.packet_count,
            'application': self.application,
            'application_category': self.application_category,
            'classification_confidence': self.classification_confidence,
            'is_encrypted': self.is_encrypted,
            'flow_duration': self.flow_duration
        }

class WebsiteVisit(db.Model):
    """Enhanced model for website visits with content analysis"""
    __tablename__ = 'website_visits'
    
    id = db.Column(db.Integer, primary_key=True)
    device_mac = db.Column(db.String(17), db.ForeignKey('devices.mac_address'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    url = db.Column(db.Text)
    title = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_transferred = db.Column(db.Integer, default=0)
    response_code = db.Column(db.Integer)
    method = db.Column(db.String(10))  # GET, POST, etc.
    duration = db.Column(db.Integer)  # Time spent on page in seconds
    
    # Enhanced fields for content analysis
    category = db.Column(db.String(100))  # from Klazify API
    subcategory = db.Column(db.String(100))
    content_type = db.Column(db.String(50))  # text/html, application/json, etc.
    user_agent = db.Column(db.String(500))
    referrer = db.Column(db.String(500))
    
    # Relationships
    content_analysis = db.relationship('ContentAnalysis', backref='website_visit', uselist=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_mac': self.device_mac,
            'domain': self.domain,
            'url': self.url,
            'title': self.title,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'bytes_transferred': self.bytes_transferred,
            'response_code': self.response_code,
            'method': self.method,
            'duration': self.duration,
            'category': self.category,
            'subcategory': self.subcategory,
            'content_type': self.content_type,
            'user_agent': self.user_agent,
            'referrer': self.referrer
        }

class ContentAnalysis(db.Model):
    """Model for detailed content analysis of website visits"""
    __tablename__ = 'content_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    website_visit_id = db.Column(db.Integer, db.ForeignKey('website_visits.id'), nullable=False)
    content_summary = db.Column(db.Text)
    keywords = db.Column(db.Text)  # JSON string of extracted keywords
    meta_description = db.Column(db.Text)
    images_count = db.Column(db.Integer, default=0)
    links_count = db.Column(db.Integer, default=0)
    forms_count = db.Column(db.Integer, default=0)
    scripts_count = db.Column(db.Integer, default=0)
    language = db.Column(db.String(10))
    sentiment_score = db.Column(db.Float)  # -1 to 1
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'website_visit_id': self.website_visit_id,
            'content_summary': self.content_summary,
            'keywords': json.loads(self.keywords) if self.keywords else [],
            'meta_description': self.meta_description,
            'images_count': self.images_count,
            'links_count': self.links_count,
            'forms_count': self.forms_count,
            'scripts_count': self.scripts_count,
            'language': self.language,
            'sentiment_score': self.sentiment_score,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class UserSession(db.Model):
    """Model for tracking user activity sessions"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_mac = db.Column(db.String(17), db.ForeignKey('devices.mac_address'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    total_bytes = db.Column(db.BigInteger, default=0)
    websites_visited = db.Column(db.Integer, default=0)
    applications_used = db.Column(db.Text)  # JSON string
    session_duration = db.Column(db.Integer)  # in seconds
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'device_mac': self.device_mac,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'total_bytes': self.total_bytes,
            'websites_visited': self.websites_visited,
            'applications_used': json.loads(self.applications_used) if self.applications_used else [],
            'session_duration': self.session_duration
        }

class EnrichedData(db.Model):
    """Enhanced model for enriched IP data"""
    __tablename__ = 'enriched_data'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    hostname = db.Column(db.String(255))
    country = db.Column(db.String(100))
    country_code = db.Column(db.String(2))
    city = db.Column(db.String(100))
    region = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    isp = db.Column(db.String(255))
    organization = db.Column(db.String(255))
    asn = db.Column(db.Integer)
    is_vpn = db.Column(db.Boolean, default=False)
    is_proxy = db.Column(db.Boolean, default=False)
    is_tor = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20))  # low, medium, high
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'country': self.country,
            'country_code': self.country_code,
            'city': self.city,
            'region': self.region,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'isp': self.isp,
            'organization': self.organization,
            'asn': self.asn,
            'is_vpn': self.is_vpn,
            'is_proxy': self.is_proxy,
            'is_tor': self.is_tor,
            'threat_level': self.threat_level,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class NetworkStats(db.Model):
    """Enhanced model for network statistics"""
    __tablename__ = 'network_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_devices = db.Column(db.Integer, default=0)
    active_devices = db.Column(db.Integer, default=0)
    total_users = db.Column(db.Integer, default=0)
    active_users = db.Column(db.Integer, default=0)
    total_traffic_bytes = db.Column(db.BigInteger, default=0)
    packets_per_second = db.Column(db.Float, default=0.0)
    top_protocols = db.Column(db.Text)  # JSON string
    top_domains = db.Column(db.Text)    # JSON string
    top_applications = db.Column(db.Text)  # JSON string
    top_categories = db.Column(db.Text)  # JSON string
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'total_devices': self.total_devices,
            'active_devices': self.active_devices,
            'total_users': self.total_users,
            'active_users': self.active_users,
            'total_traffic_bytes': self.total_traffic_bytes,
            'packets_per_second': self.packets_per_second,
            'top_protocols': json.loads(self.top_protocols) if self.top_protocols else {},
            'top_domains': json.loads(self.top_domains) if self.top_domains else {},
            'top_applications': json.loads(self.top_applications) if self.top_applications else {},
            'top_categories': json.loads(self.top_categories) if self.top_categories else {}
        }

