from src.models.user import db
from datetime import datetime
import json

class Device(db.Model):
    """Model for network devices"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))  # Support IPv6
    hostname = db.Column(db.String(255))
    vendor = db.Column(db.String(255))
    device_type = db.Column(db.String(50))  # phone, laptop, iot, etc.
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
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
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_active': self.is_active
        }

class TrafficSession(db.Model):
    """Model for network traffic sessions"""
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
            'packet_count': self.packet_count
        }

class EnrichedData(db.Model):
    """Model for enriched IP data"""
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

class WebsiteVisit(db.Model):
    """Model for website visits"""
    __tablename__ = 'website_visits'
    
    id = db.Column(db.Integer, primary_key=True)
    device_mac = db.Column(db.String(17), db.ForeignKey('devices.mac_address'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    url = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_transferred = db.Column(db.Integer, default=0)
    response_code = db.Column(db.Integer)
    method = db.Column(db.String(10))  # GET, POST, etc.
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_mac': self.device_mac,
            'domain': self.domain,
            'url': self.url,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'bytes_transferred': self.bytes_transferred,
            'response_code': self.response_code,
            'method': self.method
        }

class NetworkStats(db.Model):
    """Model for network statistics"""
    __tablename__ = 'network_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_devices = db.Column(db.Integer, default=0)
    active_devices = db.Column(db.Integer, default=0)
    total_traffic_bytes = db.Column(db.BigInteger, default=0)
    packets_per_second = db.Column(db.Float, default=0.0)
    top_protocols = db.Column(db.Text)  # JSON string
    top_domains = db.Column(db.Text)    # JSON string
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'total_devices': self.total_devices,
            'active_devices': self.active_devices,
            'total_traffic_bytes': self.total_traffic_bytes,
            'packets_per_second': self.packets_per_second,
            'top_protocols': json.loads(self.top_protocols) if self.top_protocols else {},
            'top_domains': json.loads(self.top_domains) if self.top_domains else {}
        }

