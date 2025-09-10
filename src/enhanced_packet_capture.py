"""
Enhanced Packet Capture Engine
Integrates traffic analysis with database storage and real-time processing
"""

import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
import requests
from urllib.parse import urlparse

import os

# Check if enhanced features should be enabled
ENABLE_ENHANCED = os.getenv('ENABLE_ENHANCED', '0').lower() in ('1', 'true', 'yes')

if ENABLE_ENHANCED:
    from src.models.enhanced_network import Device, TrafficSession, WebsiteVisit, ContentAnalysis, EnrichedData, db
else:
    # Use base models only
    from src.models.network import Device, TrafficSession, WebsiteVisit, EnrichedData
    from src.models.user import db
    # Create dummy classes for enhanced features
    class ContentAnalysis:
        pass
from src.traffic_analyzer import RealTimeAnalyzer, ContentAnalyzer, NetworkEnricher

class EnhancedPacketCapture:
    """Enhanced packet capture with real-time analysis and database integration"""
    
    def __init__(self, interface='eth0', app_context=None, config=None):
        self.interface = interface
        self.app_context = app_context
        self.config = config or {}
        
        # Initialize analyzers
        self.analyzer = RealTimeAnalyzer(
            interface=interface,
            klazify_api_key=self.config.get('klazify_api_key'),
            ipinfo_token=self.config.get('ipinfo_token')
        )
        
        self.content_analyzer = ContentAnalyzer(self.config.get('klazify_api_key'))
        self.enricher = NetworkEnricher(self.config.get('ipinfo_token'))
        
        # State management
        self.is_capturing = False
        self.capture_thread = None
        self.processing_thread = None
        
        # Data buffers
        self.packet_buffer = deque(maxlen=10000)
        self.device_tracker = {}
        self.session_tracker = {}
        self.http_sessions = {}
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'devices_discovered': 0,
            'sessions_created': 0,
            'websites_visited': 0,
            'start_time': None
        }
        
        # Setup analysis callback
        self.analyzer.add_analysis_callback(self._handle_analysis_result)
    
    def start_capture(self):
        """Start packet capture and analysis"""
        if self.is_capturing:
            return {"status": "already_running"}
        
        self.is_capturing = True
        self.stats['start_time'] = datetime.utcnow()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        # Start analyzer
        self.analyzer.start_analysis()
        
        print(f"Started enhanced packet capture on {self.interface}")
        return {"status": "started", "interface": self.interface}
    
    def stop_capture(self):
        """Stop packet capture and analysis"""
        if not self.is_capturing:
            return {"status": "not_running"}
        
        self.is_capturing = False
        
        # Stop analyzer
        self.analyzer.stop_analysis()
        
        # Wait for processing thread to finish
        if self.processing_thread:
            self.processing_thread.join(timeout=10)
        
        print("Stopped enhanced packet capture")
        return {"status": "stopped", "stats": self.stats}
    
    def get_status(self):
        """Get current capture status and statistics"""
        return {
            "is_capturing": self.is_capturing,
            "interface": self.interface,
            "stats": self.stats,
            "buffer_size": len(self.packet_buffer),
            "active_devices": len(self.device_tracker),
            "active_sessions": len(self.session_tracker)
        }
    
    def _handle_analysis_result(self, classification):
        """Handle analysis result from traffic analyzer"""
        try:
            self.packet_buffer.append(classification)
            self.stats['packets_captured'] += 1
        except Exception as e:
            print(f"Error handling analysis result: {e}")
    
    def _processing_loop(self):
        """Main processing loop for analyzed packets"""
        while self.is_capturing:
            try:
                # Process buffered packets
                while self.packet_buffer and self.is_capturing:
                    classification = self.packet_buffer.popleft()
                    self._process_classification(classification)
                    self.stats['packets_processed'] += 1
                
                # Brief sleep to prevent CPU spinning
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Error in processing loop: {e}")
                time.sleep(1)
    
    def _process_classification(self, classification):
        """Process a single packet classification"""
        try:
            with self.app_context.app_context():
                # Update device information
                self._update_device_info(classification)
                
                # Create or update traffic session
                self._update_traffic_session(classification)
                
                # Handle HTTP traffic
                if classification.get('application') == 'HTTP':
                    self._handle_http_traffic(classification)
                
                # Enrich IP data
                if classification.get('dst_enrichment'):
                    self._store_enriched_data(classification['dst_enrichment'])
                
        except Exception as e:
            print(f"Error processing classification: {e}")
    
    def _update_device_info(self, classification):
        """Update device information in database"""
        try:
            src_ip = classification.get('src_ip')
            if not src_ip:
                return
            
            # Generate MAC address (in real implementation, extract from packet)
            mac_address = self._generate_mac_from_ip(src_ip)
            
            # Check if device exists
            device = Device.query.filter_by(mac_address=mac_address).first()
            
            if not device:
                # Create new device
                device = Device(
                    mac_address=mac_address,
                    ip_address=src_ip,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    is_active=True
                )
                
                # Try to determine device type and vendor
                if classification.get('user_agent'):
                    device_info = self._analyze_user_agent(classification['user_agent'])
                    device.device_type = device_info.get('device_type')
                    device.operating_system = device_info.get('os')
                
                db.session.add(device)
                self.stats['devices_discovered'] += 1
            else:
                # Update existing device
                device.last_seen = datetime.utcnow()
                device.is_active = True
                
                # Update IP if changed
                if device.ip_address != src_ip:
                    device.ip_address = src_ip
            
            # Update device tracker
            self.device_tracker[mac_address] = {
                'device_id': device.id,
                'last_seen': datetime.utcnow(),
                'ip_address': src_ip
            }
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error updating device info: {e}")
            db.session.rollback()
    
    def _update_traffic_session(self, classification):
        """Create or update traffic session"""
        try:
            src_ip = classification.get('src_ip')
            dst_ip = classification.get('dst_ip')
            protocol = classification.get('protocol')
            src_port = classification.get('src_port')
            dst_port = classification.get('dst_port')
            
            if not all([src_ip, dst_ip, protocol]):
                return
            
            # Generate session key
            session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            
            # Get source device MAC
            src_mac = self._generate_mac_from_ip(src_ip)
            
            # Check for existing session
            if session_key in self.session_tracker:
                session_info = self.session_tracker[session_key]
                session = TrafficSession.query.get(session_info['session_id'])
                
                if session:
                    # Update existing session
                    session.bytes_sent += classification.get('payload_size', 0)
                    session.packet_count += 1
                    session.end_time = datetime.utcnow()
                    
                    # Update application if detected
                    if classification.get('application') and not session.application:
                        session.application = classification['application']
                        session.classification_confidence = classification.get('confidence', 0.0)
                    
                    # Update encryption status
                    if classification.get('is_encrypted'):
                        session.is_encrypted = True
            else:
                # Create new session
                session = TrafficSession(
                    src_mac=src_mac,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=datetime.utcnow(),
                    bytes_sent=classification.get('payload_size', 0),
                    packet_count=1,
                    application=classification.get('application'),
                    classification_confidence=classification.get('confidence', 0.0),
                    is_encrypted=classification.get('is_encrypted', False)
                )
                
                db.session.add(session)
                db.session.flush()  # Get the ID
                
                # Track session
                self.session_tracker[session_key] = {
                    'session_id': session.id,
                    'start_time': datetime.utcnow()
                }
                
                self.stats['sessions_created'] += 1
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error updating traffic session: {e}")
            db.session.rollback()
    
    def _handle_http_traffic(self, classification):
        """Handle HTTP traffic and website visits"""
        try:
            domain = classification.get('domain')
            url = classification.get('url')
            src_ip = classification.get('src_ip')
            
            if not all([domain, src_ip]):
                return
            
            # Get device MAC
            device_mac = self._generate_mac_from_ip(src_ip)
            
            # Create website visit record
            full_url = f"http://{domain}{url}" if url else f"http://{domain}"
            
            visit = WebsiteVisit(
                device_mac=device_mac,
                domain=domain,
                url=full_url,
                timestamp=datetime.utcnow(),
                bytes_transferred=classification.get('payload_size', 0),
                method=classification.get('http_method', 'GET'),
                user_agent=classification.get('user_agent')
            )
            
            # Add content analysis if available
            if classification.get('content_analysis'):
                content_data = classification['content_analysis']
                visit.category = content_data.get('category')
                visit.subcategory = content_data.get('subcategory')
                visit.title = content_data.get('title')
            
            db.session.add(visit)
            db.session.flush()  # Get the ID
            
            # Create detailed content analysis if available
            if classification.get('content_analysis'):
                content_analysis = ContentAnalysis(
                    website_visit_id=visit.id,
                    content_summary=content_data.get('content_summary'),
                    keywords=json.dumps(content_data.get('keywords', [])),
                    meta_description=content_data.get('meta_description'),
                    images_count=content_data.get('images_count', 0),
                    links_count=content_data.get('links_count', 0),
                    forms_count=content_data.get('forms_count', 0),
                    scripts_count=content_data.get('scripts_count', 0),
                    language=content_data.get('language'),
                    sentiment_score=content_data.get('sentiment_score', 0.0)
                )
                
                db.session.add(content_analysis)
            
            self.stats['websites_visited'] += 1
            db.session.commit()
            
        except Exception as e:
            print(f"Error handling HTTP traffic: {e}")
            db.session.rollback()
    
    def _store_enriched_data(self, enrichment):
        """Store IP enrichment data"""
        try:
            ip_address = enrichment.get('ip_address')
            if not ip_address:
                return
            
            # Check if enrichment already exists
            existing = EnrichedData.query.filter_by(ip_address=ip_address).first()
            
            if existing:
                # Update existing record
                for key, value in enrichment.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
                existing.updated_at = datetime.utcnow()
            else:
                # Create new enrichment record
                enriched_data = EnrichedData(**enrichment)
                db.session.add(enriched_data)
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error storing enriched data: {e}")
            db.session.rollback()
    
    def _generate_mac_from_ip(self, ip_address):
        """Generate a pseudo-MAC address from IP (for demo purposes)"""
        # In real implementation, extract MAC from ARP table or packet headers
        import hashlib
        hash_obj = hashlib.md5(ip_address.encode())
        hash_hex = hash_obj.hexdigest()
        mac = ':'.join([hash_hex[i:i+2] for i in range(0, 12, 2)])
        return mac
    
    def _analyze_user_agent(self, user_agent):
        """Analyze user agent string to determine device type and OS"""
        user_agent_lower = user_agent.lower()
        
        device_info = {
            'device_type': 'unknown',
            'os': 'unknown'
        }
        
        # Device type detection
        if any(mobile in user_agent_lower for mobile in ['mobile', 'android', 'iphone', 'ipad']):
            if 'ipad' in user_agent_lower:
                device_info['device_type'] = 'tablet'
            else:
                device_info['device_type'] = 'phone'
        elif any(desktop in user_agent_lower for desktop in ['windows', 'macintosh', 'linux']):
            device_info['device_type'] = 'laptop'
        
        # OS detection
        if 'windows' in user_agent_lower:
            device_info['os'] = 'Windows'
        elif 'macintosh' in user_agent_lower or 'mac os' in user_agent_lower:
            device_info['os'] = 'macOS'
        elif 'linux' in user_agent_lower:
            device_info['os'] = 'Linux'
        elif 'android' in user_agent_lower:
            device_info['os'] = 'Android'
        elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
            device_info['os'] = 'iOS'
        
        return device_info
    
    def cleanup_old_sessions(self, hours=24):
        """Clean up old session tracking data"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Clean up session tracker
            expired_sessions = [
                key for key, info in self.session_tracker.items()
                if info['start_time'] < cutoff_time
            ]
            
            for key in expired_sessions:
                del self.session_tracker[key]
            
            # Clean up device tracker
            expired_devices = [
                key for key, info in self.device_tracker.items()
                if info['last_seen'] < cutoff_time
            ]
            
            for key in expired_devices:
                del self.device_tracker[key]
            
            print(f"Cleaned up {len(expired_sessions)} sessions and {len(expired_devices)} devices")
            
        except Exception as e:
            print(f"Error cleaning up old sessions: {e}")
    
    def generate_demo_data(self):
        """Generate demo data for testing"""
        try:
            with self.app_context.app_context():
                # Create demo devices
                demo_devices = [
                    {
                        'mac_address': '00:11:22:33:44:55',
                        'ip_address': '192.168.1.100',
                        'device_name': 'John\'s Laptop',
                        'device_type': 'laptop',
                        'operating_system': 'Windows 11',
                        'vendor': 'Dell Inc.'
                    },
                    {
                        'mac_address': '00:11:22:33:44:56',
                        'ip_address': '192.168.1.101',
                        'device_name': 'Jane\'s iPhone',
                        'device_type': 'phone',
                        'operating_system': 'iOS 17',
                        'vendor': 'Apple Inc.'
                    },
                    {
                        'mac_address': '00:11:22:33:44:57',
                        'ip_address': '192.168.1.102',
                        'device_name': 'Smart TV',
                        'device_type': 'tv',
                        'operating_system': 'Android TV',
                        'vendor': 'Samsung'
                    }
                ]
                
                for device_data in demo_devices:
                    device = Device.query.filter_by(mac_address=device_data['mac_address']).first()
                    if not device:
                        device = Device(**device_data)
                        device.first_seen = datetime.utcnow() - timedelta(days=7)
                        device.last_seen = datetime.utcnow()
                        db.session.add(device)
                
                # Create demo website visits
                demo_visits = [
                    {
                        'device_mac': '00:11:22:33:44:55',
                        'domain': 'google.com',
                        'url': 'https://google.com/search?q=python',
                        'title': 'python - Google Search',
                        'category': 'Search Engines',
                        'bytes_transferred': 15420
                    },
                    {
                        'device_mac': '00:11:22:33:44:55',
                        'domain': 'github.com',
                        'url': 'https://github.com/python/cpython',
                        'title': 'GitHub - python/cpython',
                        'category': 'Technology',
                        'bytes_transferred': 89340
                    },
                    {
                        'device_mac': '00:11:22:33:44:56',
                        'domain': 'youtube.com',
                        'url': 'https://youtube.com/watch?v=dQw4w9WgXcQ',
                        'title': 'Rick Astley - Never Gonna Give You Up',
                        'category': 'Entertainment',
                        'bytes_transferred': 2450000
                    }
                ]
                
                for visit_data in demo_visits:
                    visit = WebsiteVisit(**visit_data)
                    visit.timestamp = datetime.utcnow() - timedelta(minutes=30)
                    db.session.add(visit)
                
                # Create demo traffic sessions
                demo_sessions = [
                    {
                        'src_mac': '00:11:22:33:44:55',
                        'src_ip': '192.168.1.100',
                        'dst_ip': '8.8.8.8',
                        'protocol': 'UDP',
                        'dst_port': 53,
                        'application': 'DNS',
                        'bytes_sent': 1024,
                        'bytes_received': 2048,
                        'packet_count': 10
                    },
                    {
                        'src_mac': '00:11:22:33:44:56',
                        'src_ip': '192.168.1.101',
                        'dst_ip': '142.250.191.14',
                        'protocol': 'TCP',
                        'dst_port': 443,
                        'application': 'HTTPS',
                        'bytes_sent': 50000,
                        'bytes_received': 150000,
                        'packet_count': 200,
                        'is_encrypted': True
                    }
                ]
                
                for session_data in demo_sessions:
                    session = TrafficSession(**session_data)
                    session.start_time = datetime.utcnow() - timedelta(minutes=15)
                    session.end_time = datetime.utcnow() - timedelta(minutes=10)
                    db.session.add(session)
                
                db.session.commit()
                
                return {
                    'status': 'success',
                    'devices_created': len(demo_devices),
                    'visits_created': len(demo_visits),
                    'sessions_created': len(demo_sessions)
                }
                
        except Exception as e:
            db.session.rollback()
            return {'status': 'error', 'message': str(e)}

