"""
Cross-platform packet capture system for Windows and Raspberry Pi
Integrates all capture methods with full feature support
"""

import platform
import os
import sys
import logging
import subprocess
import threading
import time
import json
import socket
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio

# Import scapy for packet capture
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

# Import database models with conditional enhanced features
ENABLE_ENHANCED = os.getenv('ENABLE_ENHANCED', '0').lower() in ('1', 'true', 'yes')

if ENABLE_ENHANCED:
    try:
        from src.models.enhanced_network import (
            User, Device, TrafficSession, WebsiteVisit, ContentAnalysis,
            EnrichedData, NetworkStats, UserSession, db
        )
    except ImportError:
        # Fallback to base models
        from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
        from src.models.user import User, db
        # Create dummy classes for enhanced features
        class ContentAnalysis:
            pass
        class UserSession:
            pass
else:
    # Use base models only
    from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
    from src.models.user import User, db
    # Create dummy classes for enhanced features
    class ContentAnalysis:
        pass
    class UserSession:
        pass

class CrossPlatformCapture:
    """Cross-platform packet capture that works on Windows and Linux/Raspberry Pi"""
    
    def __init__(self, interface=None, app_context=None):
        self.platform = platform.system()
        self.interface = interface or self._detect_interface()
        self.app_context = app_context
        self.running = False
        self.capture_thread = None
        self.packet_buffer = []
        self.dns_cache = {}  # Cache DNS lookups
        self.app_mappings = self._load_app_mappings()
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'start_time': None,
            'protocols': defaultdict(int),
            'applications': defaultdict(int),
            'devices': {},
            'domains': defaultdict(int),
            'users': {},
            'sessions': []
        }
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initialized cross-platform capture for {self.platform}")
        
    def _detect_interface(self):
        """Detect the best network interface based on platform"""
        if self.platform == "Windows":
            # Windows interface detection
            try:
                if SCAPY_AVAILABLE:
                    from scapy.arch.windows import get_windows_if_list
                    interfaces = get_windows_if_list()
                    # Find WiFi or Ethernet interface
                    for iface in interfaces:
                        name = iface.get('name', '').lower()
                        desc = iface.get('description', '').lower()
                        if 'wi-fi' in name or 'wifi' in name or 'wireless' in desc:
                            return iface.get('guid', iface.get('name'))
                        elif 'ethernet' in name or 'ethernet' in desc:
                            return iface.get('guid', iface.get('name'))
                    # Return first non-loopback interface
                    for iface in interfaces:
                        if 'loopback' not in iface.get('name', '').lower():
                            return iface.get('guid', iface.get('name'))
                # Fallback for Windows
                return "WiFi"
            except:
                return "WiFi"
                
        elif self.platform == "Linux":
            # Linux/Raspberry Pi interface detection
            try:
                # Check common interfaces
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                if 'wlan0' in result.stdout:
                    return 'wlan0'
                elif 'eth0' in result.stdout:
                    return 'eth0'
                elif 'ens' in result.stdout:
                    # Modern systemd naming
                    import re
                    match = re.search(r'(ens\d+)', result.stdout)
                    if match:
                        return match.group(1)
            except:
                pass
            return 'eth0'  # Default for Linux
            
        else:
            return 'en0'  # Default for macOS
            
    def _load_app_mappings(self):
        """Load application domain mappings from config file"""
        mappings_file = 'config/app_domains.json'
        default_mappings = {
            "Google": ["google.com", "googleapis.com", "gstatic.com", "youtube.com", "ytimg.com"],
            "Facebook": ["facebook.com", "fbcdn.net", "fb.com", "messenger.com"],
            "Microsoft": ["microsoft.com", "windows.com", "office.com", "live.com", "azure.com"],
            "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.com"],
            "Amazon": ["amazon.com", "amazonaws.com", "aws.com"],
            "WhatsApp": ["whatsapp.com", "whatsapp.net"],
            "Instagram": ["instagram.com", "cdninstagram.com"],
            "Twitter": ["twitter.com", "twimg.com", "t.co"],
            "LinkedIn": ["linkedin.com", "licdn.com"],
            "GitHub": ["github.com", "githubusercontent.com", "githubassets.com"],
            "Zoom": ["zoom.us", "zoom.com"],
            "Slack": ["slack.com", "slack-edge.com"],
            "Discord": ["discord.com", "discordapp.com", "discord.gg"],
            "Reddit": ["reddit.com", "redditmedia.com", "redditstatic.com"],
            "TikTok": ["tiktok.com", "tiktokcdn.com"],
            "Spotify": ["spotify.com", "spotifycdn.com"],
            "Apple": ["apple.com", "icloud.com", "cdn-apple.com"],
            "CloudFlare": ["cloudflare.com", "cloudflare-dns.com"],
            "Steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"]
        }
        
        # Create config directory if it doesn't exist
        os.makedirs('config', exist_ok=True)
        
        # Load or create mappings file
        if os.path.exists(mappings_file):
            try:
                with open(mappings_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Save default mappings
        with open(mappings_file, 'w') as f:
            json.dump(default_mappings, f, indent=2)
        
        return default_mappings
        
    def _categorize_domain(self, domain):
        """Categorize domain to application"""
        if not domain:
            return "Unknown"
            
        # Check each app's domain patterns
        for app, patterns in self.app_mappings.items():
            for pattern in patterns:
                if pattern in domain:
                    return app
                    
        # If no match, return the primary domain
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-2].capitalize()
        return "Unknown"
        
    def start_capture(self):
        """Start packet capture based on platform"""
        if self.running:
            return False
            
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        
        if SCAPY_AVAILABLE and (self.platform == "Linux" or 
                                (self.platform == "Windows" and self._check_npcap())):
            # Use scapy for real packet capture
            self.capture_thread = threading.Thread(target=self._scapy_capture_loop, daemon=True)
        else:
            # Fallback to netstat monitoring
            self.capture_thread = threading.Thread(target=self._netstat_capture_loop, daemon=True)
            
        self.capture_thread.start()
        self.logger.info(f"Started capture on {self.interface} using {self.platform} method")
        return True
        
    def _check_npcap(self):
        """Check if Npcap is installed on Windows"""
        if self.platform != "Windows":
            return False
            
        try:
            # Check if Npcap service is running
            result = subprocess.run(['sc', 'query', 'npcap'], capture_output=True, text=True)
            return 'RUNNING' in result.stdout
        except:
            return False
            
    def _scapy_capture_loop(self):
        """Capture packets using scapy (works on Linux and Windows with Npcap)"""
        with self.app_context.app_context() if self.app_context else nullcontext():
            try:
                self.logger.info("Starting scapy packet capture")
                sniff(
                    iface=self.interface,
                    prn=self._process_scapy_packet,
                    stop_filter=lambda x: not self.running,
                    store=0
                )
            except Exception as e:
                self.logger.error(f"Scapy capture error: {e}")
                # Fallback to netstat
                self._netstat_capture_loop()
                
    def _process_scapy_packet(self, packet):
        """Process packet captured by scapy"""
        try:
            # Extract basic info
            if IP not in packet:
                return
                
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_size = len(packet)
            
            # Get MAC addresses
            src_mac = packet.src if hasattr(packet, 'src') else 'unknown'
            dst_mac = packet.dst if hasattr(packet, 'dst') else 'unknown'
            
            # Determine protocol name and ports
            src_port = dst_port = 0
            if TCP in packet:
                protocol_name = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol_name = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol_name = 'ICMP'
            else:
                protocol_name = f'IP-{protocol}'
                
            # Extract DNS information
            domain = None
            if DNS in packet and packet[DNS].qd:
                try:
                    domain = packet[DNS].qd.qname.decode().rstrip('.')
                except Exception:
                    try:
                        domain = str(packet[DNS].qd.qname).rstrip('.')
                    except Exception:
                        domain = None
                if domain:
                    self.dns_cache[dst_ip] = domain

            # Map DNS answers (A records) to cache IP -> domain
            if DNS in packet and packet[DNS].an:
                try:
                    rr = packet[DNS].an
                    for _ in range(int(packet[DNS].ancount or 0)):
                        rrname = None
                        try:
                            rrname = rr.rrname.decode().rstrip('.') if isinstance(rr.rrname, (bytes, bytearray)) else str(rr.rrname).rstrip('.')
                        except Exception:
                            rrname = None
                        ip_candidate = rr.rdata
                        # Normalize rdata to string if it's bytes
                        if isinstance(ip_candidate, (bytes, bytearray)):
                            try:
                                ip_candidate = ip_candidate.decode('utf-8', 'ignore')
                            except Exception:
                                ip_candidate = None
                        if isinstance(ip_candidate, str) and ip_candidate.count('.') == 3:
                            # Looks like IPv4
                            if rrname:
                                self.dns_cache[ip_candidate] = rrname
                        rr = rr.payload
                except Exception:
                    pass

            # Extract HTTP information
            if HTTPRequest in packet:
                if packet[HTTPRequest].Host:
                    domain = packet[HTTPRequest].Host.decode()
                    self.dns_cache[dst_ip] = domain
                    
            # Use cached domain if available
            if not domain and dst_ip in self.dns_cache:
                domain = self.dns_cache[dst_ip]
            
            # Fallback reverse DNS lookup when still unknown
            if not domain:
                domain = self._resolve_domain(dst_ip)
                
            # Categorize application
            application = self._categorize_domain(domain) if domain else self._guess_app_from_port(dst_port)
            
            # Store packet data
            self._store_packet_data(
                src_ip, dst_ip, src_mac, dst_mac,
                src_port, dst_port, protocol_name,
                packet_size, domain, application
            )
            
            # Update statistics
            self.stats['packets_captured'] += 1
            self.stats['bytes_captured'] += packet_size
            self.stats['protocols'][protocol_name] += 1
            self.stats['applications'][application] += 1
            if domain:
                self.stats['domains'][domain] += 1
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            
    def _netstat_capture_loop(self):
        """Fallback capture using netstat (works on all platforms)"""
        with self.app_context.app_context() if self.app_context else nullcontext():
            last_connections = set()
            
            while self.running:
                try:
                    # Get network connections
                    if self.platform == "Windows":
                        cmd = ['netstat', '-an']
                    else:
                        cmd = ['netstat', '-tun']
                        
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        current_connections = self._parse_netstat_output(result.stdout)
                        
                        # Process new connections
                        new_connections = current_connections - last_connections
                        for conn in new_connections:
                            self._process_netstat_connection(conn)
                            
                        last_connections = current_connections
                        
                    time.sleep(2)  # Check every 2 seconds
                    
                except Exception as e:
                    self.logger.error(f"Netstat capture error: {e}")
                    time.sleep(5)
                    
    def _parse_netstat_output(self, output):
        """Parse netstat output to extract connections"""
        connections = set()
        
        for line in output.split('\n'):
            if 'ESTABLISHED' in line or 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    local = parts[1] if self.platform == "Windows" else parts[3]
                    remote = parts[2] if self.platform == "Windows" else parts[4]
                    
                    if ':' in local and ':' in remote:
                        connections.add((local, remote))
                        
        return connections
        
    def _process_netstat_connection(self, conn):
        """Process a netstat connection"""
        try:
            local, remote = conn
            
            # Parse addresses
            local_ip, local_port = local.rsplit(':', 1)
            remote_ip, remote_port = remote.rsplit(':', 1)
            
            # Skip localhost
            if local_ip.startswith('127.') or remote_ip.startswith('127.'):
                return
                
            # Determine protocol from port
            protocol = self._guess_protocol_from_port(int(remote_port))
            
            # Try to resolve domain
            domain = self._resolve_domain(remote_ip)
            
            # Categorize application
            application = self._categorize_domain(domain) if domain else self._guess_app_from_port(int(remote_port))
            
            # Store connection data
            self._store_packet_data(
                local_ip, remote_ip, f"device-{local_ip}", f"remote-{remote_ip}",
                int(local_port), int(remote_port), protocol,
                1500, domain, application  # Estimate packet size
            )
            
        except Exception as e:
            self.logger.error(f"Error processing connection: {e}")
            
    def _store_packet_data(self, src_ip, dst_ip, src_mac, dst_mac, 
                          src_port, dst_port, protocol, packet_size, 
                          domain, application):
        """Store packet data in database"""
        try:
            # Get or create device
            device = self._get_or_create_device(src_ip, src_mac)
            
            # Get or create user (if device is assigned and model supports it)
            user = None
            if device and hasattr(device, 'assigned_user'):
                user = device.assigned_user
            
            # Create traffic session with base model fields
            session_data = {
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'start_time': datetime.utcnow(),
                'bytes_sent': packet_size,
                'bytes_received': 0,
                'packet_count': 1
            }
            
            # Add enhanced fields only if model supports them
            if ENABLE_ENHANCED:
                session_data['application'] = application
                session_data['application_category'] = self._get_app_category(application)
                session_data['is_encrypted'] = (protocol == 'HTTPS' or dst_port == 443)
            
            session = TrafficSession(**session_data)
            db.session.add(session)
            
            # Create website visit if it's web traffic
            if domain and protocol in ['HTTP', 'HTTPS', 'TCP'] and dst_port in [80, 443, 8080, 8443]:
                visit_data = {
                    'device_mac': src_mac,
                    'domain': domain,
                    'url': f"{'https' if dst_port == 443 else 'http'}://{domain}",
                    'timestamp': datetime.utcnow(),
                    'bytes_transferred': packet_size,
                    'response_code': 200,
                    'method': 'GET'
                }
                
                # Add enhanced fields only if model supports them
                if ENABLE_ENHANCED and hasattr(WebsiteVisit, 'category'):
                    visit_data['category'] = application
                    visit_data['subcategory'] = self._get_app_category(application)
                    
                visit = WebsiteVisit(**visit_data)
                db.session.add(visit)
                
            # Update or create enriched data for destination IP
            enriched = EnrichedData.query.filter_by(ip_address=dst_ip).first()
            if not enriched:
                enriched = EnrichedData(
                    ip_address=dst_ip,
                    hostname=domain,
                    organization=application,
                    updated_at=datetime.utcnow()
                )
                db.session.add(enriched)
                
            # Update user session if user exists
            if user:
                user_session = UserSession.query.filter_by(
                    user_id=user.id,
                    device_mac=src_mac,
                    end_time=None
                ).first()
                
                if not user_session:
                    user_session = UserSession(
                        user_id=user.id,
                        device_mac=src_mac,
                        start_time=datetime.utcnow(),
                        total_bytes=0,
                        websites_visited=0,
                        applications_used=json.dumps([])
                    )
                    db.session.add(user_session)
                    
                # Update session
                user_session.total_bytes += packet_size
                if domain:
                    user_session.websites_visited += 1
                    
                apps = json.loads(user_session.applications_used or '[]')
                if application not in apps:
                    apps.append(application)
                    user_session.applications_used = json.dumps(apps)
                    
            # Commit to database
            db.session.commit()
            
        except Exception as e:
            self.logger.error(f"Error storing packet data: {e}")
            db.session.rollback()
            
    def _get_or_create_device(self, ip_address, mac_address):
        """Get existing device or create new one"""
        try:
            device = Device.query.filter_by(mac_address=mac_address).first()
            
            if not device:
                hostname = self._get_hostname(ip_address)
                
                # Create device with base model fields
                device_data = {
                    'mac_address': mac_address,
                    'ip_address': ip_address,
                    'hostname': hostname or f"Device-{ip_address}",
                    'vendor': self._get_vendor_from_mac(mac_address),
                    'device_type': self._guess_device_type(ip_address),
                    'first_seen': datetime.utcnow(),
                    'last_seen': datetime.utcnow(),
                    'is_active': True
                }
                
                # Add enhanced fields only if model supports them
                if ENABLE_ENHANCED:
                    device_data['operating_system'] = self._detect_os(ip_address)
                
                device = Device(**device_data)
                db.session.add(device)
                db.session.commit()
            else:
                device.last_seen = datetime.utcnow()
                device.ip_address = ip_address
                device.is_active = True
                db.session.commit()
                
            return device
            
        except Exception as e:
            self.logger.error(f"Error getting/creating device: {e}")
            return None
            
    def _get_hostname(self, ip_address):
        """Get hostname from IP"""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except:
            return None
            
    def _resolve_domain(self, ip_address):
        """Resolve IP to domain"""
        # Check cache first
        if ip_address in self.dns_cache:
            return self.dns_cache[ip_address]
            
        try:
            domain = socket.gethostbyaddr(ip_address)[0]
            self.dns_cache[ip_address] = domain
            return domain
        except:
            return None
            
    def _get_vendor_from_mac(self, mac_address):
        """Get vendor from MAC address"""
        # This would use an OUI database in production
        mac_prefixes = {
            'aa:bb:cc': 'Test Vendor',
            'device-': 'Local Device'
        }
        
        for prefix, vendor in mac_prefixes.items():
            if mac_address.startswith(prefix):
                return vendor
                
        return 'Unknown'
        
    def _guess_device_type(self, ip_address):
        """Guess device type from IP"""
        if ip_address.endswith('.1'):
            return 'router'
        elif ip_address.startswith('192.168.'):
            return 'computer'
        else:
            return 'device'
            
    def _detect_os(self, ip_address):
        """Detect operating system"""
        # This would use more sophisticated detection in production
        return 'Unknown'
        
    def _guess_protocol_from_port(self, port):
        """Guess protocol from port number"""
        port_protocols = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 110: 'POP3', 143: 'IMAP', 53: 'DNS',
            3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL'
        }
        return port_protocols.get(port, 'TCP')
        
    def _guess_app_from_port(self, port):
        """Guess application from port"""
        port_apps = {
            80: 'Web', 443: 'Web', 22: 'SSH', 21: 'FTP',
            25: 'Email', 110: 'Email', 143: 'Email', 53: 'DNS',
            3389: 'Remote Desktop', 3306: 'Database', 5432: 'Database',
            5900: 'VNC', 8080: 'Web', 8443: 'Web'
        }
        return port_apps.get(port, 'Unknown')
        
    def _get_app_category(self, application):
        """Get application category"""
        categories = {
            'Google': 'Productivity',
            'Facebook': 'Social Media',
            'Netflix': 'Entertainment',
            'Microsoft': 'Productivity',
            'GitHub': 'Development',
            'Zoom': 'Communication',
            'Slack': 'Communication',
            'Discord': 'Communication',
            'Steam': 'Gaming',
            'Spotify': 'Entertainment'
        }
        return categories.get(application, 'Other')
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Stopped packet capture")
        
    def get_stats(self):
        """Get capture statistics"""
        return {
            'platform': self.platform,
            'interface': self.interface,
            'running': self.running,
            'packets_captured': self.stats['packets_captured'],
            'bytes_captured': self.stats['bytes_captured'],
            'protocols': dict(self.stats['protocols']),
            'applications': dict(self.stats['applications']),
            'domains': dict(self.stats['domains']),
            'devices': len(self.stats['devices']),
            'capture_method': 'scapy' if SCAPY_AVAILABLE else 'netstat'
        }

# Context manager for optional app context
class nullcontext:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
