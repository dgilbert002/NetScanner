import asyncio
import threading
import time
import logging
from datetime import datetime
from collections import defaultdict
import re
import socket

# Import real packet capture
try:
    from .real_packet_capture import RealPacketCaptureEngine, RealNetworkMonitor
    REAL_CAPTURE_AVAILABLE = True
except ImportError:
    REAL_CAPTURE_AVAILABLE = False

# Import Windows-compatible packet capture
try:
    from .windows_packet_capture import WindowsPacketCapture, WindowsNetworkMonitor
    WINDOWS_CAPTURE_AVAILABLE = True
except ImportError:
    WINDOWS_CAPTURE_AVAILABLE = False

# Mock imports for demonstration (fallback if real capture fails)
class MockPacket:
    """Mock packet class for demonstration"""
    def __init__(self, src_ip, dst_ip, protocol, length, src_mac=None, dst_mac=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.length = length
        self.src_mac = src_mac or "aa:bb:cc:dd:ee:ff"
        self.dst_mac = dst_mac or "11:22:33:44:55:66"
        self.timestamp = datetime.utcnow()
        
        # Mock HTTP data
        if protocol == "HTTP":
            self.http_host = self._extract_domain(dst_ip)
            self.http_method = "GET"
            self.http_response_code = 200
        else:
            self.http_host = None
            self.http_method = None
            self.http_response_code = None
    
    def _extract_domain(self, ip):
        """Mock domain extraction"""
        domain_map = {
            "8.8.8.8": "google.com",
            "1.1.1.1": "cloudflare.com",
            "208.67.222.222": "opendns.com",
            "192.168.1.1": "router.local"
        }
        return domain_map.get(ip, f"unknown-{ip}")

class PacketCaptureEngine:
    """Network packet capture and analysis engine"""
    
    def __init__(self, interface='WiFi', bpf_filter=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = False
        self.capture_thread = None
        self.packet_queue = asyncio.Queue()
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'start_time': None,
            'protocols': defaultdict(int),
            'devices': set(),
            'domains': defaultdict(int)
        }
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.running:
            self.logger.warning("Capture already running")
            return
            
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        self.logger.info(f"Started packet capture on interface {self.interface}")
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Stopped packet capture")
        
    def _capture_loop(self):
        """Main capture loop (mock implementation)"""
        # In a real implementation, this would use pyshark or scapy
        # For demonstration, we'll generate mock packets
        
        mock_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222", 
            "192.168.1.100", "192.168.1.101", "192.168.1.102"
        ]
        
        mock_protocols = ["HTTP", "HTTPS", "DNS", "TCP", "UDP"]
        
        import random
        
        while self.running:
            try:
                # Generate mock packet
                src_ip = random.choice(["192.168.1.100", "192.168.1.101", "192.168.1.102"])
                dst_ip = random.choice(mock_ips)
                protocol = random.choice(mock_protocols)
                length = random.randint(64, 1500)
                
                packet = MockPacket(src_ip, dst_ip, protocol, length)
                
                # Process packet
                self._process_packet(packet)
                
                # Add to queue for async processing
                try:
                    self.packet_queue.put_nowait(packet)
                except asyncio.QueueFull:
                    self.logger.warning("Packet queue full, dropping packet")
                
                # Sleep to simulate realistic packet rates
                time.sleep(random.uniform(0.1, 2.0))
                
            except Exception as e:
                self.logger.error(f"Error in capture loop: {e}")
                time.sleep(1)
                
    def _process_packet(self, packet):
        """Process individual packet and update statistics"""
        try:
            # Update statistics
            self.stats['packets_captured'] += 1
            self.stats['bytes_captured'] += packet.length
            self.stats['protocols'][packet.protocol] += 1
            self.stats['devices'].add(packet.src_mac)
            
            if packet.http_host:
                self.stats['domains'][packet.http_host] += 1
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            
    async def get_packet(self):
        """Get next packet from queue"""
        return await self.packet_queue.get()
        
    def get_stats(self):
        """Get current capture statistics"""
        stats = self.stats.copy()
        stats['devices'] = list(stats['devices'])
        stats['protocols'] = dict(stats['protocols'])
        stats['domains'] = dict(stats['domains'])
        
        # Calculate packets per second
        if stats['start_time']:
            elapsed = (datetime.utcnow() - stats['start_time']).total_seconds()
            stats['packets_per_second'] = stats['packets_captured'] / max(elapsed, 1)
        else:
            stats['packets_per_second'] = 0
            
        return stats
        
    def get_device_info(self, mac_address):
        """Get device information from MAC address"""
        # Mock device vendor lookup
        vendor_map = {
            "aa:bb:cc:dd:ee:ff": "Apple Inc.",
            "11:22:33:44:55:66": "Samsung Electronics",
            "ff:ee:dd:cc:bb:aa": "Intel Corporation"
        }
        
        return {
            'mac_address': mac_address,
            'vendor': vendor_map.get(mac_address, "Unknown"),
            'device_type': self._guess_device_type(mac_address)
        }
        
    def _guess_device_type(self, mac_address):
        """Guess device type from MAC address"""
        # Simple heuristic based on MAC prefix
        if mac_address.startswith("aa:bb"):
            return "smartphone"
        elif mac_address.startswith("11:22"):
            return "laptop"
        else:
            return "unknown"

class DataEnrichmentEngine:
    """Data enrichment for IP addresses and domains"""
    
    def __init__(self):
        self.cache = {}
        self.logger = logging.getLogger(__name__)
        
    async def enrich_ip(self, ip_address):
        """Enrich IP address with geolocation and other data"""
        if ip_address in self.cache:
            return self.cache[ip_address]
            
        # Mock enrichment data
        enriched_data = {
            'ip_address': ip_address,
            'hostname': await self._resolve_hostname(ip_address),
            'country': self._get_mock_country(ip_address),
            'city': self._get_mock_city(ip_address),
            'isp': self._get_mock_isp(ip_address),
            'is_vpn': False,
            'is_proxy': False,
            'threat_level': 'low'
        }
        
        self.cache[ip_address] = enriched_data
        return enriched_data
        
    async def _resolve_hostname(self, ip_address):
        """Resolve IP to hostname"""
        try:
            # Mock DNS resolution
            hostname_map = {
                "8.8.8.8": "dns.google",
                "1.1.1.1": "one.one.one.one",
                "208.67.222.222": "resolver1.opendns.com"
            }
            return hostname_map.get(ip_address, f"host-{ip_address.replace('.', '-')}")
        except Exception:
            return None
            
    def _get_mock_country(self, ip_address):
        """Get mock country data"""
        if ip_address.startswith("192.168"):
            return "Local Network"
        elif ip_address.startswith("8.8"):
            return "United States"
        elif ip_address.startswith("1.1"):
            return "United States"
        else:
            return "Unknown"
            
    def _get_mock_city(self, ip_address):
        """Get mock city data"""
        if ip_address.startswith("192.168"):
            return "Local"
        elif ip_address.startswith("8.8"):
            return "Mountain View"
        elif ip_address.startswith("1.1"):
            return "San Francisco"
        else:
            return "Unknown"
            
    def _get_mock_isp(self, ip_address):
        """Get mock ISP data"""
        if ip_address.startswith("192.168"):
            return "Local Network"
        elif ip_address.startswith("8.8"):
            return "Google LLC"
        elif ip_address.startswith("1.1"):
            return "Cloudflare Inc."
        else:
            return "Unknown ISP"

class NetworkMonitor:
    """Main network monitoring coordinator"""
    
    def __init__(self, interface='WiFi'):
        # Use Windows-compatible capture first, then real capture, then mock
        if WINDOWS_CAPTURE_AVAILABLE:
            self.capture_engine = WindowsPacketCapture(interface)
            self.logger = logging.getLogger(__name__)
            self.logger.info("Using WINDOWS packet capture engine")
        elif REAL_CAPTURE_AVAILABLE:
            self.capture_engine = RealPacketCaptureEngine(interface)
            self.logger = logging.getLogger(__name__)
            self.logger.info("Using REAL packet capture engine")
        else:
            self.capture_engine = PacketCaptureEngine(interface)
            self.logger = logging.getLogger(__name__)
            self.logger.warning("Using MOCK packet capture engine (scapy not available)")
            
        self.enrichment_engine = DataEnrichmentEngine()
        self.running = False
        self.monitor_task = None
        
    async def start_monitoring(self):
        """Start network monitoring"""
        if self.running:
            return
            
        self.running = True
        self.capture_engine.start_capture()
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Started network monitoring")
        
    async def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        self.capture_engine.stop_capture()
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
                
        self.logger.info("Stopped network monitoring")
        
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get packet from capture engine
                packet = await asyncio.wait_for(
                    self.capture_engine.get_packet(), 
                    timeout=1.0
                )
                
                # Enrich packet data
                if packet.dst_ip:
                    enriched_data = await self.enrichment_engine.enrich_ip(packet.dst_ip)
                    packet.enriched_data = enriched_data
                    
                # Here you would save to database
                self.logger.debug(f"Processed packet: {packet.src_ip} -> {packet.dst_ip}")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                await asyncio.sleep(1)
                
    def get_stats(self):
        """Get monitoring statistics"""
        return self.capture_engine.get_stats()
        
    def get_devices(self):
        """Get discovered devices"""
        devices = []
        for mac in self.capture_engine.stats['devices']:
            device_info = self.capture_engine.get_device_info(mac)
            devices.append(device_info)
        return devices

