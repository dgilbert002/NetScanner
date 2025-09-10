"""
Advanced Traffic Analysis Module
Implements traffic classification, application identification, and content analysis
"""

import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP
import requests
import json
import time
import threading
from datetime import datetime
from urllib.parse import urlparse
import re
import socket
from collections import defaultdict

class TrafficClassifier:
    """Advanced traffic classification using multiple techniques"""
    
    def __init__(self):
        self.application_signatures = self._load_application_signatures()
        self.port_mappings = self._load_port_mappings()
        self.domain_cache = {}
        
    def _load_application_signatures(self):
        """Load application signatures for DPI-like classification"""
        return {
            'http': {
                'patterns': [b'GET ', b'POST ', b'PUT ', b'DELETE '],
                'ports': [80, 8080, 8000]
            },
            'https': {
                'patterns': [b'\x16\x03'],  # TLS handshake
                'ports': [443, 8443]
            },
            'ssh': {
                'patterns': [b'SSH-'],
                'ports': [22]
            },
            'ftp': {
                'patterns': [b'220 ', b'USER ', b'PASS '],
                'ports': [21]
            },
            'smtp': {
                'patterns': [b'220 ', b'HELO ', b'EHLO '],
                'ports': [25, 587]
            },
            'dns': {
                'patterns': [],
                'ports': [53]
            },
            'dhcp': {
                'patterns': [],
                'ports': [67, 68]
            },
            'ntp': {
                'patterns': [],
                'ports': [123]
            },
            'youtube': {
                'patterns': [b'youtube.com', b'googlevideo.com'],
                'ports': [443, 80]
            },
            'netflix': {
                'patterns': [b'netflix.com', b'nflxvideo.net'],
                'ports': [443, 80]
            },
            'spotify': {
                'patterns': [b'spotify.com', b'scdn.co'],
                'ports': [443, 80]
            },
            'zoom': {
                'patterns': [b'zoom.us', b'zoomgov.com'],
                'ports': [443, 80, 8801, 8802]
            },
            'teams': {
                'patterns': [b'teams.microsoft.com', b'skype.com'],
                'ports': [443, 80]
            },
            'whatsapp': {
                'patterns': [b'whatsapp.com', b'whatsapp.net'],
                'ports': [443, 80, 5222]
            },
            'telegram': {
                'patterns': [b'telegram.org', b't.me'],
                'ports': [443, 80]
            }
        }
    
    def _load_port_mappings(self):
        """Load common port to application mappings"""
        return {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'SQL Server',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5222: 'XMPP',
            6379: 'Redis',
            8080: 'HTTP Alt',
            8443: 'HTTPS Alt'
        }
    
    def classify_packet(self, packet):
        """Classify a single packet and extract metadata"""
        classification = {
            'timestamp': datetime.utcnow(),
            'protocol': None,
            'application': None,
            'confidence': 0.0,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'payload_size': 0,
            'is_encrypted': False,
            'domain': None,
            'url': None,
            'http_method': None,
            'user_agent': None
        }
        
        try:
            # Extract basic IP information
            if IP in packet:
                classification['src_ip'] = packet[IP].src
                classification['dst_ip'] = packet[IP].dst
                classification['payload_size'] = len(packet[IP].payload)
            
            # TCP analysis
            if TCP in packet:
                classification['protocol'] = 'TCP'
                classification['src_port'] = packet[TCP].sport
                classification['dst_port'] = packet[TCP].dport
                
                # Port-based classification
                dst_port = packet[TCP].dport
                if dst_port in self.port_mappings:
                    classification['application'] = self.port_mappings[dst_port]
                    classification['confidence'] = 0.7
                
                # Payload analysis for application identification
                if packet[TCP].payload:
                    payload = bytes(packet[TCP].payload)
                    app_result = self._analyze_payload(payload, dst_port)
                    if app_result:
                        classification.update(app_result)
            
            # UDP analysis
            elif UDP in packet:
                classification['protocol'] = 'UDP'
                classification['src_port'] = packet[UDP].sport
                classification['dst_port'] = packet[UDP].dport
                
                dst_port = packet[UDP].dport
                if dst_port in self.port_mappings:
                    classification['application'] = self.port_mappings[dst_port]
                    classification['confidence'] = 0.8
            
            # HTTP analysis
            if HTTPRequest in packet:
                http_data = self._analyze_http_request(packet[HTTPRequest])
                classification.update(http_data)
            
            elif HTTPResponse in packet:
                http_data = self._analyze_http_response(packet[HTTPResponse])
                classification.update(http_data)
            
        except Exception as e:
            print(f"Error classifying packet: {e}")
        
        return classification
    
    def _analyze_payload(self, payload, port):
        """Analyze packet payload for application signatures"""
        result = {}
        
        # Check application signatures
        for app_name, app_data in self.application_signatures.items():
            for pattern in app_data['patterns']:
                if pattern in payload:
                    result['application'] = app_name.upper()
                    result['confidence'] = 0.9
                    
                    # Check for encryption indicators
                    if app_name in ['https', 'ssh']:
                        result['is_encrypted'] = True
                    
                    break
        
        # TLS/SSL detection
        if payload.startswith(b'\x16\x03'):
            result['is_encrypted'] = True
            result['application'] = 'HTTPS'
            result['confidence'] = 0.95
        
        # HTTP detection
        if any(method in payload for method in [b'GET ', b'POST ', b'PUT ', b'DELETE ']):
            result['application'] = 'HTTP'
            result['confidence'] = 0.95
            
            # Extract HTTP details
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                lines = payload_str.split('\r\n')
                
                if lines:
                    # Parse request line
                    request_line = lines[0]
                    parts = request_line.split(' ')
                    if len(parts) >= 3:
                        result['http_method'] = parts[0]
                        result['url'] = parts[1]
                
                # Extract headers
                for line in lines[1:]:
                    if line.startswith('Host: '):
                        result['domain'] = line[6:].strip()
                    elif line.startswith('User-Agent: '):
                        result['user_agent'] = line[12:].strip()
            except:
                pass
        
        return result
    
    def _analyze_http_request(self, http_packet):
        """Analyze HTTP request packet"""
        result = {
            'application': 'HTTP',
            'confidence': 1.0,
            'http_method': http_packet.Method.decode() if http_packet.Method else None,
            'url': http_packet.Path.decode() if http_packet.Path else None,
            'domain': http_packet.Host.decode() if http_packet.Host else None,
            'user_agent': http_packet.User_Agent.decode() if http_packet.User_Agent else None
        }
        
        return result
    
    def _analyze_http_response(self, http_packet):
        """Analyze HTTP response packet"""
        result = {
            'application': 'HTTP',
            'confidence': 1.0
        }
        
        # Extract response code and content type if available
        if hasattr(http_packet, 'Status_Code'):
            result['http_status'] = int(http_packet.Status_Code)
        
        return result

class ContentAnalyzer:
    """Content analysis for web traffic"""
    
    def __init__(self, klazify_api_key=None):
        self.klazify_api_key = klazify_api_key
        self.session = requests.Session()
        self.domain_cache = {}
        
    def analyze_url(self, url, content=None):
        """Analyze URL and optionally its content"""
        analysis = {
            'url': url,
            'domain': None,
            'category': None,
            'subcategory': None,
            'confidence': 0.0,
            'content_summary': None,
            'keywords': [],
            'meta_description': None,
            'images_count': 0,
            'links_count': 0,
            'forms_count': 0,
            'scripts_count': 0,
            'language': None,
            'sentiment_score': 0.0
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            analysis['domain'] = parsed_url.netloc
            
            # Get domain categorization
            if self.klazify_api_key:
                category_data = self._categorize_domain(analysis['domain'])
                if category_data:
                    analysis.update(category_data)
            
            # Analyze content if provided
            if content:
                content_data = self._analyze_content(content)
                analysis.update(content_data)
            
        except Exception as e:
            print(f"Error analyzing URL {url}: {e}")
        
        return analysis
    
    def _categorize_domain(self, domain):
        """Categorize domain using Klazify API"""
        if domain in self.domain_cache:
            return self.domain_cache[domain]
        
        try:
            headers = {
                'Authorization': f'Bearer {self.klazify_api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'url': f'https://{domain}'
            }
            
            response = self.session.post(
                'https://www.klazify.com/api/categorize',
                headers=headers,
                json=data,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                
                category_data = {
                    'category': result.get('category', {}).get('name'),
                    'subcategory': result.get('category', {}).get('subcategory'),
                    'confidence': result.get('category', {}).get('confidence', 0.0)
                }
                
                # Cache result
                self.domain_cache[domain] = category_data
                return category_data
                
        except Exception as e:
            print(f"Error categorizing domain {domain}: {e}")
        
        return None
    
    def _analyze_content(self, content):
        """Analyze HTML content"""
        from bs4 import BeautifulSoup
        import re
        
        analysis = {}
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                analysis['title'] = title_tag.get_text().strip()
            
            # Extract meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                analysis['meta_description'] = meta_desc.get('content', '')
            
            # Count elements
            analysis['images_count'] = len(soup.find_all('img'))
            analysis['links_count'] = len(soup.find_all('a'))
            analysis['forms_count'] = len(soup.find_all('form'))
            analysis['scripts_count'] = len(soup.find_all('script'))
            
            # Extract text content
            text_content = soup.get_text()
            
            # Simple keyword extraction
            words = re.findall(r'\b\w+\b', text_content.lower())
            word_freq = {}
            for word in words:
                if len(word) > 3:  # Only words longer than 3 characters
                    word_freq[word] = word_freq.get(word, 0) + 1
            
            # Get top keywords
            top_keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10]
            analysis['keywords'] = [word for word, freq in top_keywords]
            
            # Simple content summary (first 200 characters of text)
            clean_text = re.sub(r'\s+', ' ', text_content).strip()
            analysis['content_summary'] = clean_text[:200] + '...' if len(clean_text) > 200 else clean_text
            
            # Language detection (simple heuristic)
            analysis['language'] = self._detect_language(text_content)
            
            # Simple sentiment analysis (placeholder)
            analysis['sentiment_score'] = self._analyze_sentiment(text_content)
            
        except Exception as e:
            print(f"Error analyzing content: {e}")
        
        return analysis
    
    def _detect_language(self, text):
        """Simple language detection"""
        # This is a placeholder - in production, use a proper language detection library
        common_english_words = ['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']
        
        text_lower = text.lower()
        english_count = sum(1 for word in common_english_words if word in text_lower)
        
        if english_count > 3:
            return 'en'
        else:
            return 'unknown'
    
    def _analyze_sentiment(self, text):
        """Simple sentiment analysis"""
        # This is a placeholder - in production, use a proper sentiment analysis library
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'love', 'like']
        negative_words = ['bad', 'terrible', 'awful', 'hate', 'dislike', 'horrible', 'worst', 'poor']
        
        text_lower = text.lower()
        positive_count = sum(1 for word in positive_words if word in text_lower)
        negative_count = sum(1 for word in negative_words if word in text_lower)
        
        if positive_count + negative_count == 0:
            return 0.0
        
        return (positive_count - negative_count) / (positive_count + negative_count)

class NetworkEnricher:
    """Network data enrichment using external APIs"""
    
    def __init__(self, ipinfo_token=None, maxmind_license_key=None):
        self.ipinfo_token = ipinfo_token
        self.maxmind_license_key = maxmind_license_key
        self.session = requests.Session()
        self.ip_cache = {}
        
    def enrich_ip(self, ip_address):
        """Enrich IP address with geolocation and threat intelligence"""
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]
        
        enrichment = {
            'ip_address': ip_address,
            'hostname': None,
            'country': None,
            'country_code': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'isp': None,
            'organization': None,
            'asn': None,
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'threat_level': 'low'
        }
        
        try:
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                enrichment['hostname'] = hostname
            except:
                pass
            
            # IPinfo enrichment
            if self.ipinfo_token:
                ipinfo_data = self._get_ipinfo_data(ip_address)
                if ipinfo_data:
                    enrichment.update(ipinfo_data)
            
            # Basic threat detection (placeholder)
            enrichment['threat_level'] = self._assess_threat_level(ip_address, enrichment)
            
            # Cache result
            self.ip_cache[ip_address] = enrichment
            
        except Exception as e:
            print(f"Error enriching IP {ip_address}: {e}")
        
        return enrichment
    
    def _get_ipinfo_data(self, ip_address):
        """Get data from IPinfo API"""
        try:
            url = f"https://ipinfo.io/{ip_address}/json"
            params = {'token': self.ipinfo_token} if self.ipinfo_token else {}
            
            response = self.session.get(url, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse location
                loc = data.get('loc', '').split(',')
                latitude = float(loc[0]) if len(loc) > 0 and loc[0] else None
                longitude = float(loc[1]) if len(loc) > 1 and loc[1] else None
                
                return {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'latitude': latitude,
                    'longitude': longitude,
                    'isp': data.get('org'),
                    'organization': data.get('org'),
                    'asn': self._extract_asn(data.get('org', ''))
                }
                
        except Exception as e:
            print(f"Error getting IPinfo data for {ip_address}: {e}")
        
        return None
    
    def _extract_asn(self, org_string):
        """Extract ASN from organization string"""
        if org_string:
            asn_match = re.match(r'AS(\d+)', org_string)
            if asn_match:
                return int(asn_match.group(1))
        return None
    
    def _assess_threat_level(self, ip_address, enrichment):
        """Assess threat level based on available data"""
        # This is a placeholder - in production, integrate with threat intelligence feeds
        
        # Check for known malicious indicators
        if enrichment.get('organization', '').lower() in ['tor', 'proxy', 'vpn']:
            return 'medium'
        
        # Check for suspicious patterns
        hostname = enrichment.get('hostname', '')
        if any(keyword in hostname.lower() for keyword in ['malware', 'botnet', 'spam']):
            return 'high'
        
        return 'low'

class RealTimeAnalyzer:
    """Real-time traffic analysis coordinator"""
    
    def __init__(self, interface='eth0', klazify_api_key=None, ipinfo_token=None):
        self.interface = interface
        self.classifier = TrafficClassifier()
        self.content_analyzer = ContentAnalyzer(klazify_api_key)
        self.enricher = NetworkEnricher(ipinfo_token)
        self.is_running = False
        self.analysis_thread = None
        self.packet_queue = []
        self.analysis_callbacks = []
        
    def add_analysis_callback(self, callback):
        """Add callback function to receive analysis results"""
        self.analysis_callbacks.append(callback)
    
    def start_analysis(self):
        """Start real-time traffic analysis"""
        if self.is_running:
            return
        
        self.is_running = True
        self.analysis_thread = threading.Thread(target=self._packet_capture_loop)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        print(f"Started real-time analysis on interface {self.interface}")
    
    def stop_analysis(self):
        """Stop real-time traffic analysis"""
        self.is_running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        
        print("Stopped real-time analysis")
    
    def _packet_capture_loop(self):
        """Main packet capture and analysis loop"""
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_running,
                store=False
            )
        except Exception as e:
            print(f"Error in packet capture loop: {e}")
    
    def _process_packet(self, packet):
        """Process individual packet"""
        try:
            # Classify packet
            classification = self.classifier.classify_packet(packet)
            
            # Enrich IP data for external IPs
            if classification['dst_ip'] and not self._is_private_ip(classification['dst_ip']):
                enrichment = self.enricher.enrich_ip(classification['dst_ip'])
                classification['dst_enrichment'] = enrichment
            
            # Analyze content for HTTP traffic
            if classification['application'] == 'HTTP' and classification['url']:
                content_analysis = self.content_analyzer.analyze_url(
                    f"http://{classification['domain']}{classification['url']}"
                )
                classification['content_analysis'] = content_analysis
            
            # Send to callbacks
            for callback in self.analysis_callbacks:
                try:
                    callback(classification)
                except Exception as e:
                    print(f"Error in analysis callback: {e}")
                    
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _is_private_ip(self, ip):
        """Check if IP is in private range"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

# Example usage and testing
if __name__ == "__main__":
    # Example of how to use the traffic analyzer
    analyzer = RealTimeAnalyzer(
        interface='eth0',
        klazify_api_key='your_klazify_key',
        ipinfo_token='your_ipinfo_token'
    )
    
    def analysis_callback(classification):
        print(f"Analyzed: {classification['application']} - {classification['dst_ip']}")
        if classification.get('domain'):
            print(f"  Domain: {classification['domain']}")
        if classification.get('content_analysis'):
            print(f"  Category: {classification['content_analysis'].get('category')}")
    
    analyzer.add_analysis_callback(analysis_callback)
    
    # Start analysis (uncomment to test)
    # analyzer.start_analysis()
    # time.sleep(60)  # Run for 1 minute
    # analyzer.stop_analysis()

