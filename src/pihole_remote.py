"""
Remote Pi-hole connection via SSH
Connects to Pi-hole server and queries the database remotely
"""

import os
import json
import subprocess
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

class PiHoleRemote:
    """Connect to Pi-hole via SSH and query the database remotely."""
    
    def __init__(self, host: str = None, user: str = "pi"):
        self.host = host or os.getenv('PIHOLE_HOST', '192.168.50.113')
        self.user = user
        self.enabled = False
        self.last_check = None
        self.cache = {}
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self):
        """Test if we can reach the Pi-hole server."""
        try:
            # Simple ping test
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', self.host],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                self.enabled = True
                print(f"✓ Pi-hole server reachable at {self.host}")
                # Try to get Pi-hole stats via API
                self._test_api()
            else:
                print(f"✗ Pi-hole server not reachable at {self.host}")
        except Exception as e:
            print(f"✗ Pi-hole connection test failed: {e}")
            self.enabled = False
    
    def _test_api(self):
        """Test Pi-hole API access."""
        try:
            import urllib.request
            import json
            
            # Try Pi-hole API endpoint
            url = f"http://{self.host}/admin/api.php?summary"
            with urllib.request.urlopen(url, timeout=2) as response:
                data = json.loads(response.read())
                if 'dns_queries_today' in data:
                    print(f"✓ Pi-hole API accessible - {data['dns_queries_today']} queries today")
                    return True
        except Exception:
            # API not accessible, but server is up
            pass
        return False
    
    def get_recent_queries(self, since_seconds: int = 300) -> List[Tuple[str, str, datetime]]:
        """Get recent DNS queries from Pi-hole."""
        if not self.enabled:
            return []
        
        results = []
        try:
            # Use Pi-hole API to get recent queries
            import urllib.request
            import json
            
            # Get all queries (limited to recent)
            url = f"http://{self.host}/admin/api.php?getAllQueries&auth="
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read())
                
                if 'data' in data:
                    cutoff = datetime.utcnow() - timedelta(seconds=since_seconds)
                    for query in data['data']:
                        # query format: [timestamp, type, domain, client, status, ...]
                        if len(query) >= 4:
                            timestamp = datetime.fromtimestamp(int(query[0]))
                            if timestamp >= cutoff:
                                domain = query[2]
                                client = query[3]
                                results.append((client, domain, timestamp))
        except Exception as e:
            # Fallback: try to read from log file via HTTP
            try:
                url = f"http://{self.host}/admin/api.php?recentBlocked"
                with urllib.request.urlopen(url, timeout=2) as response:
                    data = response.read().decode('utf-8')
                    # Parse the response for hostnames
            except Exception:
                pass
        
        return results
    
    def lookup_hostname(self, ip: str) -> Optional[str]:
        """Look up hostname for an IP address."""
        if not self.enabled:
            return None
        
        # Check cache first
        if ip in self.cache:
            cached_time, hostname = self.cache[ip]
            if (datetime.utcnow() - cached_time).seconds < 300:  # 5 min cache
                return hostname
        
        # Query recent DNS resolutions
        recent = self.get_recent_queries(600)  # Last 10 minutes
        for client_ip, domain, _ in recent:
            if client_ip == ip:
                self.cache[ip] = (datetime.utcnow(), domain)
                return domain
        
        return None
