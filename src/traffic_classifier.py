"""
Traffic Classification Fallback
Identifies applications and categories based on ports, protocols, and patterns
without requiring nDPI installation.
"""

import re
from typing import Dict, Optional, Tuple

class TrafficClassifier:
    """Fallback traffic classifier using port/protocol heuristics."""
    
    # Common port to application mappings
    PORT_APPS = {
        # Web
        80: ("HTTP", "Web"),
        443: ("HTTPS", "Web"),
        8080: ("HTTP-Proxy", "Web"),
        8443: ("HTTPS-Alt", "Web"),
        
        # Email
        25: ("SMTP", "Email"),
        110: ("POP3", "Email"),
        143: ("IMAP", "Email"),
        465: ("SMTPS", "Email"),
        587: ("SMTP-Submission", "Email"),
        993: ("IMAPS", "Email"),
        995: ("POP3S", "Email"),
        
        # File Transfer
        20: ("FTP-Data", "FileTransfer"),
        21: ("FTP", "FileTransfer"),
        22: ("SSH", "RemoteAccess"),
        23: ("Telnet", "RemoteAccess"),
        69: ("TFTP", "FileTransfer"),
        115: ("SFTP", "FileTransfer"),
        
        # Messaging & VoIP
        5060: ("SIP", "VoIP"),
        5061: ("SIPS", "VoIP"),
        5222: ("XMPP", "Messaging"),
        5223: ("XMPP-SSL", "Messaging"),
        6667: ("IRC", "Messaging"),
        6697: ("IRC-SSL", "Messaging"),
        1863: ("MSN", "Messaging"),
        5190: ("AIM/ICQ", "Messaging"),
        
        # Gaming
        3074: ("Xbox-Live", "Gaming"),
        1935: ("RTMP", "Streaming"),
        3478: ("STUN/TURN", "VoIP"),
        3479: ("STUN/TURN", "VoIP"),
        3724: ("World-of-Warcraft", "Gaming"),
        6112: ("Battle.net", "Gaming"),
        25565: ("Minecraft", "Gaming"),
        27015: ("Steam", "Gaming"),
        
        # Streaming
        554: ("RTSP", "Streaming"),
        1935: ("RTMP", "Streaming"),
        8554: ("RTSP-Alt", "Streaming"),
        
        # Database
        1433: ("MSSQL", "Database"),
        1521: ("Oracle", "Database"),
        3306: ("MySQL", "Database"),
        5432: ("PostgreSQL", "Database"),
        6379: ("Redis", "Database"),
        7000: ("Cassandra", "Database"),
        7001: ("Cassandra-SSL", "Database"),
        9042: ("Cassandra-Native", "Database"),
        27017: ("MongoDB", "Database"),
        
        # Remote Desktop
        3389: ("RDP", "RemoteAccess"),
        5900: ("VNC", "RemoteAccess"),
        5901: ("VNC-1", "RemoteAccess"),
        
        # Network Services
        53: ("DNS", "Network"),
        67: ("DHCP-Server", "Network"),
        68: ("DHCP-Client", "Network"),
        123: ("NTP", "Network"),
        161: ("SNMP", "Network"),
        162: ("SNMP-Trap", "Network"),
        389: ("LDAP", "Network"),
        636: ("LDAPS", "Network"),
        
        # File Sharing
        137: ("NetBIOS-NS", "FileSharing"),
        138: ("NetBIOS-DGM", "FileSharing"),
        139: ("NetBIOS-SSN", "FileSharing"),
        445: ("SMB", "FileSharing"),
        2049: ("NFS", "FileSharing"),
        
        # Development
        8000: ("HTTP-Dev", "Development"),
        8001: ("HTTP-Dev", "Development"),
        9000: ("SonarQube", "Development"),
        9090: ("Prometheus", "Monitoring"),
        9200: ("Elasticsearch", "Database"),
        
        # Cloud Services
        9418: ("Git", "Development"),
        11211: ("Memcached", "Database"),
    }
    
    # Domain patterns to application mappings
    DOMAIN_PATTERNS = {
        # Social Media
        r'facebook\.com|fbcdn\.net|fb\.com': ("Facebook", "SocialMedia"),
        r'twitter\.com|twimg\.com|t\.co': ("Twitter", "SocialMedia"),
        r'instagram\.com|cdninstagram\.com': ("Instagram", "SocialMedia"),
        r'linkedin\.com|licdn\.com': ("LinkedIn", "SocialMedia"),
        r'tiktok\.com|tiktokcdn\.com|musical\.ly': ("TikTok", "SocialMedia"),
        r'snapchat\.com|snap\.com|snapkit\.co': ("Snapchat", "SocialMedia"),
        r'reddit\.com|redd\.it|redditstatic\.com': ("Reddit", "SocialMedia"),
        r'pinterest\.com|pinimg\.com': ("Pinterest", "SocialMedia"),
        
        # Streaming
        r'youtube\.com|ytimg\.com|googlevideo\.com|youtu\.be': ("YouTube", "Streaming"),
        r'netflix\.com|nflximg\.com|nflxvideo\.net': ("Netflix", "Streaming"),
        r'twitch\.tv|ttvnw\.net|jtvnw\.net': ("Twitch", "Streaming"),
        r'spotify\.com|scdn\.co|spotifycdn\.com': ("Spotify", "Streaming"),
        r'hulu\.com|hulustream\.com': ("Hulu", "Streaming"),
        r'disney\.com|disneyplus\.com|dssott\.com': ("Disney+", "Streaming"),
        r'hbomax\.com|hbo\.com': ("HBO", "Streaming"),
        r'primevideo\.com|amazonvideo\.com': ("PrimeVideo", "Streaming"),
        r'apple\.com.*music|itunes\.apple\.com': ("AppleMusic", "Streaming"),
        r'soundcloud\.com|sndcdn\.com': ("SoundCloud", "Streaming"),
        
        # Messaging
        r'whatsapp\.com|whatsapp\.net': ("WhatsApp", "Messaging"),
        r'telegram\.org|telegram\.me|t\.me': ("Telegram", "Messaging"),
        r'discord\.com|discord\.gg|discordapp\.com': ("Discord", "Messaging"),
        r'slack\.com|slack-edge\.com': ("Slack", "Messaging"),
        r'zoom\.us|zoom\.com': ("Zoom", "VideoConference"),
        r'teams\.microsoft\.com|teams\.cdn\.office\.net': ("Teams", "VideoConference"),
        r'meet\.google\.com': ("GoogleMeet", "VideoConference"),
        r'skype\.com': ("Skype", "VideoConference"),
        
        # Cloud Services
        r'amazonaws\.com|aws\.amazon\.com': ("AWS", "CloudServices"),
        r'azure\.com|azurewebsites\.net|blob\.core\.windows\.net': ("Azure", "CloudServices"),
        r'googleapis\.com|googleusercontent\.com|gstatic\.com': ("Google", "CloudServices"),
        r'cloudflare\.com|cloudflareinsights\.com': ("Cloudflare", "CDN"),
        r'akamai\.com|akamaihd\.net|akamaitechnologies\.com': ("Akamai", "CDN"),
        r'fastly\.net|fastlylb\.net': ("Fastly", "CDN"),
        r'cloudfront\.net': ("CloudFront", "CDN"),
        
        # Shopping
        r'amazon\.com|amazon\.[a-z]{2,3}|amazonservices\.com': ("Amazon", "Shopping"),
        r'ebay\.com|ebaystatic\.com|ebayimg\.com': ("eBay", "Shopping"),
        r'aliexpress\.com|alibaba\.com|aliyun\.com': ("Alibaba", "Shopping"),
        r'shopify\.com|myshopify\.com': ("Shopify", "Shopping"),
        r'walmart\.com|walmartimages\.com': ("Walmart", "Shopping"),
        
        # Gaming
        r'steampowered\.com|steamcommunity\.com|steamstatic\.com': ("Steam", "Gaming"),
        r'epicgames\.com|unrealengine\.com': ("EpicGames", "Gaming"),
        r'battle\.net|blizzard\.com': ("Blizzard", "Gaming"),
        r'leagueoflegends\.com|riotgames\.com': ("RiotGames", "Gaming"),
        r'minecraft\.net|mojang\.com': ("Minecraft", "Gaming"),
        r'ea\.com|origin\.com': ("EA", "Gaming"),
        r'ubisoft\.com|ubi\.com': ("Ubisoft", "Gaming"),
        r'playstation\.com|sony\.com': ("PlayStation", "Gaming"),
        r'xbox\.com|xboxlive\.com': ("Xbox", "Gaming"),
        
        # Productivity
        r'office\.com|office365\.com|outlook\.com': ("Office365", "Productivity"),
        r'google\.com.*docs|drive\.google\.com': ("GoogleDocs", "Productivity"),
        r'dropbox\.com|dropboxstatic\.com': ("Dropbox", "CloudStorage"),
        r'box\.com|boxcdn\.net': ("Box", "CloudStorage"),
        r'onedrive\.com|onedrive\.live\.com': ("OneDrive", "CloudStorage"),
        r'github\.com|githubusercontent\.com|githubassets\.com': ("GitHub", "Development"),
        r'gitlab\.com': ("GitLab", "Development"),
        r'bitbucket\.org|atlassian\.com': ("Atlassian", "Development"),
        
        # News & Media
        r'cnn\.com|cnn\.io': ("CNN", "News"),
        r'bbc\.com|bbc\.co\.uk|bbci\.co\.uk': ("BBC", "News"),
        r'nytimes\.com|nyt\.com': ("NYTimes", "News"),
        r'foxnews\.com|foxbusiness\.com': ("FoxNews", "News"),
        r'reuters\.com|thomsonreuters\.com': ("Reuters", "News"),
        
        # Adult Content (for filtering)
        r'pornhub\.com|xvideos\.com|xhamster\.com': ("Adult", "Adult"),
        
        # Ads & Tracking
        r'doubleclick\.net|googleadservices\.com|googlesyndication\.com': ("GoogleAds", "Advertising"),
        r'facebook\.com.*tr|fbcdn\.net.*tracking': ("FacebookTracking", "Tracking"),
        r'google-analytics\.com|googletagmanager\.com': ("GoogleAnalytics", "Analytics"),
        r'scorecardresearch\.com|quantserve\.com': ("Analytics", "Analytics"),
        r'amazon-adsystem\.com': ("AmazonAds", "Advertising"),
    }
    
    # IP range patterns for major services
    IP_RANGES = {
        # Google
        "8.8.": ("Google-DNS", "Network"),
        "8.34.": ("Google", "CloudServices"),
        "35.": ("Google-Cloud", "CloudServices"),
        "74.125.": ("Google", "CloudServices"),
        "142.250.": ("Google", "CloudServices"),
        "172.217.": ("Google", "CloudServices"),
        "216.58.": ("Google", "CloudServices"),
        
        # Cloudflare
        "1.0.0.": ("Cloudflare-DNS", "Network"),
        "1.1.1.": ("Cloudflare-DNS", "Network"),
        "104.16.": ("Cloudflare", "CDN"),
        "104.17.": ("Cloudflare", "CDN"),
        "104.18.": ("Cloudflare", "CDN"),
        "104.19.": ("Cloudflare", "CDN"),
        "172.64.": ("Cloudflare", "CDN"),
        "172.65.": ("Cloudflare", "CDN"),
        "172.66.": ("Cloudflare", "CDN"),
        "172.67.": ("Cloudflare", "CDN"),
        
        # AWS
        "52.": ("AWS", "CloudServices"),
        "54.": ("AWS", "CloudServices"),
        "18.": ("AWS", "CloudServices"),
        "3.": ("AWS", "CloudServices"),
        "13.": ("AWS", "CloudServices"),
        
        # Microsoft/Azure
        "13.64.": ("Azure", "CloudServices"),
        "13.65.": ("Azure", "CloudServices"),
        "13.66.": ("Azure", "CloudServices"),
        "13.67.": ("Azure", "CloudServices"),
        "13.68.": ("Azure", "CloudServices"),
        "13.69.": ("Azure", "CloudServices"),
        "13.70.": ("Azure", "CloudServices"),
        "13.71.": ("Azure", "CloudServices"),
        "13.72.": ("Azure", "CloudServices"),
        "13.73.": ("Azure", "CloudServices"),
        "20.": ("Azure", "CloudServices"),
        "40.": ("Azure", "CloudServices"),
        "52.96.": ("Office365", "Productivity"),
        "52.97.": ("Office365", "Productivity"),
        "52.98.": ("Office365", "Productivity"),
        "52.99.": ("Office365", "Productivity"),
        "52.100.": ("Office365", "Productivity"),
        "52.101.": ("Office365", "Productivity"),
        "52.102.": ("Office365", "Productivity"),
        "52.103.": ("Office365", "Productivity"),
        "52.104.": ("Office365", "Productivity"),
        "52.105.": ("Office365", "Productivity"),
        "52.106.": ("Office365", "Productivity"),
        "52.107.": ("Office365", "Productivity"),
        "52.108.": ("Office365", "Productivity"),
        "52.109.": ("Office365", "Productivity"),
        "52.110.": ("Office365", "Productivity"),
        "52.111.": ("Office365", "Productivity"),
        "52.112.": ("Office365", "Productivity"),
        "52.113.": ("Office365", "Productivity"),
        "52.114.": ("Office365", "Productivity"),
        "52.115.": ("Office365", "Productivity"),
        
        # Facebook/Meta
        "31.13.": ("Facebook", "SocialMedia"),
        "66.220.": ("Facebook", "SocialMedia"),
        "69.63.": ("Facebook", "SocialMedia"),
        "69.171.": ("Facebook", "SocialMedia"),
        "74.119.": ("Facebook", "SocialMedia"),
        "157.240.": ("Facebook", "SocialMedia"),
        "179.60.": ("Facebook", "SocialMedia"),
        
        # Akamai
        "23.": ("Akamai", "CDN"),
        "104.": ("Various-CDN", "CDN"),
        "184.": ("Akamai", "CDN"),
    }
    
    @classmethod
    def classify_by_port(cls, port: int) -> Tuple[Optional[str], Optional[str]]:
        """Classify traffic by port number."""
        return cls.PORT_APPS.get(port, (None, None))
    
    @classmethod
    def classify_by_domain(cls, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify traffic by domain/hostname."""
        if not hostname:
            return (None, None)
        
        hostname_lower = hostname.lower()
        for pattern, (app, category) in cls.DOMAIN_PATTERNS.items():
            if re.search(pattern, hostname_lower):
                return (app, category)
        return (None, None)
    
    @classmethod
    def classify_by_ip(cls, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify traffic by IP address patterns."""
        if not ip:
            return (None, None)
        
        # Check IP prefixes
        for prefix, (app, category) in cls.IP_RANGES.items():
            if ip.startswith(prefix):
                return (app, category)
        return (None, None)
    
    @classmethod
    def classify(cls, dst_ip: str, dst_port: int, hostname: str = None, 
                 protocol: str = None) -> Dict[str, str]:
        """
        Classify network traffic based on available information.
        
        Returns:
            Dict with 'app', 'category', and 'confidence' keys
        """
        app = None
        category = None
        confidence = "low"
        
        # Try hostname-based classification first (most accurate)
        if hostname:
            app, category = cls.classify_by_domain(hostname)
            if app:
                confidence = "high"
        
        # Try port-based classification
        if not app and dst_port:
            app, category = cls.classify_by_port(dst_port)
            if app:
                confidence = "medium" if not hostname else "high"
        
        # Try IP-based classification as fallback
        if not app and dst_ip:
            app, category = cls.classify_by_ip(dst_ip)
            if app:
                confidence = "low"
        
        # Default classifications for common protocols
        if not app:
            if dst_port == 443 or protocol == "HTTPS":
                app = "HTTPS"
                category = "Web"
                confidence = "low"
            elif dst_port == 80 or protocol == "HTTP":
                app = "HTTP"
                category = "Web"
                confidence = "low"
            elif protocol:
                app = protocol
                category = "Network"
                confidence = "low"
        
        return {
            "app": app or "Unknown",
            "category": category or "Uncategorized",
            "confidence": confidence
        }
