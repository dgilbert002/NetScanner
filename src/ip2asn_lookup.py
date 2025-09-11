import os
import ipaddress


class Ip2AsnDB:
    """Lightweight offline ASN lookup from ip2asn TSV file.

    Supported formats (best-effort):
    - start_uint32<TAB>end_uint32<TAB>AS<TAB>country<TAB>registry<TAB>allocated<TAB>asn_name
    - start_uint32<TAB>end_uint32<TAB>country<TAB>AS<TAB>asn_name
    - start_ip<TAB>end_ip<TAB>AS<TAB>country<TAB>asn_name
    Any additional trailing fields are ignored.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.ranges = []  # list of (start_int, end_int, asn_int, country, asn_name)
        if os.path.exists(self.file_path):
            self._load()

    def _parse_asn(self, token: str):
        s = str(token).strip().upper()
        if s.startswith('AS'):
            s = s[2:]
        digits = ''.join(ch for ch in s if ch.isdigit())
        return int(digits) if digits else None

    def _ip_to_int(self, token: str):
        try:
            return int(ipaddress.ip_address(token))
        except Exception:
            return None

    def _load(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t') if '\t' in line else line.split('|') if '|' in line else line.split()
                    if len(parts) < 4:
                        continue
                    # Try uint32 start/end first
                    start_int = None
                    end_int = None
                    try:
                        start_int = int(parts[0])
                        end_int = int(parts[1])
                    except Exception:
                        # Try dotted IPs
                        start_int = self._ip_to_int(parts[0])
                        end_int = self._ip_to_int(parts[1])
                    if start_int is None or end_int is None:
                        continue

                    # Heuristics to find ASN and country
                    asn = None
                    country = None
                    asn_name = None
                    # Look for a token that looks like ASN in the first 5 tokens
                    for i in range(2, min(len(parts), 7)):
                        if asn is None:
                            a = self._parse_asn(parts[i])
                            if a is not None:
                                asn = a
                                continue
                        if country is None and len(parts[i]) in (2, 3) and parts[i].isalpha():
                            country = parts[i].upper()
                    # ASN name likely last token
                    if len(parts) >= 5:
                        asn_name = parts[-1]

                    if asn is None:
                        continue

                    self.ranges.append((start_int, end_int, asn, country, asn_name))
            # Sort by start_int for binary search
            self.ranges.sort(key=lambda r: r[0])
        except Exception:
            self.ranges = []

    def lookup(self, ip: str):
        if not self.ranges:
            return None
        try:
            ip_int = int(ipaddress.ip_address(ip))
        except Exception:
            return None
        # Binary search over ranges
        lo, hi = 0, len(self.ranges) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, asn, country, asn_name = self.ranges[mid]
            if ip_int < start:
                hi = mid - 1
            elif ip_int > end:
                lo = mid + 1
            else:
                return {
                    'asn': asn,
                    'country': country,
                    'organization': asn_name
                }
        return None


