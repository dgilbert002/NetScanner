"""Protocol parsing tests: DNS, TLS ClientHello, QUIC, DHCP, HTTP."""

import struct

from src.intel.flow import (
    decode_qname,
    parse_dhcp_options,
    parse_dns_message,
    parse_http_request,
    parse_tls_client_hello,
    is_quic,
    scan_for_client_hello,
    PacketExtractor,
)


def build_tls_client_hello(sni='example.com', ciphers=(0x1301, 0x1302, 0xC02B)):
    """Build a minimal but valid TLS 1.2/1.3 ClientHello record."""
    server_name = sni.encode()
    # server_name extension
    sni_ext = struct.pack('!H', 0x0000) + struct.pack('!H', len(server_name) + 5)
    sni_ext += struct.pack('!H', len(server_name) + 3) + b'\x00' + struct.pack('!H', len(server_name)) + server_name
    # supported_versions extension (TLS1.3 + 1.2)
    versions = b'\x03\x04\x03\x03'
    sv_ext = struct.pack('!HH', 0x002B, len(versions) + 1) + bytes([len(versions)]) + versions
    # supported_groups
    groups = struct.pack('!HH', 0x001D, 0x0017)
    sg_ext = struct.pack('!HH', 0x000A, len(groups) + 2) + struct.pack('!H', len(groups)) + groups
    # ec point formats
    ec_ext = struct.pack('!HH', 0x000B, 2) + b'\x01\x00'
    extensions = sni_ext + sv_ext + sg_ext + ec_ext

    body = b'\x03\x03' + b'\x11' * 32          # legacy_version + random
    session_id = b'\x00' * 0
    body += bytes([len(session_id)]) + session_id
    cipher_bytes = b''.join(struct.pack('!H', c) for c in ciphers)
    body += struct.pack('!H', len(cipher_bytes)) + cipher_bytes
    body += b'\x01\x00'                        # one compression method: null
    body += struct.pack('!H', len(extensions)) + extensions

    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    record = b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake
    return record


def test_tls_sni_extraction():
    record = build_tls_client_hello('www.netflix.com')
    parsed = parse_tls_client_hello(record)
    assert parsed is not None
    assert parsed['sni'] == 'www.netflix.com'
    assert parsed['cipher_count'] == 3
    assert len(parsed['ja3']) == 32
    assert 0x0000 in parsed['extensions'] or parsed['extensions']


def test_tls_scan_finds_hello_inside_quic_payload():
    """QUIC carries the ClientHello inside CRYPTO frames - the scanner must find it."""
    inner = build_tls_client_hello('cdn.instagram.com')
    fake_quic = b'\xc3\x00\x00\x00\x01' + b'\x08' + b'\x01' * 8 + b'\x00' + b'\x40\x50'
    fake_quic += b'\x06\x00\x40\x7a' + inner           # CRYPTO frame-ish
    parsed = scan_for_client_hello(fake_quic)
    assert parsed is not None
    assert parsed['sni'] == 'cdn.instagram.com'


def test_quic_header_detection():
    assert is_quic(b'\xc0\x00\x00\x00\x01' + b'\x00' * 10)
    assert not is_quic(b'\x45\x00\x00' + b'\x00' * 10)


def test_dns_message_parsing():
    # Header: id, flags (standard response), qd=1 an=1
    header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b'\x03www\x06google\x03com\x00'
    question = qname + struct.pack('!HH', 1, 1)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([142, 250, 80, 46])
    parsed = parse_dns_message(header + question + answer)
    assert parsed['questions'][0][0] == 'www.google.com'
    assert parsed['answers'][0] == ('www.google.com', 'A', '142.250.80.46')


def test_qname_compression_guard():
    data = b'\x03www\x07example\x03com\x00'
    name, offset = decode_qname(data, 0)
    assert name == 'www.example.com'
    assert offset == len(data)
    # A pointer loop must not hang
    loop = b'\xc0\x00'
    name, _offset = decode_qname(loop, 0)
    assert name == ''


def test_http_request_parsing():
    payload = (b'GET /watch?v=abc HTTP/1.1\r\nHost: www.youtube.com\r\n'
               b'User-Agent: Mozilla/5.0 (iPhone)\r\nReferer: https://google.com/\r\n\r\n')
    parsed = parse_http_request(payload)
    assert parsed['host'] == 'www.youtube.com'
    assert parsed['path'] == '/watch?v=abc'
    assert 'iPhone' in parsed['user_agent']
    assert parse_http_request(b'\x16\x03\x01\x00\x00') is None


def test_dhcp_option_parsing():
    payload = bytearray(240)
    payload[28:34] = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    payload[236:240] = b'\x63\x82\x53\x63'
    payload += bytes([12, 10]) + b'Maries-iPhone'[:10]
    payload += bytes([60, 8]) + b'android!'
    payload += bytes([255])
    parsed = parse_dhcp_options(bytes(payload))
    assert parsed['client_mac'] == 'aa:bb:cc:dd:ee:ff'
    assert parsed['hostname'].startswith('Maries-iPh')
    assert parsed['vendor_class'] == 'android!'


def test_extractor_reverse_evidence_keeps_name():
    extractor = PacketExtractor(local_networks=['192.168.1.0/24'])
    assert extractor.is_local('192.168.1.22')
    assert not extractor.is_local('8.8.8.8')
    extractor.remember_name('203.0.113.5', 'example.com')
    assert extractor.name_for_ip('203.0.113.5') == 'example.com'
