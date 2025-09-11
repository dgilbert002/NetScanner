from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats, db
try:
    from src.models.settings import AppSettings
except Exception:
    AppSettings = None
from src.models.hostnames import HnCategory, HnApp, HnRule, bootstrap_defaults
import tldextract
from src.packet_capture import NetworkMonitor
from datetime import datetime, timedelta
import asyncio
import threading
import json

network_bp = Blueprint('network', __name__)

# Global network monitor instance
network_monitor = None
monitor_thread = None

def get_network_monitor():
    """Get or create network monitor instance"""
    global network_monitor
    if network_monitor is None:
        network_monitor = NetworkMonitor()
    return network_monitor

@network_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get all discovered devices for Devices tab."""
    try:
        devices = Device.query.all()
        rows = []
        for d in devices:
            rows.append({
                'id': getattr(d, 'id', None),
                'mac_address': getattr(d, 'mac_address', None),
                'ip_address': getattr(d, 'ip_address', None),
                'hostname': getattr(d, 'hostname', None),
                'vendor': getattr(d, 'vendor', None),
                'last_seen': (getattr(d, 'last_seen', None).isoformat() if getattr(d, 'last_seen', None) else None),
                'is_active': bool(getattr(d, 'is_active', False)),
            })
        return jsonify(rows)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/devices/<mac_address>', methods=['GET'])
def get_device(mac_address):
    """Get specific device details"""
    try:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        return jsonify(device.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/devices/<mac_address>', methods=['PUT'])
def update_device(mac_address):
    """Update device information"""
    try:
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            return jsonify({'error': 'Device not found'}), 404
            
        data = request.json
        if 'hostname' in data:
            device.hostname = data['hostname']
        if 'device_type' in data:
            device.device_type = data['device_type']
            
        db.session.commit()
        return jsonify(device.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/traffic/summary', methods=['GET'])
def get_traffic_summary():
    """Get traffic summary statistics"""
    try:
        # Get time range from query parameters
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Query traffic sessions
        sessions = TrafficSession.query.filter(
            TrafficSession.start_time >= since
        ).all()
        
        # Calculate summary statistics
        total_sessions = len(sessions)
        total_bytes = sum(s.bytes_sent + s.bytes_received for s in sessions)
        
        # Protocol breakdown
        protocols = {}
        for session in sessions:
            protocols[session.protocol] = protocols.get(session.protocol, 0) + 1
            
        # Top talkers
        device_traffic = {}
        for session in sessions:
            if session.src_mac:
                device_traffic[session.src_mac] = device_traffic.get(session.src_mac, 0) + session.bytes_sent
            if session.dst_mac:
                device_traffic[session.dst_mac] = device_traffic.get(session.dst_mac, 0) + session.bytes_received
                
        top_talkers = sorted(device_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return jsonify({
            'total_sessions': total_sessions,
            'total_bytes': total_bytes,
            'protocols': protocols,
            'top_talkers': [{'mac': mac, 'bytes': bytes_} for mac, bytes_ in top_talkers],
            'time_range_hours': hours
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/traffic/devices/<mac_address>', methods=['GET'])
def get_device_traffic(mac_address):
    """Get traffic for specific device"""
    try:
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        sessions = TrafficSession.query.filter(
            db.or_(
                TrafficSession.src_mac == mac_address,
                TrafficSession.dst_mac == mac_address
            ),
            TrafficSession.start_time >= since
        ).all()
        
        return jsonify([session.to_dict() for session in sessions])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/websites', methods=['GET'])
def get_website_visits():
    """Get website visits"""
    try:
        hours = request.args.get('hours', 24, type=int)
        device_mac = request.args.get('device_mac')
        since = datetime.utcnow() - timedelta(hours=hours)
        
        query = WebsiteVisit.query.filter(WebsiteVisit.timestamp >= since)
        
        if device_mac:
            query = query.filter(WebsiteVisit.device_mac == device_mac)
            
        visits = query.order_by(WebsiteVisit.timestamp.desc()).limit(1000).all()
        
        return jsonify([visit.to_dict() for visit in visits])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _extract_root_domain(hostname: str) -> str:
    if not hostname:
        return ''
    ext = tldextract.extract(hostname)
    root = '.'.join(p for p in [ext.domain, ext.suffix] if p)
    return root.lower()


@network_bp.route('/classify', methods=['POST'])
def classify_flow():
    """DNS/SNI-first classifier. Input: { hostname, sni, ip }
    Returns { category, app, rule_source, confidence }
    """
    data = request.get_json(force=True)
    hostname = (data.get('hostname') or data.get('sni') or '').lower()
    ip = (data.get('ip') or '').lower()
    print('classify_flow()', data)

    bootstrap_defaults()

    # 1) Domain rules (exact, then root)
    root = _extract_root_domain(hostname)
    if hostname:
        rule = HnRule.query.filter_by(type='domain', value=hostname).first()
        if not rule and root and root != hostname:
            rule = HnRule.query.filter_by(type='domain', value=root).first()
        if rule:
            app = HnApp.query.get(rule.app_id)
            cat = HnCategory.query.get(app.category_id) if app else None
            return jsonify({
                'category': cat.name if cat else 'Uncategorized',
                'app': app.name if app else 'Unknown',
                'rule_source': rule.source,
                'confidence': rule.confidence
            })

    # 2) IP rules
    if ip:
        rule = HnRule.query.filter_by(type='ip', value=ip).first()
        if rule:
            app = HnApp.query.get(rule.app_id)
            cat = HnCategory.query.get(app.category_id) if app else None
            return jsonify({
                'category': cat.name if cat else 'Uncategorized',
                'app': app.name if app else 'Unknown',
                'rule_source': rule.source,
                'confidence': rule.confidence
            })

    # 3) Fallback
    cat = HnCategory.query.filter_by(name='Uncategorized').first()
    app = HnApp.query.filter_by(name='Unknown').first()
    return jsonify({
        'category': cat.name if cat else 'Uncategorized',
        'app': app.name if app else 'Unknown',
        'rule_source': 'fallback',
        'confidence': 0.2
    })


def _classify_for_endpoint(hostname: str, ip: str):
    """Internal helper to classify quickly and return names and ids."""
    bootstrap_defaults()
    cat_name = 'Uncategorized'
    app_name = 'Unknown'
    cat_id = None
    app_id = None

    # Domain rules
    if hostname:
        host = hostname.lower()
        root = _extract_root_domain(host)
        rule = HnRule.query.filter_by(type='domain', value=host).first()
        if not rule and root and root != host:
            rule = HnRule.query.filter_by(type='domain', value=root).first()
        if rule:
            app = HnApp.query.get(rule.app_id)
            cat = HnCategory.query.get(app.category_id) if app else None
            if app:
                app_id, app_name = app.id, app.name
            if cat:
                cat_id, cat_name = cat.id, cat.name
            return cat_name, app_name, cat_id, app_id

    # IP rules
    if ip:
        rule = HnRule.query.filter_by(type='ip', value=ip).first()
        if rule:
            app = HnApp.query.get(rule.app_id)
            cat = HnCategory.query.get(app.category_id) if app else None
            if app:
                app_id, app_name = app.id, app.name
            if cat:
                cat_id, cat_name = cat.id, cat.name
            return cat_name, app_name, cat_id, app_id

    # Fallback
    cat = HnCategory.query.filter_by(name='Uncategorized').first()
    app = HnApp.query.filter_by(name='Unknown').first()
    if cat: cat_id = cat.id
    if app: app_id = app.id
    return cat_name, app_name, cat_id, app_id


@network_bp.route('/live/sessions', methods=['GET'])
def live_sessions():
    """Return recent sessions shaped for the Live table.
    Does minimal shaping; client performs filtering/sorting.
    """
    try:
        # timeframe: last 24h by default
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)

        q = TrafficSession.query.filter(TrafficSession.start_time >= since)
        q = q.order_by(TrafficSession.start_time.desc())
        sessions = q.limit(200).all()

        rows = []
        now = datetime.utcnow()
        idle_seconds = 90
        try:
            if AppSettings is not None:
                idle_seconds = AppSettings.get_or_create_defaults().session_idle_seconds or 90
        except Exception:
            pass

        for s in sessions:
            # Device friendly name
            dev = Device.query.filter_by(mac_address=s.src_mac).first()
            device_name = dev.hostname if dev and getattr(dev, 'hostname', None) else (s.src_ip or s.src_mac)
            device_ip = s.src_ip or ''

            # Destination enrichment
            enr = EnrichedData.query.filter_by(ip_address=s.dst_ip).first()
            hostname = enr.hostname if enr and enr.hostname else None
            organization = enr.organization if enr and getattr(enr, 'organization', None) else None
            asn = enr.asn if enr and getattr(enr, 'asn', None) else None
            root_domain = _extract_root_domain(hostname) if hostname else ''

            # Classify
            cat_name, app_name, cat_id, app_id = _classify_for_endpoint(hostname, s.dst_ip or '')

            # Duration and status (treat end_time as last_activity marker)
            last_seen_dt = (s.end_time or s.start_time or now)
            is_active = ((now - last_seen_dt).total_seconds() <= idle_seconds)
            duration_minutes = int(((last_seen_dt) - (s.start_time or last_seen_dt)).total_seconds() // 60)
            data_bytes = int((s.bytes_sent or 0) + (s.bytes_received or 0))

            # nDPI labels (if enabled) with fallback classifier
            ndpi_app = None
            ndpi_category = None
            ndpi_confidence = None
            try:
                # Try nDPI first
                from src.main import ndpi_worker
                if ndpi_worker and ndpi_worker.enabled:
                    lbl = ndpi_worker.get_label(s.src_ip, s.dst_ip, s.dst_port, s.protocol)
                    if lbl:
                        ndpi_app = lbl.get('app')
                        ndpi_category = lbl.get('category')
                        ndpi_confidence = lbl.get('confidence')
                
                # Fallback to traffic classifier if no nDPI results
                if not ndpi_app or not ndpi_category:
                    from src.traffic_classifier import TrafficClassifier
                    classification = TrafficClassifier.classify(
                        dst_ip=s.dst_ip,
                        dst_port=s.dst_port,
                        hostname=hostname if hostname else None,
                        protocol=s.protocol
                    )
                    if classification:
                        if not ndpi_app:
                            ndpi_app = classification.get('app')
                        if not ndpi_category:
                            ndpi_category = classification.get('category')
                        if not ndpi_confidence:
                            ndpi_confidence = classification.get('confidence')
            except Exception:
                pass

            rows.append({
                'device': device_name,
                'deviceIp': device_ip,
                'dstIp': s.dst_ip or '',
                'hostname': hostname or None,
                'organization': organization,
                'asn': asn,
                'countryCode': getattr(enr, 'country_code', None) if enr else None,
                'protocol': s.protocol,
                'srcPort': s.src_port,
                'dstPort': s.dst_port,
                'rootDomain': root_domain,
                'isEncrypted': bool((s.dst_port or 0) == 443),
                'ndpi_app': ndpi_app,
                'ndpi_category': ndpi_category,
                'ndpi_confidence': ndpi_confidence,
                'category': cat_name,
                'categoryId': cat_id or 0,
                'app': app_name,
                'appId': app_id or 0,
                'startTime': (s.start_time or now).isoformat(),
                'lastSeen': last_seen_dt.isoformat(),
                'duration': duration_minutes,
                'dataBytes': data_bytes,
                'isActive': bool(is_active)
            })

        return jsonify({'sessions': rows, 'count': len(rows), 'timestamp': now.isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/websites/top-domains', methods=['GET'])
def get_top_domains():
    """Get most visited domains"""
    try:
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Query to get domain visit counts
        result = db.session.query(
            WebsiteVisit.domain,
            db.func.count(WebsiteVisit.id).label('visit_count'),
            db.func.sum(WebsiteVisit.bytes_transferred).label('total_bytes')
        ).filter(
            WebsiteVisit.timestamp >= since
        ).group_by(
            WebsiteVisit.domain
        ).order_by(
            db.func.count(WebsiteVisit.id).desc()
        ).limit(20).all()
        
        domains = []
        for domain, visit_count, total_bytes in result:
            domains.append({
                'domain': domain,
                'visit_count': visit_count,
                'total_bytes': total_bytes or 0
            })
            
        return jsonify(domains)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/enrichment/<ip_address>', methods=['GET'])
def get_ip_enrichment(ip_address):
    """Get enriched data for IP address"""
    try:
        enriched = EnrichedData.query.filter_by(ip_address=ip_address).first()
        if not enriched:
            return jsonify({'error': 'No enrichment data found'}), 404
        return jsonify(enriched.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/stats/realtime', methods=['GET'])
def get_realtime_stats():
    """Get real-time monitoring statistics"""
    try:
        monitor = get_network_monitor()
        stats = monitor.get_stats()
        
        # Add database statistics
        stats['total_devices_db'] = Device.query.count()
        stats['active_devices_db'] = Device.query.filter_by(is_active=True).count()
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    try:
        global monitor_thread
        
        monitor = get_network_monitor()
        
        # Start monitoring in a separate thread
        def run_monitor():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(monitor.start_monitoring())
            
        if monitor_thread is None or not monitor_thread.is_alive():
            monitor_thread = threading.Thread(target=run_monitor, daemon=True)
            monitor_thread.start()
            
        return jsonify({'status': 'started', 'message': 'Network monitoring started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    try:
        monitor = get_network_monitor()
        
        # Stop monitoring
        asyncio.run(monitor.stop_monitoring())
        
        return jsonify({'status': 'stopped', 'message': 'Network monitoring stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Get monitoring status"""
    try:
        # Try to use real-time capture first
        from src.main import realtime_capture
        if realtime_capture and realtime_capture.running:
            return jsonify({
                'running': True,
                'interface': realtime_capture.interface,
                'stats': realtime_capture.get_stats()
            })
        
        # Fallback to regular monitor
        monitor = get_network_monitor()
        
        return jsonify({
            'running': monitor.running,
            'interface': monitor.capture_engine.interface,
            'stats': monitor.get_stats()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Real data generation from actual network monitoring
@network_bp.route('/demo/generate-data', methods=['POST'])
def generate_demo_data():
    """Generate real data from actual network monitoring"""
    try:
        # Start monitoring to get real data
        monitor = get_network_monitor()
        
        # Start monitoring if not already running
        if not monitor.running:
            asyncio.run(monitor.start_monitoring())
        
        # Get real statistics
        stats = monitor.get_stats()
        
        return jsonify({
            'message': 'Real network monitoring started - data will appear as you browse the web',
            'stats': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

