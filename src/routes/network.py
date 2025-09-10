from flask import Blueprint, jsonify, request
from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats, db
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
    """Get all discovered devices"""
    try:
        devices = Device.query.all()
        return jsonify([device.to_dict() for device in devices])
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

