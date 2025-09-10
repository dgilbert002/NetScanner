"""
Comprehensive API routes for advanced analytics and monitoring
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from src.comprehensive_analytics import ComprehensiveAnalytics
import json
import os

# Check if enhanced features should be enabled
ENABLE_ENHANCED = os.getenv('ENABLE_ENHANCED', '0').lower() in ('1', 'true', 'yes')

if ENABLE_ENHANCED:
    try:
        from src.models.enhanced_network import (
            User, Device, TrafficSession, WebsiteVisit, 
            UserSession, db
        )
    except ImportError:
        # Fallback to base models
        from src.models.network import Device, TrafficSession, WebsiteVisit
        from src.models.user import User, db
        # Create dummy class for enhanced features
        class UserSession:
            pass
else:
    # Use base models only
    from src.models.network import Device, TrafficSession, WebsiteVisit
    from src.models.user import User, db
    # Create dummy class for enhanced features
    class UserSession:
        pass

comprehensive_bp = Blueprint('comprehensive', __name__)
analytics = ComprehensiveAnalytics()

@comprehensive_bp.route('/api/v2/users', methods=['GET'])
def get_users():
    """Get all users with their device counts"""
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'full_name': u.full_name,
        'email': u.email,
        'role': u.role,
        'device_count': len(u.devices),
        'is_active': u.is_active
    } for u in users])

@comprehensive_bp.route('/api/v2/users/<int:user_id>/analytics', methods=['GET'])
def get_user_analytics(user_id):
    """Get comprehensive analytics for a specific user"""
    period = request.args.get('period', '24h')
    group_by = request.args.get('group_by', 'hour')
    
    data = analytics.get_user_analytics(user_id, period, group_by)
    if data:
        return jsonify(data)
    return jsonify({'error': 'User not found'}), 404

@comprehensive_bp.route('/api/v2/devices', methods=['GET'])
def get_devices():
    """Get all devices with enriched information"""
    devices = Device.query.all()
    result = []
    for d in devices:
        device_info = {
            'id': d.id,
            'mac_address': d.mac_address,
            'ip_address': d.ip_address,
            'hostname': d.hostname,
            'device_type': d.device_type,
            'vendor': d.vendor,
            'is_active': d.is_active,
            'last_seen': d.last_seen.isoformat() if d.last_seen else None
        }
        
        # Add enhanced fields if available
        if hasattr(d, 'device_name'):
            device_info['device_name'] = d.device_name or d.hostname
        else:
            device_info['device_name'] = d.hostname
            
        if hasattr(d, 'operating_system'):
            device_info['os'] = d.operating_system
        else:
            device_info['os'] = 'Unknown'
            
        if hasattr(d, 'assigned_user'):
            device_info['user'] = d.assigned_user.username if d.assigned_user else None
        else:
            device_info['user'] = None
            
        if hasattr(d, 'user_id'):
            device_info['user_id'] = d.user_id
        else:
            device_info['user_id'] = None
            
        result.append(device_info)
        
    return jsonify(result)

@comprehensive_bp.route('/api/v2/devices/<int:device_id>/analytics', methods=['GET'])
def get_device_analytics(device_id):
    """Get detailed analytics for a specific device"""
    period = request.args.get('period', '24h')
    
    data = analytics.get_device_analytics(device_id=device_id, period=period)
    if data:
        return jsonify(data)
    return jsonify({'error': 'Device not found'}), 404

@comprehensive_bp.route('/api/v2/devices/<int:device_id>/assign', methods=['POST'])
def assign_device_to_user(device_id):
    """Assign a device to a user"""
    data = request.get_json()
    user_id = data.get('user_id')
    
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
        
    if user_id:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        device.user_id = user_id
        device.assigned_user = user
    else:
        device.user_id = None
        device.assigned_user = None
        
    db.session.commit()
    return jsonify({'message': 'Device assignment updated'})

@comprehensive_bp.route('/api/v2/groups', methods=['GET'])
def get_groups():
    """Get device groups (by user)"""
    users = User.query.filter(User.devices.any()).all()
    groups = []
    
    for user in users:
        groups.append({
            'id': f'user-{user.id}',
            'name': f"{user.full_name}'s Devices",
            'type': 'user',
            'device_count': len(user.devices),
            'devices': [d.id for d in user.devices],
            'user_id': user.id
        })
        
    # Add department groups if users have departments
    departments = {}
    for user in User.query.all():
        dept = getattr(user, 'department', 'General')
        if dept not in departments:
            departments[dept] = []
        departments[dept].extend([d.id for d in user.devices])
        
    for dept, device_ids in departments.items():
        if device_ids:
            groups.append({
                'id': f'dept-{dept.lower()}',
                'name': f"{dept} Department",
                'type': 'department',
                'device_count': len(device_ids),
                'devices': device_ids
            })
            
    return jsonify(groups)

@comprehensive_bp.route('/api/v2/groups/<group_id>/analytics', methods=['GET'])
def get_group_analytics(group_id):
    """Get analytics for a group of devices"""
    period = request.args.get('period', '24h')
    
    # Parse group ID
    if group_id.startswith('user-'):
        user_id = int(group_id.replace('user-', ''))
        user = User.query.get(user_id)
        if user:
            data = analytics.get_group_analytics(
                f"{user.full_name}'s Devices",
                user_ids=[user_id],
                period=period
            )
            return jsonify(data)
            
    elif group_id.startswith('dept-'):
        dept = group_id.replace('dept-', '').title()
        users = User.query.filter_by(department=dept).all()
        if users:
            data = analytics.get_group_analytics(
                f"{dept} Department",
                user_ids=[u.id for u in users],
                period=period
            )
            return jsonify(data)
            
    return jsonify({'error': 'Group not found'}), 404

@comprehensive_bp.route('/api/v2/applications', methods=['GET'])
def get_applications():
    """Get list of all detected applications"""
    # Check if we have enhanced models with application field
    if ENABLE_ENHANCED and hasattr(TrafficSession, 'application'):
        # Get unique applications from sessions
        apps = db.session.query(TrafficSession.application).distinct().all()
        app_list = [app[0] for app in apps if app[0]]
        
        # Get statistics for each app
        app_stats = []
        for app_name in app_list:
            sessions = TrafficSession.query.filter_by(application=app_name).all()
            total_bytes = sum(s.bytes_sent + s.bytes_received for s in sessions)
            
            app_stats.append({
                'name': app_name,
                'total_bytes': total_bytes,
                'session_count': len(sessions),
                'category': analytics._get_app_category(app_name) if hasattr(analytics, '_get_app_category') else 'Unknown'
            })
        
        return jsonify(sorted(app_stats, key=lambda x: x['total_bytes'], reverse=True))
    else:
        # Return empty list for base models
        return jsonify([])

@comprehensive_bp.route('/api/v2/applications/<app_name>/analytics', methods=['GET'])
def get_application_analytics(app_name):
    """Get detailed analytics for a specific application"""
    period = request.args.get('period', '24h')
    
    data = analytics.get_application_analytics(app_name, period)
    if data:
        return jsonify(data)
    return jsonify({'error': 'Application not found'}), 404

@comprehensive_bp.route('/api/v2/traffic/live', methods=['GET'])
def get_live_traffic():
    """Get live traffic data (last 5 minutes)"""
    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    
    sessions = TrafficSession.query.filter(
        TrafficSession.start_time >= five_min_ago
    ).order_by(TrafficSession.start_time.desc()).limit(100).all()
    
    return jsonify([{
        'id': s.id,
        'time': s.start_time.isoformat(),
        'src_ip': s.src_ip,
        'dst_ip': s.dst_ip,
        'src_port': s.src_port,
        'dst_port': s.dst_port,
        'protocol': s.protocol,
        'bytes': s.bytes_sent + s.bytes_received,
        'application': s.application,
        'device': Device.query.filter_by(mac_address=s.src_mac).first().device_name 
                  if Device.query.filter_by(mac_address=s.src_mac).first() else s.src_mac
    } for s in sessions])

@comprehensive_bp.route('/api/v2/traffic/summary', methods=['GET'])
def get_traffic_summary():
    """Get traffic summary with multiple time ranges"""
    now = datetime.utcnow()
    
    # Calculate for different time ranges
    ranges = {
        'last_hour': now - timedelta(hours=1),
        'last_24h': now - timedelta(hours=24),
        'last_7d': now - timedelta(days=7),
        'last_30d': now - timedelta(days=30)
    }
    
    summary = {}
    for range_name, start_time in ranges.items():
        sessions = TrafficSession.query.filter(
            TrafficSession.start_time >= start_time
        ).all()
        
        total_bytes = sum(s.bytes_sent + s.bytes_received for s in sessions)
        
        summary[range_name] = {
            'total_bytes': total_bytes,
            'session_count': len(sessions),
            'unique_devices': len(set(s.src_mac for s in sessions)),
            'unique_destinations': len(set(s.dst_ip for s in sessions))
        }
        
    return jsonify(summary)

@comprehensive_bp.route('/api/v2/domains', methods=['GET'])
def get_domains():
    """Get all visited domains with statistics"""
    # Get time range
    hours = int(request.args.get('hours', 24))
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    visits = WebsiteVisit.query.filter(
        WebsiteVisit.timestamp >= start_time
    ).all()
    
    # Aggregate by domain
    domains = {}
    for visit in visits:
        domain = visit.domain
        if domain not in domains:
            domains[domain] = {
                'domain': domain,
                'visits': 0,
                'bytes': 0,
                'category': visit.category,
                'devices': set()
            }
        domains[domain]['visits'] += 1
        domains[domain]['bytes'] += visit.bytes_transferred
        domains[domain]['devices'].add(visit.device_mac)
        
    # Convert sets to counts
    for domain in domains.values():
        domain['device_count'] = len(domain['devices'])
        del domain['devices']
        
    return jsonify(sorted(domains.values(), key=lambda x: x['bytes'], reverse=True))

@comprehensive_bp.route('/api/v2/compare', methods=['POST'])
def compare_entities():
    """Compare multiple users, devices, or groups"""
    data = request.get_json()
    entity_type = data.get('type', 'user')
    entity_ids = data.get('ids', [])
    period = data.get('period', '7d')
    
    comparison = analytics.get_comparative_analytics(entity_type, entity_ids, period)
    if comparison:
        return jsonify(comparison)
    return jsonify({'error': 'No data for comparison'}), 404

@comprehensive_bp.route('/api/v2/trends/<entity_type>', methods=['GET'])
def get_trends(entity_type):
    """Get historical trends for system, user, or device"""
    entity_id = request.args.get('id')
    days = int(request.args.get('days', 30))
    
    trends = analytics.get_historical_trends(entity_type, entity_id, days)
    return jsonify(trends)

@comprehensive_bp.route('/api/v2/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Get current monitoring status"""
    from src.main import realtime_capture
    
    if realtime_capture:
        stats = realtime_capture.get_stats()
        return jsonify({
            'running': realtime_capture.running,
            'platform': realtime_capture.platform,
            'interface': realtime_capture.interface,
            'stats': stats
        })
    
    return jsonify({
        'running': False,
        'error': 'Monitoring not initialized'
    })

@comprehensive_bp.route('/api/v2/config/app-domains', methods=['GET'])
def get_app_domains():
    """Get application domain mappings"""
    try:
        with open('config/app_domains.json', 'r') as f:
            domains = json.load(f)
        return jsonify(domains)
    except:
        return jsonify({})

@comprehensive_bp.route('/api/v2/config/app-domains', methods=['POST'])
def update_app_domains():
    """Update application domain mappings"""
    data = request.get_json()
    
    try:
        with open('config/app_domains.json', 'w') as f:
            json.dump(data, f, indent=2)
            
        # Reload in capture engine
        from src.main import realtime_capture
        if realtime_capture:
            realtime_capture.app_mappings = data
            
        return jsonify({'message': 'Domain mappings updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/api/v2/export/<format>', methods=['GET'])
def export_data(format):
    """Export data in various formats (csv, json)"""
    entity = request.args.get('entity', 'traffic')
    period = request.args.get('period', '24h')
    
    start_time = analytics._get_time_range(period)
    
    if entity == 'traffic':
        sessions = TrafficSession.query.filter(
            TrafficSession.start_time >= start_time
        ).all()
        
        data = [{
            'timestamp': s.start_time.isoformat(),
            'src_ip': s.src_ip,
            'dst_ip': s.dst_ip,
            'protocol': s.protocol,
            'bytes': s.bytes_sent + s.bytes_received,
            'application': s.application
        } for s in sessions]
        
    elif entity == 'devices':
        devices = Device.query.all()
        data = [d.to_dict() for d in devices]
        
    elif entity == 'users':
        users = User.query.all()
        data = [u.to_dict() for u in users]
        
    else:
        return jsonify({'error': 'Invalid entity'}), 400
        
    if format == 'json':
        return jsonify(data)
    elif format == 'csv':
        # Convert to CSV
        import csv
        import io
        
        if not data:
            return '', 204
            
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename={entity}_{period}.csv'
        }
        
    return jsonify({'error': 'Invalid format'}), 400
