from flask import Blueprint, request, jsonify
from src.models.enhanced_network import Device, TrafficSession, WebsiteVisit, ContentAnalysis, NetworkStats, EnrichedData, User, db
from datetime import datetime, timedelta
import json

enhanced_network_bp = Blueprint('enhanced_network', __name__)

# Time-based filtering helper
def get_time_filter():
    """Get time filter from request parameters"""
    period = request.args.get('period', '24h')
    
    if period == '1h':
        start_time = datetime.utcnow() - timedelta(hours=1)
    elif period == '24h':
        start_time = datetime.utcnow() - timedelta(hours=24)
    elif period == '7d':
        start_time = datetime.utcnow() - timedelta(days=7)
    elif period == '30d':
        start_time = datetime.utcnow() - timedelta(days=30)
    else:
        # Custom date range
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if start_date:
            start_time = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        else:
            start_time = datetime.utcnow() - timedelta(hours=24)
    
    return start_time

# Enhanced device management
@enhanced_network_bp.route('/devices/enhanced', methods=['GET'])
def get_enhanced_devices():
    """Get devices with enhanced information and filtering"""
    user_id = request.args.get('user_id', type=int)
    device_type = request.args.get('device_type')
    is_active = request.args.get('is_active', type=bool)
    
    query = Device.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if device_type:
        query = query.filter_by(device_type=device_type)
    
    if is_active is not None:
        query = query.filter_by(is_active=is_active)
    
    devices = query.all()
    
    # Add usage statistics for each device
    start_time = get_time_filter()
    
    enhanced_devices = []
    for device in devices:
        device_dict = device.to_dict()
        
        # Calculate usage statistics
        traffic_stats = db.session.query(
            db.func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('total_bytes'),
            db.func.count(TrafficSession.id).label('session_count')
        ).filter(
            TrafficSession.src_mac == device.mac_address,
            TrafficSession.start_time >= start_time
        ).first()
        
        website_count = WebsiteVisit.query.filter(
            WebsiteVisit.device_mac == device.mac_address,
            WebsiteVisit.timestamp >= start_time
        ).count()
        
        device_dict['usage_stats'] = {
            'total_bytes': traffic_stats.total_bytes or 0,
            'session_count': traffic_stats.session_count or 0,
            'website_visits': website_count,
            'period': request.args.get('period', '24h')
        }
        
        enhanced_devices.append(device_dict)
    
    return jsonify({
        'devices': enhanced_devices,
        'count': len(enhanced_devices)
    })

@enhanced_network_bp.route('/devices/<int:device_id>/update', methods=['PUT'])
def update_device(device_id):
    """Update device information"""
    device = Device.query.get_or_404(device_id)
    data = request.get_json()
    
    try:
        # Update allowed fields
        if 'device_name' in data:
            device.device_name = data['device_name']
        
        if 'device_type' in data:
            device.device_type = data['device_type']
        
        if 'operating_system' in data:
            device.operating_system = data['operating_system']
        
        if 'manufacturer' in data:
            device.manufacturer = data['manufacturer']
        
        if 'model' in data:
            device.model = data['model']
        
        if 'user_id' in data:
            device.user_id = data['user_id']
        
        device.last_seen = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Device updated successfully',
            'device': device.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Enhanced traffic analysis
@enhanced_network_bp.route('/traffic/analysis', methods=['GET'])
def get_traffic_analysis():
    """Get detailed traffic analysis with time-based filtering"""
    start_time = get_time_filter()
    user_id = request.args.get('user_id', type=int)
    device_id = request.args.get('device_id', type=int)
    
    query = TrafficSession.query.filter(TrafficSession.start_time >= start_time)
    
    # Apply user filter
    if user_id:
        user_devices = Device.query.filter_by(user_id=user_id).all()
        device_macs = [device.mac_address for device in user_devices]
        query = query.filter(TrafficSession.src_mac.in_(device_macs))
    
    # Apply device filter
    if device_id:
        device = Device.query.get(device_id)
        if device:
            query = query.filter_by(src_mac=device.mac_address)
    
    sessions = query.all()
    
    # Calculate statistics
    total_bytes = sum(session.bytes_sent + session.bytes_received for session in sessions)
    total_sessions = len(sessions)
    
    # Protocol distribution
    protocol_stats = {}
    for session in sessions:
        protocol = session.protocol
        if protocol not in protocol_stats:
            protocol_stats[protocol] = {'count': 0, 'bytes': 0}
        protocol_stats[protocol]['count'] += 1
        protocol_stats[protocol]['bytes'] += session.bytes_sent + session.bytes_received
    
    # Application distribution
    app_stats = {}
    for session in sessions:
        app = session.application or 'Unknown'
        if app not in app_stats:
            app_stats[app] = {'count': 0, 'bytes': 0}
        app_stats[app]['count'] += 1
        app_stats[app]['bytes'] += session.bytes_sent + session.bytes_received
    
    # Top destinations
    dest_stats = {}
    for session in sessions:
        dest = session.dst_ip
        if dest not in dest_stats:
            dest_stats[dest] = {'count': 0, 'bytes': 0}
        dest_stats[dest]['count'] += 1
        dest_stats[dest]['bytes'] += session.bytes_sent + session.bytes_received
    
    return jsonify({
        'summary': {
            'total_bytes': total_bytes,
            'total_sessions': total_sessions,
            'period': request.args.get('period', '24h'),
            'start_time': start_time.isoformat()
        },
        'protocol_distribution': protocol_stats,
        'application_distribution': app_stats,
        'top_destinations': dict(sorted(dest_stats.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10])
    })

# Enhanced website analytics
@enhanced_network_bp.route('/websites/analytics', methods=['GET'])
def get_website_analytics():
    """Get detailed website analytics with time-based filtering"""
    start_time = get_time_filter()
    user_id = request.args.get('user_id', type=int)
    device_id = request.args.get('device_id', type=int)
    category = request.args.get('category')
    
    query = WebsiteVisit.query.filter(WebsiteVisit.timestamp >= start_time)
    
    # Apply user filter
    if user_id:
        user_devices = Device.query.filter_by(user_id=user_id).all()
        device_macs = [device.mac_address for device in user_devices]
        query = query.filter(WebsiteVisit.device_mac.in_(device_macs))
    
    # Apply device filter
    if device_id:
        device = Device.query.get(device_id)
        if device:
            query = query.filter_by(device_mac=device.mac_address)
    
    # Apply category filter
    if category:
        query = query.filter_by(category=category)
    
    visits = query.all()
    
    # Calculate statistics
    total_visits = len(visits)
    total_bytes = sum(visit.bytes_transferred for visit in visits)
    total_duration = sum(visit.duration or 0 for visit in visits)
    
    # Domain statistics
    domain_stats = {}
    for visit in visits:
        domain = visit.domain
        if domain not in domain_stats:
            domain_stats[domain] = {
                'visits': 0,
                'bytes': 0,
                'duration': 0,
                'category': visit.category
            }
        domain_stats[domain]['visits'] += 1
        domain_stats[domain]['bytes'] += visit.bytes_transferred
        domain_stats[domain]['duration'] += visit.duration or 0
    
    # Category statistics
    category_stats = {}
    for visit in visits:
        cat = visit.category or 'Uncategorized'
        if cat not in category_stats:
            category_stats[cat] = {'visits': 0, 'bytes': 0, 'duration': 0}
        category_stats[cat]['visits'] += 1
        category_stats[cat]['bytes'] += visit.bytes_transferred
        category_stats[cat]['duration'] += visit.duration or 0
    
    # Time-based analysis (hourly breakdown)
    hourly_stats = {}
    for visit in visits:
        hour = visit.timestamp.hour
        if hour not in hourly_stats:
            hourly_stats[hour] = {'visits': 0, 'bytes': 0}
        hourly_stats[hour]['visits'] += 1
        hourly_stats[hour]['bytes'] += visit.bytes_transferred
    
    return jsonify({
        'summary': {
            'total_visits': total_visits,
            'total_bytes': total_bytes,
            'total_duration': total_duration,
            'average_duration': total_duration / total_visits if total_visits > 0 else 0,
            'period': request.args.get('period', '24h'),
            'start_time': start_time.isoformat()
        },
        'top_domains': dict(sorted(domain_stats.items(), key=lambda x: x[1]['visits'], reverse=True)[:20]),
        'category_distribution': category_stats,
        'hourly_breakdown': hourly_stats
    })

# Content analysis endpoints
@enhanced_network_bp.route('/content/analysis', methods=['GET'])
def get_content_analysis():
    """Get content analysis data with filtering"""
    start_time = get_time_filter()
    user_id = request.args.get('user_id', type=int)
    
    query = ContentAnalysis.query.join(WebsiteVisit).filter(
        WebsiteVisit.timestamp >= start_time
    )
    
    # Apply user filter
    if user_id:
        user_devices = Device.query.filter_by(user_id=user_id).all()
        device_macs = [device.mac_address for device in user_devices]
        query = query.filter(WebsiteVisit.device_mac.in_(device_macs))
    
    analyses = query.all()
    
    # Aggregate statistics
    total_analyses = len(analyses)
    avg_sentiment = sum(analysis.sentiment_score or 0 for analysis in analyses) / total_analyses if total_analyses > 0 else 0
    
    # Language distribution
    language_stats = {}
    for analysis in analyses:
        lang = analysis.language or 'Unknown'
        language_stats[lang] = language_stats.get(lang, 0) + 1
    
    # Content type statistics
    content_stats = {
        'total_images': sum(analysis.images_count for analysis in analyses),
        'total_links': sum(analysis.links_count for analysis in analyses),
        'total_forms': sum(analysis.forms_count for analysis in analyses),
        'total_scripts': sum(analysis.scripts_count for analysis in analyses)
    }
    
    return jsonify({
        'summary': {
            'total_analyses': total_analyses,
            'average_sentiment': avg_sentiment,
            'period': request.args.get('period', '24h')
        },
        'language_distribution': language_stats,
        'content_statistics': content_stats
    })

# User activity timeline
@enhanced_network_bp.route('/users/<int:user_id>/timeline', methods=['GET'])
def get_user_timeline(user_id):
    """Get detailed timeline of user activity"""
    user = User.query.get_or_404(user_id)
    start_time = get_time_filter()
    
    # Get user's devices
    devices = Device.query.filter_by(user_id=user_id).all()
    device_macs = [device.mac_address for device in devices]
    
    if not device_macs:
        return jsonify({
            'user': user.to_dict(),
            'timeline': [],
            'summary': {
                'total_events': 0,
                'websites_visited': 0,
                'applications_used': 0,
                'data_transferred': 0
            }
        })
    
    # Get website visits
    website_visits = WebsiteVisit.query.filter(
        WebsiteVisit.device_mac.in_(device_macs),
        WebsiteVisit.timestamp >= start_time
    ).order_by(WebsiteVisit.timestamp.desc()).all()
    
    # Get traffic sessions
    traffic_sessions = TrafficSession.query.filter(
        TrafficSession.src_mac.in_(device_macs),
        TrafficSession.start_time >= start_time
    ).order_by(TrafficSession.start_time.desc()).all()
    
    # Create timeline events
    timeline = []
    
    # Add website visits to timeline
    for visit in website_visits:
        timeline.append({
            'type': 'website_visit',
            'timestamp': visit.timestamp.isoformat(),
            'data': {
                'domain': visit.domain,
                'url': visit.url,
                'title': visit.title,
                'category': visit.category,
                'bytes_transferred': visit.bytes_transferred,
                'duration': visit.duration,
                'device_mac': visit.device_mac
            }
        })
    
    # Add significant traffic sessions to timeline
    for session in traffic_sessions:
        if session.application and session.bytes_sent + session.bytes_received > 1024:  # Only significant sessions
            timeline.append({
                'type': 'traffic_session',
                'timestamp': session.start_time.isoformat(),
                'data': {
                    'application': session.application,
                    'dst_ip': session.dst_ip,
                    'protocol': session.protocol,
                    'bytes_total': session.bytes_sent + session.bytes_received,
                    'duration': session.flow_duration,
                    'device_mac': session.src_mac
                }
            })
    
    # Sort timeline by timestamp
    timeline.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate summary statistics
    total_websites = len(website_visits)
    unique_applications = len(set(session.application for session in traffic_sessions if session.application))
    total_data = sum(visit.bytes_transferred for visit in website_visits) + \
                 sum(session.bytes_sent + session.bytes_received for session in traffic_sessions)
    
    return jsonify({
        'user': user.to_dict(),
        'timeline': timeline[:100],  # Limit to 100 most recent events
        'summary': {
            'total_events': len(timeline),
            'websites_visited': total_websites,
            'applications_used': unique_applications,
            'data_transferred': total_data,
            'period': request.args.get('period', '24h')
        }
    })

# Real-time monitoring endpoints
@enhanced_network_bp.route('/monitoring/live', methods=['GET'])
def get_live_monitoring():
    """Get real-time monitoring data"""
    # Get data from the last 5 minutes
    start_time = datetime.utcnow() - timedelta(minutes=5)
    
    # Recent traffic sessions
    recent_sessions = TrafficSession.query.filter(
        TrafficSession.start_time >= start_time
    ).order_by(TrafficSession.start_time.desc()).limit(50).all()
    
    # Recent website visits
    recent_visits = WebsiteVisit.query.filter(
        WebsiteVisit.timestamp >= start_time
    ).order_by(WebsiteVisit.timestamp.desc()).limit(50).all()
    
    # Active devices (seen in last 5 minutes)
    active_devices = Device.query.filter(
        Device.last_seen >= start_time
    ).all()
    
    return jsonify({
        'timestamp': datetime.utcnow().isoformat(),
        'active_devices': len(active_devices),
        'recent_sessions': [session.to_dict() for session in recent_sessions],
        'recent_visits': [visit.to_dict() for visit in recent_visits],
        'devices': [device.to_dict() for device in active_devices]
    })

# Export endpoints
@enhanced_network_bp.route('/export/user_report/<int:user_id>', methods=['GET'])
def export_user_report(user_id):
    """Export detailed user activity report"""
    user = User.query.get_or_404(user_id)
    start_time = get_time_filter()
    
    # Get comprehensive user data
    devices = Device.query.filter_by(user_id=user_id).all()
    device_macs = [device.mac_address for device in devices]
    
    if device_macs:
        website_visits = WebsiteVisit.query.filter(
            WebsiteVisit.device_mac.in_(device_macs),
            WebsiteVisit.timestamp >= start_time
        ).all()
        
        traffic_sessions = TrafficSession.query.filter(
            TrafficSession.src_mac.in_(device_macs),
            TrafficSession.start_time >= start_time
        ).all()
    else:
        website_visits = []
        traffic_sessions = []
    
    # Generate comprehensive report
    report = {
        'user': user.to_dict(),
        'report_period': {
            'start': start_time.isoformat(),
            'end': datetime.utcnow().isoformat(),
            'period': request.args.get('period', '24h')
        },
        'devices': [device.to_dict() for device in devices],
        'website_visits': [visit.to_dict() for visit in website_visits],
        'traffic_sessions': [session.to_dict() for session in traffic_sessions],
        'summary': {
            'total_devices': len(devices),
            'total_website_visits': len(website_visits),
            'total_traffic_sessions': len(traffic_sessions),
            'total_data_transferred': sum(visit.bytes_transferred for visit in website_visits) + 
                                    sum(session.bytes_sent + session.bytes_received for session in traffic_sessions)
        }
    }
    
    return jsonify(report)

