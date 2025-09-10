from flask import Blueprint, request, jsonify
from src.models.enhanced_network import User, Device, UserSession, db
from datetime import datetime, timedelta
import json

user_management_bp = Blueprint('user_management', __name__)

# User CRUD operations
@user_management_bp.route('/users', methods=['GET'])
def get_users():
    """Get all users with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    
    query = User.query
    if search:
        query = query.filter(
            (User.username.contains(search)) |
            (User.email.contains(search)) |
            (User.full_name.contains(search))
        )
    
    users = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'users': [user.to_dict() for user in users.items],
        'total': users.total,
        'pages': users.pages,
        'current_page': page,
        'per_page': per_page
    })

@user_management_bp.route('/users', methods=['POST'])
def create_user():
    """Create a new user"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'full_name']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    try:
        user = User(
            username=data['username'],
            email=data['email'],
            full_name=data['full_name'],
            role=data.get('role', 'user'),
            time_zone=data.get('time_zone', 'UTC'),
            notification_preferences=json.dumps(data.get('notification_preferences', {}))
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user"""
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@user_management_bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update a user"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    try:
        # Update fields if provided
        if 'username' in data:
            # Check if new username is unique
            existing = User.query.filter_by(username=data['username']).first()
            if existing and existing.id != user_id:
                return jsonify({'error': 'Username already exists'}), 400
            user.username = data['username']
        
        if 'email' in data:
            # Check if new email is unique
            existing = User.query.filter_by(email=data['email']).first()
            if existing and existing.id != user_id:
                return jsonify({'error': 'Email already exists'}), 400
            user.email = data['email']
        
        if 'full_name' in data:
            user.full_name = data['full_name']
        
        if 'role' in data:
            user.role = data['role']
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        if 'time_zone' in data:
            user.time_zone = data['time_zone']
        
        if 'notification_preferences' in data:
            user.notification_preferences = json.dumps(data['notification_preferences'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    
    try:
        # Unassign devices before deleting user
        Device.query.filter_by(user_id=user_id).update({'user_id': None})
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Device assignment operations
@user_management_bp.route('/users/<int:user_id>/devices', methods=['GET'])
def get_user_devices(user_id):
    """Get all devices assigned to a user"""
    user = User.query.get_or_404(user_id)
    devices = Device.query.filter_by(user_id=user_id).all()
    
    return jsonify({
        'user': user.to_dict(),
        'devices': [device.to_dict() for device in devices]
    })

@user_management_bp.route('/users/<int:user_id>/devices/<int:device_id>', methods=['POST'])
def assign_device_to_user(user_id, device_id):
    """Assign a device to a user"""
    user = User.query.get_or_404(user_id)
    device = Device.query.get_or_404(device_id)
    
    try:
        device.user_id = user_id
        db.session.commit()
        
        return jsonify({
            'message': f'Device {device.mac_address} assigned to user {user.username}',
            'device': device.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/users/<int:user_id>/devices/<int:device_id>', methods=['DELETE'])
def unassign_device_from_user(user_id, device_id):
    """Unassign a device from a user"""
    device = Device.query.get_or_404(device_id)
    
    if device.user_id != user_id:
        return jsonify({'error': 'Device is not assigned to this user'}), 400
    
    try:
        device.user_id = None
        db.session.commit()
        
        return jsonify({
            'message': f'Device {device.mac_address} unassigned from user',
            'device': device.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_management_bp.route('/devices/unassigned', methods=['GET'])
def get_unassigned_devices():
    """Get all devices not assigned to any user"""
    devices = Device.query.filter_by(user_id=None).all()
    
    return jsonify({
        'devices': [device.to_dict() for device in devices],
        'count': len(devices)
    })

# User analytics and statistics
@user_management_bp.route('/users/<int:user_id>/analytics', methods=['GET'])
def get_user_analytics(user_id):
    """Get analytics for a specific user"""
    user = User.query.get_or_404(user_id)
    
    # Get time range from query parameters
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get user's devices
    devices = Device.query.filter_by(user_id=user_id).all()
    device_macs = [device.mac_address for device in devices]
    
    if not device_macs:
        return jsonify({
            'user': user.to_dict(),
            'analytics': {
                'total_devices': 0,
                'total_sessions': 0,
                'total_bytes': 0,
                'websites_visited': 0,
                'top_domains': [],
                'top_applications': [],
                'daily_usage': []
            }
        })
    
    # Calculate analytics
    from src.models.enhanced_network import WebsiteVisit, TrafficSession
    
    # Total sessions
    total_sessions = UserSession.query.filter(
        UserSession.user_id == user_id,
        UserSession.start_time >= start_date
    ).count()
    
    # Total bytes
    total_bytes = db.session.query(db.func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received)).filter(
        TrafficSession.src_mac.in_(device_macs),
        TrafficSession.start_time >= start_date
    ).scalar() or 0
    
    # Websites visited
    websites_visited = WebsiteVisit.query.filter(
        WebsiteVisit.device_mac.in_(device_macs),
        WebsiteVisit.timestamp >= start_date
    ).count()
    
    # Top domains
    top_domains = db.session.query(
        WebsiteVisit.domain,
        db.func.count(WebsiteVisit.id).label('count')
    ).filter(
        WebsiteVisit.device_mac.in_(device_macs),
        WebsiteVisit.timestamp >= start_date
    ).group_by(WebsiteVisit.domain).order_by(db.desc('count')).limit(10).all()
    
    # Top applications
    top_applications = db.session.query(
        TrafficSession.application,
        db.func.count(TrafficSession.id).label('count')
    ).filter(
        TrafficSession.src_mac.in_(device_macs),
        TrafficSession.start_time >= start_date,
        TrafficSession.application.isnot(None)
    ).group_by(TrafficSession.application).order_by(db.desc('count')).limit(10).all()
    
    return jsonify({
        'user': user.to_dict(),
        'analytics': {
            'total_devices': len(devices),
            'total_sessions': total_sessions,
            'total_bytes': total_bytes,
            'websites_visited': websites_visited,
            'top_domains': [{'domain': domain, 'count': count} for domain, count in top_domains],
            'top_applications': [{'application': app, 'count': count} for app, count in top_applications if app],
            'time_range_days': days
        }
    })

@user_management_bp.route('/analytics/summary', methods=['GET'])
def get_analytics_summary():
    """Get overall analytics summary"""
    # Get time range from query parameters
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Calculate summary statistics
    total_users = User.query.filter_by(is_active=True).count()
    total_devices = Device.query.filter_by(is_active=True).count()
    assigned_devices = Device.query.filter(Device.user_id.isnot(None)).count()
    unassigned_devices = Device.query.filter_by(user_id=None).count()
    
    # Recent activity
    recent_sessions = UserSession.query.filter(
        UserSession.start_time >= start_date
    ).count()
    
    # Top users by activity
    top_users = db.session.query(
        User.username,
        User.full_name,
        db.func.count(UserSession.id).label('session_count')
    ).join(UserSession).filter(
        UserSession.start_time >= start_date
    ).group_by(User.id).order_by(db.desc('session_count')).limit(10).all()
    
    return jsonify({
        'summary': {
            'total_users': total_users,
            'total_devices': total_devices,
            'assigned_devices': assigned_devices,
            'unassigned_devices': unassigned_devices,
            'recent_sessions': recent_sessions,
            'assignment_rate': round((assigned_devices / total_devices * 100) if total_devices > 0 else 0, 2)
        },
        'top_users': [
            {
                'username': username,
                'full_name': full_name,
                'session_count': session_count
            }
            for username, full_name, session_count in top_users
        ],
        'time_range_days': days
    })

