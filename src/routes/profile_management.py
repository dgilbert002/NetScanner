"""
API routes for user profile management (renamed from group management)
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from src.models.network import Device
from src.comprehensive_analytics import ComprehensiveAnalytics
import sqlite3
import os
import json

profile_management_bp = Blueprint('profile_management', __name__)
analytics = ComprehensiveAnalytics()

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'enhanced_network_monitor.db')


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_tables():
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            color TEXT DEFAULT '#3498db',
            icon TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            profile_metadata TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profile_device_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            profile_id INTEGER NOT NULL,
            added_at TEXT,
            added_by TEXT,
            UNIQUE(device_id, profile_id)
        )
        """
    )
    conn.commit()
    conn.close()


def _profile_to_dict(row, device_count=0, device_ids=None):
    metadata = json.loads(row['profile_metadata']) if row['profile_metadata'] else {}
    return {
        'id': row['id'],
        'name': row['name'],
        'description': row['description'],
        'color': row['color'],
        'icon': row['icon'],
        'is_active': bool(row['is_active']),
        'metadata': metadata,
        'picture': metadata.get('picture'),  # Extract picture from metadata
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
        'device_count': device_count,
        'device_ids': device_ids or []
    }


# ============= PROFILE CRUD OPERATIONS =============

@profile_management_bp.route('/api/v2/profiles/create', methods=['POST'])
def create_profile():
    """Create a new user profile"""
    _ensure_tables()
    data = request.get_json() or {}

    if not data.get('name'):
        return jsonify({'error': 'Profile name is required'}), 400

    conn = _connect()
    cur = conn.cursor()

    # Check existing
    cur.execute('SELECT id FROM user_profiles WHERE name = ? AND is_active = 1', (data['name'],))
    if cur.fetchone():
        conn.close()
        return jsonify({'error': 'Profile with this name already exists'}), 400

    now = datetime.utcnow().isoformat()
    
    # Prepare metadata including picture
    metadata = data.get('metadata', {})
    if 'picture' in data:
        metadata['picture'] = data['picture']
    
    cur.execute(
        'INSERT INTO user_profiles(name, description, color, icon, is_active, profile_metadata, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)',
        (
            data['name'],
            data.get('description', ''),
            data.get('color', '#3498db'),
            data.get('icon', 'user'),
            1 if data.get('is_active', True) else 0,
            json.dumps(metadata),
            now,
            now,
        ),
    )
    profile_id = cur.lastrowid
    conn.commit()

    cur.execute('SELECT * FROM user_profiles WHERE id = ?', (profile_id,))
    row = cur.fetchone()
    conn.close()
    return jsonify({'message': 'Profile created successfully', 'profile': _profile_to_dict(row)})


@profile_management_bp.route('/api/v2/profiles/list', methods=['GET'])
def list_profiles():
    """List all user profiles with their device counts"""
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()

    cur.execute('SELECT * FROM user_profiles WHERE is_active = 1 ORDER BY name')
    profiles = []
    
    for row in cur.fetchall():
        # Get device count for this profile
        cur.execute('SELECT COUNT(*) as count FROM profile_device_assignments WHERE profile_id = ?', (row['id'],))
        device_count = cur.fetchone()['count']
        
        # Get device IDs
        cur.execute('SELECT device_id FROM profile_device_assignments WHERE profile_id = ?', (row['id'],))
        device_ids = [r['device_id'] for r in cur.fetchall()]
        
        profiles.append(_profile_to_dict(row, device_count, device_ids))
    
    conn.close()
    return jsonify({'profiles': profiles})


@profile_management_bp.route('/api/v2/profiles/<int:profile_id>', methods=['GET'])
def get_profile(profile_id):
    """Get a specific profile with its devices"""
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    
    cur.execute('SELECT * FROM user_profiles WHERE id = ?', (profile_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Profile not found'}), 404
    
    # Get devices for this profile
    cur.execute('''
        SELECT d.*, pda.added_at as assigned_at
        FROM devices d
        JOIN profile_device_assignments pda ON d.id = pda.device_id
        WHERE pda.profile_id = ?
        ORDER BY d.hostname
    ''', (profile_id,))
    
    devices = []
    for device_row in cur.fetchall():
        devices.append({
            'id': device_row['id'],
            'mac_address': device_row['mac_address'],
            'ip_address': device_row['ip_address'],
            'hostname': device_row['hostname'],
            'friendly_name': device_row.get('friendly_name', ''),
            'device_type': device_row.get('device_type', 'Unknown'),
            'vendor': device_row.get('vendor', 'Unknown'),
            'is_active': bool(device_row.get('is_active', True)),
            'last_seen': device_row.get('last_seen'),
            'assigned_at': device_row['assigned_at']
        })
    
    conn.close()
    
    profile_data = _profile_to_dict(row, len(devices))
    profile_data['devices'] = devices
    return jsonify(profile_data)


@profile_management_bp.route('/api/v2/profiles/<int:profile_id>/update', methods=['PUT'])
def update_profile(profile_id):
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT * FROM user_profiles WHERE id = ?', (profile_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Profile not found'}), 404

    data = request.get_json() or {}

    # Duplicate name check
    if 'name' in data:
        cur.execute('SELECT id FROM user_profiles WHERE name = ? AND id != ?', (data['name'], profile_id))
        if cur.fetchone():
            conn.close()
            return jsonify({'error': 'Another profile with this name already exists'}), 400

    fields = {
        'name': data.get('name', row['name']),
        'description': data.get('description', row['description']),
        'color': data.get('color', row['color']),
        'icon': data.get('icon', row['icon']),
        'is_active': 1 if data.get('is_active', bool(row['is_active'])) else 0,
        'profile_metadata': json.dumps(data.get('metadata', json.loads(row['profile_metadata'] or '{}'))),
        'updated_at': datetime.utcnow().isoformat(),
    }
    cur.execute(
        'UPDATE user_profiles SET name=?, description=?, color=?, icon=?, is_active=?, profile_metadata=?, updated_at=? WHERE id=?',
        (fields['name'], fields['description'], fields['color'], fields['icon'], fields['is_active'], fields['profile_metadata'], fields['updated_at'], profile_id),
    )
    conn.commit()

    cur.execute('SELECT * FROM user_profiles WHERE id = ?', (profile_id,))
    updated = cur.fetchone()
    conn.close()
    return jsonify({'message': 'Profile updated successfully', 'profile': _profile_to_dict(updated)})


@profile_management_bp.route('/api/v2/profiles/<int:profile_id>/delete', methods=['DELETE'])
def delete_profile(profile_id):
    """Delete a profile (soft delete by setting is_active=0)"""
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    
    cur.execute('SELECT * FROM user_profiles WHERE id = ?', (profile_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Profile not found'}), 404
    
    # Soft delete
    cur.execute('UPDATE user_profiles SET is_active=0, updated_at=? WHERE id=?', 
                (datetime.utcnow().isoformat(), profile_id))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Profile deleted successfully'})


# ============= DEVICE ASSIGNMENT OPERATIONS =============

@profile_management_bp.route('/api/v2/profiles/<int:profile_id>/assign-device', methods=['POST'])
def assign_device_to_profile(profile_id):
    """Assign a device to a profile"""
    _ensure_tables()
    data = request.get_json() or {}
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'error': 'Device ID is required'}), 400
    
    conn = _connect()
    cur = conn.cursor()
    
    # Check if profile exists
    cur.execute('SELECT id FROM user_profiles WHERE id = ? AND is_active = 1', (profile_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({'error': 'Profile not found'}), 404
    
    # Check if device exists
    cur.execute('SELECT id FROM devices WHERE id = ?', (device_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({'error': 'Device not found'}), 404
    
    # Remove device from any other profile first
    cur.execute('DELETE FROM profile_device_assignments WHERE device_id = ?', (device_id,))
    
    # Assign device to profile
    now = datetime.utcnow().isoformat()
    cur.execute(
        'INSERT INTO profile_device_assignments(device_id, profile_id, added_at, added_by) VALUES (?,?,?,?)',
        (device_id, profile_id, now, 'admin')
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Device assigned to profile successfully'})


@profile_management_bp.route('/api/v2/profiles/<int:profile_id>/unassign-device', methods=['POST'])
def unassign_device_from_profile(profile_id):
    """Remove a device from a profile"""
    _ensure_tables()
    data = request.get_json() or {}
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'error': 'Device ID is required'}), 400
    
    conn = _connect()
    cur = conn.cursor()
    
    cur.execute('DELETE FROM profile_device_assignments WHERE device_id = ? AND profile_id = ?', 
                (device_id, profile_id))
    
    if cur.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Device not assigned to this profile'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Device unassigned from profile successfully'})


# ============= ANALYTICS OPERATIONS =============

@profile_management_bp.route('/api/v2/profiles/<int:profile_id>/analytics', methods=['GET'])
def get_profile_analytics(profile_id):
    """Get analytics for a specific profile"""
    _ensure_tables()
    
    # Get profile info
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT * FROM user_profiles WHERE id = ?', (profile_id,))
    profile = cur.fetchone()
    if not profile:
        conn.close()
        return jsonify({'error': 'Profile not found'}), 404
    
    # Get device IDs for this profile
    cur.execute('SELECT device_id FROM profile_device_assignments WHERE profile_id = ?', (profile_id,))
    device_ids = [row['device_id'] for row in cur.fetchall()]
    conn.close()
    
    if not device_ids:
        return jsonify({
            'profile': _profile_to_dict(profile),
            'analytics': {
                'total_devices': 0,
                'active_devices': 0,
                'total_traffic': 0,
                'top_domains': [],
                'recent_activity': []
            }
        })
    
    # Get analytics for devices in this profile
    try:
        analytics_data = analytics.get_profile_analytics(profile_id, device_ids)
        return jsonify({
            'profile': _profile_to_dict(profile),
            'analytics': analytics_data
        })
    except Exception as e:
        return jsonify({'error': f'Failed to get analytics: {str(e)}'}), 500
