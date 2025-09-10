"""
API routes for device group management (using direct SQLite to avoid ORM conflicts)
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from src.models.network import Device
from src.comprehensive_analytics import ComprehensiveAnalytics
import sqlite3
import os
import json

group_management_bp = Blueprint('group_management', __name__)
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
        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            color TEXT DEFAULT '#3498db',
            icon TEXT DEFAULT 'folder',
            is_active INTEGER DEFAULT 1,
            group_metadata TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_group_memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            added_at TEXT,
            added_by TEXT,
            UNIQUE(device_id, group_id)
        )
        """
    )
    conn.commit()
    conn.close()


def _group_to_dict(row, device_count=0, device_ids=None):
    return {
        'id': row['id'],
        'name': row['name'],
        'description': row['description'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
        'color': row['color'],
        'icon': row['icon'],
        'is_active': bool(row['is_active']),
        'metadata': json.loads(row['group_metadata'] or '{}'),
        'device_count': device_count,
        'device_ids': device_ids or []
    }


# ============= GROUP CRUD OPERATIONS =============

@group_management_bp.route('/api/v2/groups/create', methods=['POST'])
def create_group():
    """Create a new device group"""
    _ensure_tables()
    data = request.get_json() or {}

    if not data.get('name'):
        return jsonify({'error': 'Group name is required'}), 400

    conn = _connect()
    cur = conn.cursor()

    # Check existing
    cur.execute('SELECT id FROM device_groups WHERE name = ? AND is_active = 1', (data['name'],))
    if cur.fetchone():
        conn.close()
        return jsonify({'error': 'Group with this name already exists'}), 400

    now = datetime.utcnow().isoformat()
    cur.execute(
        'INSERT INTO device_groups(name, description, color, icon, is_active, group_metadata, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)',
        (
            data['name'],
            data.get('description', ''),
            data.get('color', '#3498db'),
            data.get('icon', 'folder'),
            1 if data.get('is_active', True) else 0,
            json.dumps(data.get('metadata', {})),
            now,
            now,
        ),
    )
    group_id = cur.lastrowid
    conn.commit()

    cur.execute('SELECT * FROM device_groups WHERE id = ?', (group_id,))
    row = cur.fetchone()
    conn.close()
    return jsonify({'message': 'Group created successfully', 'group': _group_to_dict(row)})


@group_management_bp.route('/api/v2/groups/list', methods=['GET'])
def list_groups():
    """List all device groups with their device counts"""
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT * FROM device_groups WHERE is_active = 1 ORDER BY name ASC')
    groups = cur.fetchall()

    result = []
    for g in groups:
        cur.execute('SELECT COUNT(*) as c FROM device_group_memberships WHERE group_id = ?', (g['id'],))
        count = cur.fetchone()['c']
        cur.execute('SELECT device_id FROM device_group_memberships WHERE group_id = ?', (g['id'],))
        device_ids = [r['device_id'] for r in cur.fetchall()]
        result.append(_group_to_dict(g, count, device_ids))
    conn.close()
    return jsonify(result)


@group_management_bp.route('/api/v2/groups/<int:group_id>', methods=['GET'])
def get_group(group_id):
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT * FROM device_groups WHERE id = ?', (group_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    cur.execute('SELECT device_id FROM device_group_memberships WHERE group_id = ?', (group_id,))
    device_ids = [r['device_id'] for r in cur.fetchall()]
    conn.close()

    devices = []
    if device_ids:
        for device in Device.query.filter(Device.id.in_(device_ids)).all():
            devices.append({
                'id': device.id,
                'mac_address': device.mac_address,
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'device_type': device.device_type,
                'vendor': device.vendor,
                'is_active': device.is_active,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            })

    group_data = _group_to_dict(row, len(devices), device_ids)
    group_data['devices'] = devices
    return jsonify(group_data)


@group_management_bp.route('/api/v2/groups/<int:group_id>/update', methods=['PUT'])
def update_group(group_id):
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT * FROM device_groups WHERE id = ?', (group_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    data = request.get_json() or {}

    # Duplicate name check
    if 'name' in data:
        cur.execute('SELECT id FROM device_groups WHERE name = ? AND id != ?', (data['name'], group_id))
        if cur.fetchone():
            conn.close()
            return jsonify({'error': 'Another group with this name already exists'}), 400

    fields = {
        'name': data.get('name', row['name']),
        'description': data.get('description', row['description']),
        'color': data.get('color', row['color']),
        'icon': data.get('icon', row['icon']),
        'is_active': 1 if data.get('is_active', bool(row['is_active'])) else 0,
        'group_metadata': json.dumps(data.get('metadata', json.loads(row['group_metadata'] or '{}'))),
        'updated_at': datetime.utcnow().isoformat(),
    }
    cur.execute(
        'UPDATE device_groups SET name=?, description=?, color=?, icon=?, is_active=?, group_metadata=?, updated_at=? WHERE id=?',
        (fields['name'], fields['description'], fields['color'], fields['icon'], fields['is_active'], fields['group_metadata'], fields['updated_at'], group_id),
    )
    conn.commit()

    cur.execute('SELECT * FROM device_groups WHERE id = ?', (group_id,))
    updated = cur.fetchone()
    conn.close()
    return jsonify({'message': 'Group updated successfully', 'group': _group_to_dict(updated)})


@group_management_bp.route('/api/v2/groups/<int:group_id>/delete', methods=['DELETE'])
def delete_group(group_id):
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    cur.execute('UPDATE device_groups SET is_active = 0, updated_at = ? WHERE id = ?', (datetime.utcnow().isoformat(), group_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Group deleted successfully'})


# ============= DEVICE MEMBERSHIP OPERATIONS =============

@group_management_bp.route('/api/v2/groups/<int:group_id>/add-device', methods=['POST'])
def add_device_to_group(group_id):
    _ensure_tables()
    data = request.get_json() or {}
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'Device ID is required'}), 400

    # Validate device exists
    if not Device.query.get(device_id):
        return jsonify({'error': 'Device not found'}), 404

    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT OR IGNORE INTO device_group_memberships(device_id, group_id, added_at, added_by) VALUES (?,?,?,?)',
            (device_id, group_id, datetime.utcnow().isoformat(), data.get('added_by', 'system')),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({'message': 'Device added to group successfully'})


@group_management_bp.route('/api/v2/groups/<int:group_id>/remove-device', methods=['POST'])
def remove_device_from_group(group_id):
    _ensure_tables()
    data = request.get_json() or {}
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'Device ID is required'}), 400

    conn = _connect()
    cur = conn.cursor()
    cur.execute('DELETE FROM device_group_memberships WHERE device_id = ? AND group_id = ?', (device_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Device removed from group successfully'})


@group_management_bp.route('/api/v2/groups/<int:group_id>/add-devices', methods=['POST'])
def add_multiple_devices_to_group(group_id):
    _ensure_tables()
    data = request.get_json() or {}
    device_ids = data.get('device_ids', [])
    added_by = data.get('added_by', 'system')
    if not device_ids:
        return jsonify({'error': 'Device IDs are required'}), 400

    conn = _connect()
    cur = conn.cursor()
    added, skipped = [], []
    for device_id in device_ids:
        if not Device.query.get(device_id):
            skipped.append({'id': device_id, 'reason': 'Device not found'})
            continue
        try:
            cur.execute(
                'INSERT OR IGNORE INTO device_group_memberships(device_id, group_id, added_at, added_by) VALUES (?,?,?,?)',
                (device_id, group_id, datetime.utcnow().isoformat(), added_by),
            )
            if cur.rowcount == 0:
                skipped.append({'id': device_id, 'reason': 'Already in group'})
            else:
                added.append(device_id)
        except Exception as e:
            skipped.append({'id': device_id, 'reason': str(e)})
    conn.commit()
    conn.close()
    return jsonify({'message': f'Added {len(added)} devices to group', 'added': added, 'skipped': skipped})


# ============= ANALYTICS BY GROUP =============

@group_management_bp.route('/api/v2/groups/<int:group_id>/analytics', methods=['GET'])
def get_group_analytics(group_id):
    _ensure_tables()
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT * FROM device_groups WHERE id = ?', (group_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    cur.execute('SELECT device_id FROM device_group_memberships WHERE group_id = ?', (group_id,))
    device_ids = [r['device_id'] for r in cur.fetchall()]
    conn.close()

    if not device_ids:
        return jsonify({'group': _group_to_dict(row), 'message': 'No devices in this group', 'analytics': None})

    period = request.args.get('period', '24h')
    analytics_data = analytics.get_group_analytics(group_name=row['name'], device_ids=device_ids, period=period)
    return jsonify({'group': _group_to_dict(row), 'analytics': analytics_data})


@group_management_bp.route('/api/v2/groups/<int:group_id>/traffic', methods=['GET'])
def get_group_traffic(group_id):
    _ensure_tables()
    # Get device IDs
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT device_id FROM device_group_memberships WHERE group_id = ?', (group_id,))
    device_ids = [r['device_id'] for r in cur.fetchall()]
    conn.close()
    if not device_ids:
        return jsonify([])

    # Map to MACs via ORM
    devices = Device.query.filter(Device.id.in_(device_ids)).all()
    macs = [d.mac_address for d in devices]

    # Query recent traffic via ORM
    from src.models.network import TrafficSession
    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    sessions = (
        TrafficSession.query
        .filter(TrafficSession.src_mac.in_(macs), TrafficSession.start_time >= five_min_ago)
        .order_by(TrafficSession.start_time.desc())
        .limit(100)
        .all()
    )

    out = []
    for s in sessions:
        device = next((d for d in devices if d.mac_address == s.src_mac), None)
        out.append({
            'id': s.id,
            'time': s.start_time.isoformat(),
            'device': device.hostname if device else s.src_mac,
            'device_id': device.id if device else None,
            'src_ip': s.src_ip,
            'dst_ip': s.dst_ip,
            'src_port': s.src_port,
            'dst_port': s.dst_port,
            'protocol': s.protocol,
            'bytes': s.bytes_sent + s.bytes_received,
        })
    return jsonify(out)


# ============= DEVICE GROUP SUGGESTIONS =============

@group_management_bp.route('/api/v2/groups/suggest', methods=['GET'])
def suggest_groups():
    devices = Device.query.filter_by(is_active=True).all()
    suggestions = []

    # Group by device type
    by_type = {}
    for d in devices:
        t = d.device_type or 'unknown'
        by_type.setdefault(t, []).append(d.id)
    for t, ids in by_type.items():
        if len(ids) > 1:
            suggestions.append({
                'name': f'{t.title()} Devices',
                'description': f'All {t} devices on the network',
                'device_ids': ids,
                'reason': 'Same device type',
                'icon': 'laptop' if 'computer' in t else 'device',
            })

    # Group by vendor
    by_vendor = {}
    for d in devices:
        v = d.vendor or 'unknown'
        if v != 'unknown':
            by_vendor.setdefault(v, []).append(d.id)
    for v, ids in by_vendor.items():
        if len(ids) > 1:
            suggestions.append({
                'name': f'{v} Devices',
                'description': f'All devices from {v}',
                'device_ids': ids,
                'reason': 'Same vendor',
                'icon': 'building',
            })

    # Group by subnet
    by_subnet = {}
    for d in devices:
        if d.ip_address and '.' in d.ip_address:
            subnet = '.'.join(d.ip_address.split('.')[:3])
            by_subnet.setdefault(subnet, []).append(d.id)
    for s, ids in by_subnet.items():
        if len(ids) > 1:
            suggestions.append({
                'name': f'Subnet {s}.x',
                'description': f'All devices in {s}.0/24 subnet',
                'device_ids': ids,
                'reason': 'Same network subnet',
                'icon': 'network',
            })

    return jsonify(suggestions)
