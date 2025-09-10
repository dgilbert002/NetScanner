"""
Admin endpoints for devices: friendly names and profile assignments
"""

from flask import Blueprint, jsonify, request
from src.models.network import Device
from datetime import datetime
import sqlite3
import os

device_admin_bp = Blueprint('device_admin', __name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'enhanced_network_monitor.db')


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_group_tables():
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


@device_admin_bp.route('/api/v2/devices', methods=['GET'])
def list_devices():
    devices = Device.query.all()
    out = []
    for d in devices:
        out.append({
            'id': d.id,
            'mac_address': d.mac_address,
            'ip_address': d.ip_address,
            'hostname': d.hostname,
            'device_type': d.device_type,
            'vendor': d.vendor,
            'friendly_name': d.hostname,  # using hostname as initial friendly name
            'is_active': d.is_active,
            'last_seen': d.last_seen.isoformat() if d.last_seen else None,
        })
    return jsonify(out)


@device_admin_bp.route('/api/v2/devices/<int:device_id>/rename', methods=['PUT'])
def rename_device(device_id):
    data = request.get_json() or {}
    new_name = data.get('friendly_name') or data.get('hostname')
    if not new_name:
        return jsonify({'error': 'friendly_name is required'}), 400

    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    device.hostname = new_name
    from src.models.user import db
    db.session.commit()
    return jsonify({'message': 'Device renamed', 'device': {'id': device.id, 'hostname': device.hostname}})


@device_admin_bp.route('/api/v2/devices/<int:device_id>/assign-group', methods=['POST'])
def assign_device_to_group(device_id):
    _ensure_group_tables()
    data = request.get_json() or {}
    group_id = data.get('group_id')
    if not group_id:
        return jsonify({'error': 'group_id is required'}), 400
    if not Device.query.get(device_id):
        return jsonify({'error': 'Device not found'}), 404

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        'INSERT OR IGNORE INTO device_group_memberships(device_id, group_id, added_at, added_by) VALUES (?,?,?,?)',
        (device_id, group_id, datetime.utcnow().isoformat(), 'system'),
    )
    conn.commit()
    conn.close()
    return jsonify({'message': 'Device assigned to group'})


@device_admin_bp.route('/api/v2/devices/<int:device_id>/unassign-group', methods=['POST'])
def unassign_device_from_group(device_id):
    _ensure_group_tables()
    data = request.get_json() or {}
    group_id = data.get('group_id')
    if not group_id:
        return jsonify({'error': 'group_id is required'}), 400

    conn = _connect()
    cur = conn.cursor()
    cur.execute('DELETE FROM device_group_memberships WHERE device_id = ? AND group_id = ?', (device_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Device unassigned from group'})


