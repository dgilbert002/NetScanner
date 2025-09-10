import os
import sys
# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from src.models.user import db
from datetime import datetime, timedelta

# Check if enhanced features should be enabled
ENABLE_ENHANCED = os.getenv('ENABLE_ENHANCED', '0').lower() in ('1', 'true', 'yes')

# Import enhanced models only if enabled
if ENABLE_ENHANCED:
    try:
        from src.models.enhanced_network import (
            User, Device, TrafficSession, WebsiteVisit, ContentAnalysis, 
            EnrichedData, NetworkStats, UserSession
        )
        enhanced_models_available = True
    except ImportError:
        enhanced_models_available = False
        # Fallback to original models if enhanced models not available
        from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
        from src.models.user import User
else:
    # Use base models only
    from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
    from src.models.user import User
    enhanced_models_available = False

# Import route blueprints
from src.routes.user import user_bp
from src.routes.network import network_bp

# Import enhanced routes only if enabled
if ENABLE_ENHANCED:
    try:
        from src.routes.user_management import user_management_bp
        from src.routes.enhanced_network import enhanced_network_bp
        enhanced_routes_available = True
    except ImportError:
        enhanced_routes_available = False
else:
    enhanced_routes_available = False

# Import services if available
try:
    from src.analytics_service import AnalyticsService
    from src.enhanced_packet_capture import EnhancedPacketCapture
    enhanced_services_available = True
except ImportError:
    enhanced_services_available = False

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = 'asdf#FGSgvasgf$5$WGT'

# Enable CORS for all routes
CORS(app)

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(network_bp, url_prefix='/api')

if enhanced_routes_available:
    app.register_blueprint(user_management_bp, url_prefix='/api')
    app.register_blueprint(enhanced_network_bp, url_prefix='/api')

# Register comprehensive API routes
try:
    from src.routes.comprehensive_api import comprehensive_bp
    app.register_blueprint(comprehensive_bp)
    print("✅ Comprehensive API routes loaded")
except ImportError as e:
    print(f"⚠️ Could not load comprehensive API: {e}")

# Register group management routes (legacy)
try:
    from src.routes.group_management import group_management_bp
    app.register_blueprint(group_management_bp)
    print("✅ Group management routes loaded (legacy)")
except ImportError as e:
    print(f"⚠️ Could not load group management: {e}")

# Register profile management routes (new)
try:
    from src.routes.profile_management import profile_management_bp
    app.register_blueprint(profile_management_bp)
    print("✅ Profile management routes loaded")
except ImportError as e:
    print(f"⚠️ Could not load profile management: {e}")

# Register device admin routes
try:
    from src.routes.device_admin import device_admin_bp
    app.register_blueprint(device_admin_bp)
    print("✅ Device admin routes loaded")
except ImportError as e:
    print(f"⚠️ Could not load device admin: {e}")

# Serve group management page
@app.route('/groups')
def groups_page():
    return app.send_static_file('group_management.html')

# Serve UI prototypes
@app.route('/prototypes/<page>')
def serve_prototype(page):
    prototypes_dir = os.path.join(app.static_folder, 'prototypes')
    target = os.path.join(prototypes_dir, f"{page}.html")
    if os.path.exists(target):
        return send_from_directory(prototypes_dir, f"{page}.html")
    return jsonify({'error': 'prototype not found'}), 404

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'enhanced_network_monitor.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Initialize services if available
analytics_service = None
packet_capture = None
realtime_capture = None

if enhanced_services_available:
    analytics_service = AnalyticsService()

# Import and initialize cross-platform capture
try:
    from src.cross_platform_capture import CrossPlatformCapture
    realtime_capture = CrossPlatformCapture(app_context=app)
    # Auto-start monitoring on app launch
    realtime_capture.start_capture()
    print(f"✅ Real-time network monitoring started automatically on {realtime_capture.platform}!")
    print(f"   Interface: {realtime_capture.interface}")
    print(f"   Method: {'Scapy' if realtime_capture.platform == 'Linux' or (realtime_capture.platform == 'Windows' and realtime_capture._check_npcap()) else 'Netstat'}")
except Exception as e:
    print(f"⚠️ Could not start real-time capture: {e}")
    realtime_capture = None

# Enhanced API endpoints
@app.route('/api/analytics/summary')
def get_analytics_summary():
    """Get analytics summary"""
    if not analytics_service:
        return jsonify({'error': 'Analytics service not available'}), 503
    
    period = request.args.get('period', '24h')
    user_id = request.args.get('user_id', type=int)
    
    try:
        analytics = analytics_service.get_overview_analytics(period, user_id)
        return jsonify(analytics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/user/<int:user_id>')
def get_user_analytics_detail(user_id):
    """Get detailed user analytics"""
    if not analytics_service:
        return jsonify({'error': 'Analytics service not available'}), 503
    
    period = request.args.get('period', '24h')
    
    try:
        analytics = analytics_service.get_user_analytics(user_id, period)
        if analytics is None:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(analytics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/start', methods=['POST'])
def start_enhanced_capture():
    """Start enhanced packet capture"""
    global packet_capture
    
    if not enhanced_services_available:
        return jsonify({'error': 'Enhanced capture not available'}), 503
    
    try:
        if packet_capture is None:
            config = {
                'klazify_api_key': os.getenv('KLAZIFY_API_KEY'),
                'ipinfo_token': os.getenv('IPINFO_TOKEN')
            }
            packet_capture = EnhancedPacketCapture(
                interface='WiFi',
                app_context=app,
                config=config
            )
        
        result = packet_capture.start_capture()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_enhanced_capture():
    """Stop enhanced packet capture"""
    global packet_capture
    
    try:
        if packet_capture:
            result = packet_capture.stop_capture()
            return jsonify(result)
        else:
            return jsonify({'status': 'not_running'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demo/generate', methods=['POST'])
def generate_enhanced_demo():
    """Generate enhanced demo data"""
    global packet_capture
    
    if not enhanced_services_available:
        return jsonify({'error': 'Enhanced demo not available'}), 503
    
    try:
        if packet_capture is None:
            packet_capture = EnhancedPacketCapture(
                interface='WiFi',
                app_context=app,
                config={}
            )
        
        result = packet_capture.generate_demo_data()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Dashboard API endpoints
@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get device count
        device_count = Device.query.count()
        
        # Get active profiles count (from new profile system)
        try:
            import sqlite3
            import os
            db_path = os.path.join(os.path.dirname(__file__), 'database', 'enhanced_network_monitor.db')
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM user_profiles WHERE is_active = 1')
            profile_count = cur.fetchone()[0]
            conn.close()
        except:
            profile_count = 0
        
        # Get live sessions (active traffic sessions)
        try:
            from src.models.network import TrafficSession
            live_sessions = TrafficSession.query.filter(
                TrafficSession.end_time.is_(None)
            ).count()
        except:
            live_sessions = 0
        
        # Get data transferred (sum of recent traffic)
        try:
            from src.models.network import TrafficSession
            from sqlalchemy import func
            data_transferred = db.session.query(
                func.sum(TrafficSession.bytes_transferred)
            ).filter(
                TrafficSession.start_time >= datetime.utcnow() - timedelta(hours=1)
            ).scalar() or 0
        except:
            data_transferred = 0
        
        return jsonify({
            'total_devices': device_count,
            'active_profiles': profile_count,
            'live_sessions': live_sessions,
            'data_transferred': data_transferred
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/live')
def get_live_traffic():
    """Get live traffic data"""
    try:
        # This would typically come from real-time packet capture
        # For now, return empty array
        return jsonify({
            'traffic': [],
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hostnames')
def get_hostnames():
    """Get hostname and application data"""
    try:
        # This would come from a hostnames table
        # For now, return empty array
        return jsonify({
            'hostnames': []
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

with app.app_context():
    db.create_all()

@app.route('/')
def serve_dashboard():
    """Serve the main dashboard"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404

    if os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        # Fallback to index for SPA routing
        return send_from_directory(static_folder_path, 'index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
