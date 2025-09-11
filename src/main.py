import os
import sys
import threading
import time
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

# Register hostnames manager routes
try:
    from src.routes.hostnames import hostnames_bp
    app.register_blueprint(hostnames_bp)
    print("✅ Hostnames manager routes loaded")
except ImportError as e:
    print(f"⚠️ Could not load hostnames manager: {e}")

# Register settings routes
try:
    from src.routes.settings import settings_bp
    app.register_blueprint(settings_bp)
    print("✅ Settings routes loaded")
except ImportError as e:
    print(f"⚠️ Could not load settings: {e}")

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
enrichment_worker = None
pihole_tap = None
ndpi_worker = None

if enhanced_services_available:
    analytics_service = AnalyticsService()

# Import and initialize cross-platform capture
try:
    from src.cross_platform_capture import CrossPlatformCapture
    from src.enrichment_worker import EnrichmentWorker
    realtime_capture = CrossPlatformCapture(app_context=app)
    # Auto-start monitoring on app launch
    realtime_capture.start_capture()
    print(f"✅ Real-time network monitoring started automatically on {realtime_capture.platform}!")
    print(f"   Interface: {realtime_capture.interface}")
    print(f"   Method: {'Scapy' if realtime_capture.platform == 'Linux' or (realtime_capture.platform == 'Windows' and realtime_capture._check_npcap()) else 'Netstat'}")
    
    # Start enrichment worker
    enrichment_worker = EnrichmentWorker(app=app, ttl_hours=24)
    enrichment_worker.start()
    # Optional Pi-hole DNS tap
    pihole_tap = None
    try:
        # Try local database first
        from src.pihole_tap import PiHoleTap
        pihole_tap = PiHoleTap()
        if pihole_tap.enabled:
            print("✅ Pi-hole DNS tap enabled (local database)")
    except Exception:
        pass
    
    # If local didn't work, try remote connection
    if not pihole_tap or not pihole_tap.enabled:
        try:
            from src.pihole_remote import PiHoleRemote
            pihole_remote = PiHoleRemote()
            if pihole_remote.enabled:
                print("✅ Pi-hole connected via network")
                pihole_tap = pihole_remote  # Use same interface
        except Exception as e:
            print(f"ℹ️  Pi-hole not available: {e}")

    # Optional nDPI worker based on Settings (Fallback/On)
    try:
        from src.models.settings import AppSettings as _S
        ndpi_mode = (_S.get_or_create_defaults().ndpi_mode or 'off').lower()
    except Exception:
        ndpi_mode = 'off'
    if ndpi_mode in ('fallback', 'on'):
        try:
            from src.ndpi_worker import NDPIWorker
            ndpi_worker = NDPIWorker(realtime_capture.interface if realtime_capture else 'eth0')
            if ndpi_worker.start():
                print("✅ nDPI worker started")
            else:
                print("ℹ️  ndpiReader not found; nDPI disabled")
        except Exception as _:
            ndpi_worker = None

    # Start a periodic session logger (every 3 seconds)
    def _session_logger_loop():
        with app.app_context():
            while True:
                try:
                    now = datetime.utcnow()
                    since = now - timedelta(seconds=3)
                    # Fetch sessions updated/seen in the last 3 seconds
                    rows = []
                    try:
                        q = TrafficSession.query.filter(
                            db.or_(
                                TrafficSession.start_time >= since,
                                TrafficSession.end_time >= since
                            )
                        ).order_by(TrafficSession.start_time.desc()).limit(50)
                        recent = q.all()
                    except Exception as e:
                        print(f"[SESSION_LOG] query error: {e}")
                        recent = []

                    for s in recent:
                        try:
                            src = s.src_ip or s.src_mac or 'unknown'
                            dst = s.dst_ip or 'unknown'
                            proto = s.protocol or 'IP'
                            port = s.dst_port or 0
                            total_bytes = int((s.bytes_sent or 0) + (s.bytes_received or 0))
                            # Status using idle window
                            idle_seconds = 90
                            try:
                                from src.models.settings import AppSettings as _S
                                idle_seconds = _S.get_or_create_defaults().session_idle_seconds or 90
                            except Exception:
                                pass
                            last_seen_dt = (s.end_time or s.start_time or now)
                            active = ((now - last_seen_dt).total_seconds() <= idle_seconds)
                            ts = last_seen_dt.isoformat()
                            # Enqueue enrichment immediately for unknowns
                            try:
                                enr = EnrichedData.query.filter_by(ip_address=dst).first()
                                if not enr or not (enr.hostname or enr.organization):
                                    if enrichment_worker:
                                        enrichment_worker.enqueue_ip(dst, immediate=True)
                                # Consult Pi-hole DNS tap for last-seen hostname by source IP
                                if (not enr or not enr.hostname) and pihole_tap and src:
                                    for ip, host, _tstamp in (pihole_tap.lookup_recent_a(180) or []):
                                        if ip == src and host:
                                            # Opportunistically store hostname
                                            try:
                                                rec = EnrichedData.query.filter_by(ip_address=dst).first()
                                                if not rec:
                                                    rec = EnrichedData(ip_address=dst, hostname=host, updated_at=datetime.utcnow())
                                                    db.session.add(rec)
                                                else:
                                                    rec.hostname = host
                                                    rec.updated_at = datetime.utcnow()
                                                db.session.commit()
                                                enr = rec
                                            except Exception:
                                                db.session.rollback()
                                            break
                                org = (enr.organization if enr else None) or 'Unknown'
                                asn = str(enr.asn) if (enr and enr.asn is not None) else 'unknown'
                                host = (enr.hostname if enr else None) or 'unknown'
                            except Exception:
                                org = 'unknown'
                                asn = 'unknown'
                                host = 'unknown'

                            # nDPI labels (best effort) with fallback classifier
                            ndpi_app = ndpi_cat = ndpi_conf = 'n/a'
                            try:
                                # Try nDPI first if available
                                if ndpi_worker and ndpi_worker.enabled:
                                    lbl = ndpi_worker.get_label(src, dst, port, proto)
                                    if lbl:
                                        ndpi_app = lbl.get('app') or 'n/a'
                                        ndpi_cat = lbl.get('category') or 'n/a'
                                        ndpi_conf = lbl.get('confidence') or 'n/a'
                                
                                # Fallback to traffic classifier if nDPI not available or no results
                                if ndpi_app == 'n/a' or ndpi_cat == 'n/a':
                                    from src.traffic_classifier import TrafficClassifier
                                    classification = TrafficClassifier.classify(
                                        dst_ip=dst,
                                        dst_port=port,
                                        hostname=host if host != 'unknown' else None,
                                        protocol=proto
                                    )
                                    if classification:
                                        if ndpi_app == 'n/a':
                                            ndpi_app = classification.get('app', 'n/a')
                                        if ndpi_cat == 'n/a':
                                            ndpi_cat = classification.get('category', 'n/a')
                                        if ndpi_conf == 'n/a':
                                            ndpi_conf = classification.get('confidence', 'n/a')
                            except Exception:
                                pass

                            # Include enriched extras
                            try:
                                enr = EnrichedData.query.filter_by(ip_address=dst).first()
                                root_domain = None
                                if enr and enr.hostname:
                                    ext = __import__('tldextract').tldextract.extract(enr.hostname)
                                    root_domain = '.'.join(p for p in [ext.domain, ext.suffix] if p) or None
                                cc = getattr(enr, 'country_code', None) if enr else None
                                # ip2asn fallback for cc
                                if (not cc or cc.lower() == 'n/a') and enrichment_worker and enrichment_worker.ip2asn:
                                    info = enrichment_worker.ip2asn.lookup(dst)
                                    if info and info.get('country'):
                                        cc = info.get('country')
                            except Exception:
                                root_domain = None
                                cc = None

                            rows.append(f"{ts} | {src} -> {dst} {proto}:{port} bytes={total_bytes} active={active} org={org} asn={asn} host={host} cc={cc or 'n/a'} root={root_domain or 'n/a'} ndpi_app={ndpi_app} ndpi_cat={ndpi_cat} ndpi_conf={ndpi_conf}")
                        except Exception:
                            continue

                    if rows:
                        iface = getattr(realtime_capture, 'interface', 'n/a')
                        print(f"[SESSION_LOG] last 3s on {iface}: {len(rows)} session(s)")
                        for line in rows[:10]:
                            print(f"[SESSION_LOG] {line}")
                except Exception as e:
                    print(f"[SESSION_LOG] loop error: {e}")
                finally:
                    time.sleep(3)

    _t = threading.Thread(target=_session_logger_loop, daemon=True)
    _t.start()
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
