"""
Comprehensive analytics with advanced drill-down capabilities
Supports user, device, group, and time-based analysis
"""

from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, desc, asc
from collections import defaultdict
import json
import statistics
import os

# Check if enhanced features should be enabled
ENABLE_ENHANCED = os.getenv('ENABLE_ENHANCED', '0').lower() in ('1', 'true', 'yes')

if ENABLE_ENHANCED:
    try:
        from src.models.enhanced_network import (
            User, Device, TrafficSession, WebsiteVisit, ContentAnalysis,
            EnrichedData, NetworkStats, UserSession, db
        )
    except ImportError:
        # Fallback to base models
        from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
        from src.models.user import User, db
        # Create dummy classes for enhanced features
        class ContentAnalysis:
            pass
        class UserSession:
            pass
else:
    # Use base models only
    from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
    from src.models.user import User, db
    # Create dummy classes for enhanced features
    class ContentAnalysis:
        pass
    class UserSession:
        pass

class ComprehensiveAnalytics:
    """Advanced analytics with full drill-down capabilities"""
    
    def __init__(self):
        self.logger = None
        
    def get_user_analytics(self, user_id=None, period='24h', group_by='hour'):
        """Get comprehensive user analytics with drill-down"""
        start_time = self._get_time_range(period)
        
        query = db.session.query(User)
        if user_id:
            query = query.filter(User.id == user_id)
            
        users = query.all()
        analytics = []
        
        for user in users:
            # Get user's devices
            devices = Device.query.filter_by(user_id=user.id).all()
            device_macs = [d.mac_address for d in devices]
            
            if not device_macs:
                continue
                
            # Get traffic sessions
            sessions = TrafficSession.query.filter(
                TrafficSession.src_mac.in_(device_macs),
                TrafficSession.start_time >= start_time
            ).all()
            
            # Get website visits
            visits = WebsiteVisit.query.filter(
                WebsiteVisit.device_mac.in_(device_macs),
                WebsiteVisit.timestamp >= start_time
            ).all()
            
            # Calculate statistics
            total_bytes = sum(s.bytes_sent + s.bytes_received for s in sessions)
            total_sessions = len(sessions)
            total_visits = len(visits)
            
            # Application breakdown
            app_usage = defaultdict(lambda: {'bytes': 0, 'sessions': 0, 'time': 0})
            for session in sessions:
                app = session.application or 'Unknown'
                app_usage[app]['bytes'] += session.bytes_sent + session.bytes_received
                app_usage[app]['sessions'] += 1
                if session.flow_duration:
                    app_usage[app]['time'] += session.flow_duration
                    
            # Domain breakdown
            domain_usage = defaultdict(lambda: {'visits': 0, 'bytes': 0})
            for visit in visits:
                domain = visit.domain
                domain_usage[domain]['visits'] += 1
                domain_usage[domain]['bytes'] += visit.bytes_transferred
                
            # Time-based analysis
            time_series = self._generate_time_series(sessions, visits, start_time, group_by)
            
            # Device breakdown
            device_stats = []
            for device in devices:
                device_sessions = [s for s in sessions if s.src_mac == device.mac_address]
                device_visits = [v for v in visits if v.device_mac == device.mac_address]
                
                device_stats.append({
                    'device': device.to_dict(),
                    'bytes': sum(s.bytes_sent + s.bytes_received for s in device_sessions),
                    'sessions': len(device_sessions),
                    'visits': len(device_visits),
                    'last_active': max([s.start_time for s in device_sessions] + 
                                      [v.timestamp for v in device_visits] + 
                                      [datetime.min]).isoformat() if device_sessions or device_visits else None
                })
                
            analytics.append({
                'user': user.to_dict(),
                'period': period,
                'summary': {
                    'total_bytes': total_bytes,
                    'total_sessions': total_sessions,
                    'total_visits': total_visits,
                    'active_devices': len([d for d in device_stats if d['bytes'] > 0]),
                    'total_devices': len(devices)
                },
                'applications': dict(app_usage),
                'domains': dict(domain_usage),
                'devices': device_stats,
                'time_series': time_series,
                'top_applications': sorted(app_usage.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10],
                'top_domains': sorted(domain_usage.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]
            })
            
        return analytics if not user_id else (analytics[0] if analytics else None)
        
    def get_device_analytics(self, device_id=None, mac_address=None, period='24h'):
        """Get detailed device analytics"""
        start_time = self._get_time_range(period)
        
        # Get device
        if device_id:
            device = Device.query.get(device_id)
        elif mac_address:
            device = Device.query.filter_by(mac_address=mac_address).first()
        else:
            return None
            
        if not device:
            return None
            
        # Get traffic sessions
        sessions = TrafficSession.query.filter(
            TrafficSession.src_mac == device.mac_address,
            TrafficSession.start_time >= start_time
        ).all()
        
        # Get website visits
        visits = WebsiteVisit.query.filter(
            WebsiteVisit.device_mac == device.mac_address,
            WebsiteVisit.timestamp >= start_time
        ).all()
        
        # Protocol breakdown
        protocol_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
        for session in sessions:
            protocol = session.protocol
            protocol_stats[protocol]['count'] += 1
            protocol_stats[protocol]['bytes'] += session.bytes_sent + session.bytes_received
            
        # Port analysis
        port_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
        for session in sessions:
            port = session.dst_port
            port_stats[port]['count'] += 1
            port_stats[port]['bytes'] += session.bytes_sent + session.bytes_received
            
        # Destination IP analysis
        dest_ips = defaultdict(lambda: {'count': 0, 'bytes': 0, 'domain': None})
        for session in sessions:
            ip = session.dst_ip
            dest_ips[ip]['count'] += 1
            dest_ips[ip]['bytes'] += session.bytes_sent + session.bytes_received
            
            # Try to get domain for IP
            enriched = EnrichedData.query.filter_by(ip_address=ip).first()
            if enriched and enriched.hostname:
                dest_ips[ip]['domain'] = enriched.hostname
                
        # Application timeline
        app_timeline = defaultdict(list)
        for session in sessions:
            app = session.application or 'Unknown'
            app_timeline[app].append({
                'time': session.start_time.isoformat(),
                'bytes': session.bytes_sent + session.bytes_received,
                'duration': session.flow_duration
            })
            
        return {
            'device': device.to_dict(),
            'period': period,
            'summary': {
                'total_bytes_sent': sum(s.bytes_sent for s in sessions),
                'total_bytes_received': sum(s.bytes_received for s in sessions),
                'total_sessions': len(sessions),
                'total_visits': len(visits),
                'unique_destinations': len(set(s.dst_ip for s in sessions)),
                'unique_domains': len(set(v.domain for v in visits))
            },
            'protocols': dict(protocol_stats),
            'ports': dict(sorted(port_stats.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]),
            'destinations': dict(sorted(dest_ips.items(), key=lambda x: x[1]['bytes'], reverse=True)[:50]),
            'application_timeline': dict(app_timeline),
            'hourly_usage': self._calculate_hourly_usage(sessions, visits),
            'bandwidth_trend': self._calculate_bandwidth_trend(sessions, period)
        }
        
    def get_group_analytics(self, group_name, device_ids=None, user_ids=None, period='24h'):
        """Get analytics for a group of devices or users"""
        start_time = self._get_time_range(period)
        
        # Get devices for the group
        devices = []
        if device_ids:
            devices = Device.query.filter(Device.id.in_(device_ids)).all()
        elif user_ids:
            devices = Device.query.filter(Device.user_id.in_(user_ids)).all()
        else:
            return None
            
        device_macs = [d.mac_address for d in devices]
        
        if not device_macs:
            return None
            
        # Get aggregated data
        sessions = TrafficSession.query.filter(
            TrafficSession.src_mac.in_(device_macs),
            TrafficSession.start_time >= start_time
        ).all()
        
        visits = WebsiteVisit.query.filter(
            WebsiteVisit.device_mac.in_(device_macs),
            WebsiteVisit.timestamp >= start_time
        ).all()
        
        # Group statistics
        group_stats = {
            'name': group_name,
            'device_count': len(devices),
            'user_count': len(set(d.user_id for d in devices if d.user_id)),
            'total_bytes': sum(s.bytes_sent + s.bytes_received for s in sessions),
            'total_sessions': len(sessions),
            'total_visits': len(visits)
        }
        
        # Per-device breakdown
        device_breakdown = []
        for device in devices:
            device_sessions = [s for s in sessions if s.src_mac == device.mac_address]
            device_visits = [v for v in visits if v.device_mac == device.mac_address]
            
            device_breakdown.append({
                'device': device.device_name or device.hostname or device.mac_address,
                'user': device.assigned_user.username if device.assigned_user else 'Unassigned',
                'bytes': sum(s.bytes_sent + s.bytes_received for s in device_sessions),
                'sessions': len(device_sessions),
                'visits': len(device_visits),
                'percentage': 0  # Will calculate after
            })
            
        # Calculate percentages
        total_bytes = group_stats['total_bytes']
        if total_bytes > 0:
            for item in device_breakdown:
                item['percentage'] = (item['bytes'] / total_bytes) * 100
                
        # Application distribution across group
        app_distribution = defaultdict(lambda: {'bytes': 0, 'devices': set()})
        for session in sessions:
            app = session.application or 'Unknown'
            app_distribution[app]['bytes'] += session.bytes_sent + session.bytes_received
            app_distribution[app]['devices'].add(session.src_mac)
            
        # Convert sets to counts
        for app in app_distribution:
            app_distribution[app]['device_count'] = len(app_distribution[app]['devices'])
            del app_distribution[app]['devices']
            
        return {
            'group': group_stats,
            'period': period,
            'devices': sorted(device_breakdown, key=lambda x: x['bytes'], reverse=True),
            'applications': dict(sorted(app_distribution.items(), key=lambda x: x[1]['bytes'], reverse=True)),
            'time_series': self._generate_time_series(sessions, visits, start_time, 'hour'),
            'peak_usage': self._calculate_peak_usage(sessions),
            'average_per_device': {
                'bytes': group_stats['total_bytes'] / len(devices) if devices else 0,
                'sessions': group_stats['total_sessions'] / len(devices) if devices else 0,
                'visits': group_stats['total_visits'] / len(devices) if devices else 0
            }
        }
        
    def get_application_analytics(self, app_name=None, period='24h'):
        """Get detailed analytics for specific applications"""
        start_time = self._get_time_range(period)
        
        # Get sessions for application
        query = TrafficSession.query.filter(TrafficSession.start_time >= start_time)
        if app_name:
            query = query.filter(TrafficSession.application == app_name)
            
        sessions = query.all()
        
        # Get visits for application (by category)
        visit_query = WebsiteVisit.query.filter(WebsiteVisit.timestamp >= start_time)
        if app_name:
            visit_query = visit_query.filter(WebsiteVisit.category == app_name)
            
        visits = visit_query.all()
        
        # User and device breakdown
        user_usage = defaultdict(lambda: {'bytes': 0, 'sessions': 0, 'devices': set()})
        device_usage = defaultdict(lambda: {'bytes': 0, 'sessions': 0})
        
        for session in sessions:
            device = Device.query.filter_by(mac_address=session.src_mac).first()
            if device:
                device_key = device.mac_address
                device_usage[device_key]['bytes'] += session.bytes_sent + session.bytes_received
                device_usage[device_key]['sessions'] += 1
                
                if device.assigned_user:
                    user_key = device.assigned_user.username
                    user_usage[user_key]['bytes'] += session.bytes_sent + session.bytes_received
                    user_usage[user_key]['sessions'] += 1
                    user_usage[user_key]['devices'].add(device.mac_address)
                    
        # Convert sets to counts
        for user in user_usage:
            user_usage[user]['device_count'] = len(user_usage[user]['devices'])
            del user_usage[user]['devices']
            
        # Time patterns
        hourly_pattern = [0] * 24
        daily_pattern = [0] * 7
        
        for session in sessions:
            hour = session.start_time.hour
            day = session.start_time.weekday()
            bytes_total = session.bytes_sent + session.bytes_received
            hourly_pattern[hour] += bytes_total
            daily_pattern[day] += bytes_total
            
        # Related domains
        domain_stats = defaultdict(lambda: {'visits': 0, 'bytes': 0})
        for visit in visits:
            domain_stats[visit.domain]['visits'] += 1
            domain_stats[visit.domain]['bytes'] += visit.bytes_transferred
            
        return {
            'application': app_name or 'All Applications',
            'period': period,
            'summary': {
                'total_bytes': sum(s.bytes_sent + s.bytes_received for s in sessions),
                'total_sessions': len(sessions),
                'total_visits': len(visits),
                'unique_users': len(user_usage),
                'unique_devices': len(device_usage),
                'average_session_size': statistics.mean([s.bytes_sent + s.bytes_received for s in sessions]) if sessions else 0
            },
            'users': dict(sorted(user_usage.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]),
            'devices': dict(sorted(device_usage.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]),
            'domains': dict(sorted(domain_stats.items(), key=lambda x: x[1]['bytes'], reverse=True)[:50]),
            'usage_patterns': {
                'hourly': hourly_pattern,
                'daily': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                'daily_values': daily_pattern
            },
            'peak_hour': hourly_pattern.index(max(hourly_pattern)) if hourly_pattern else 0,
            'peak_day': daily_pattern.index(max(daily_pattern)) if daily_pattern else 0
        }
        
    def get_comparative_analytics(self, entity_type='user', entity_ids=[], period='7d'):
        """Compare multiple users, devices, or groups"""
        start_time = self._get_time_range(period)
        comparisons = []
        
        for entity_id in entity_ids:
            if entity_type == 'user':
                data = self.get_user_analytics(entity_id, period)
            elif entity_type == 'device':
                data = self.get_device_analytics(device_id=entity_id, period=period)
            else:
                continue
                
            if data:
                comparisons.append(data)
                
        # Calculate comparative metrics
        if len(comparisons) >= 2:
            # Find common applications
            all_apps = set()
            for comp in comparisons:
                if 'applications' in comp:
                    all_apps.update(comp['applications'].keys())
                    
            # Build comparison matrix
            comparison_matrix = {
                'entities': [c.get('user', c.get('device', {})).get('username', 
                            c.get('device', {}).get('hostname', 'Unknown')) for c in comparisons],
                'metrics': {
                    'total_bytes': [c.get('summary', {}).get('total_bytes', 0) for c in comparisons],
                    'total_sessions': [c.get('summary', {}).get('total_sessions', 0) for c in comparisons],
                    'total_visits': [c.get('summary', {}).get('total_visits', 0) for c in comparisons]
                },
                'applications': {}
            }
            
            for app in all_apps:
                comparison_matrix['applications'][app] = []
                for comp in comparisons:
                    app_data = comp.get('applications', {}).get(app, {})
                    comparison_matrix['applications'][app].append(app_data.get('bytes', 0))
                    
            return comparison_matrix
            
        return None
        
    def get_historical_trends(self, entity_type='system', entity_id=None, days=30):
        """Get historical trends over specified days"""
        trends = []
        
        for i in range(days):
            date = datetime.utcnow() - timedelta(days=i)
            start = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
            
            # Get data for this day
            if entity_type == 'system':
                stats = NetworkStats.query.filter(
                    NetworkStats.timestamp >= start,
                    NetworkStats.timestamp < end
                ).all()
                
                daily_bytes = sum(s.total_traffic_bytes for s in stats)
                daily_devices = max([s.total_devices for s in stats] + [0])
                
            elif entity_type == 'user' and entity_id:
                user = User.query.get(entity_id)
                if user:
                    devices = Device.query.filter_by(user_id=user.id).all()
                    device_macs = [d.mac_address for d in devices]
                    
                    sessions = TrafficSession.query.filter(
                        TrafficSession.src_mac.in_(device_macs),
                        TrafficSession.start_time >= start,
                        TrafficSession.start_time < end
                    ).all()
                    
                    daily_bytes = sum(s.bytes_sent + s.bytes_received for s in sessions)
                    daily_devices = len(set(s.src_mac for s in sessions))
                else:
                    daily_bytes = daily_devices = 0
                    
            else:
                daily_bytes = daily_devices = 0
                
            trends.append({
                'date': start.isoformat(),
                'bytes': daily_bytes,
                'devices': daily_devices
            })
            
        return list(reversed(trends))
        
    def _get_time_range(self, period):
        """Convert period string to datetime"""
        if period == '1h':
            return datetime.utcnow() - timedelta(hours=1)
        elif period == '24h':
            return datetime.utcnow() - timedelta(hours=24)
        elif period == '7d':
            return datetime.utcnow() - timedelta(days=7)
        elif period == '30d':
            return datetime.utcnow() - timedelta(days=30)
        elif period == '1y':
            return datetime.utcnow() - timedelta(days=365)
        else:
            # Try to parse as date
            try:
                return datetime.fromisoformat(period)
            except:
                return datetime.utcnow() - timedelta(hours=24)
                
    def _generate_time_series(self, sessions, visits, start_time, group_by='hour'):
        """Generate time series data"""
        time_series = defaultdict(lambda: {'bytes': 0, 'sessions': 0, 'visits': 0})
        
        for session in sessions:
            if group_by == 'hour':
                key = session.start_time.strftime('%Y-%m-%d %H:00')
            elif group_by == 'day':
                key = session.start_time.strftime('%Y-%m-%d')
            elif group_by == 'week':
                key = session.start_time.strftime('%Y-W%U')
            else:
                key = session.start_time.strftime('%Y-%m')
                
            time_series[key]['bytes'] += session.bytes_sent + session.bytes_received
            time_series[key]['sessions'] += 1
            
        for visit in visits:
            if group_by == 'hour':
                key = visit.timestamp.strftime('%Y-%m-%d %H:00')
            elif group_by == 'day':
                key = visit.timestamp.strftime('%Y-%m-%d')
            elif group_by == 'week':
                key = visit.timestamp.strftime('%Y-W%U')
            else:
                key = visit.timestamp.strftime('%Y-%m')
                
            time_series[key]['visits'] += 1
            
        return dict(sorted(time_series.items()))
        
    def _calculate_hourly_usage(self, sessions, visits):
        """Calculate usage by hour of day"""
        hourly = [0] * 24
        
        for session in sessions:
            hour = session.start_time.hour
            hourly[hour] += session.bytes_sent + session.bytes_received
            
        return hourly
        
    def _calculate_bandwidth_trend(self, sessions, period):
        """Calculate bandwidth trend over time"""
        # Group sessions by time intervals
        interval = timedelta(hours=1) if '24h' in period else timedelta(days=1)
        
        trends = defaultdict(int)
        for session in sessions:
            # Round to nearest interval
            timestamp = session.start_time
            key = timestamp.strftime('%Y-%m-%d %H:00' if interval.seconds == 3600 else '%Y-%m-%d')
            trends[key] += session.bytes_sent + session.bytes_received
            
        return dict(sorted(trends.items()))
        
    def _calculate_peak_usage(self, sessions):
        """Calculate peak usage times"""
        hourly_bytes = defaultdict(int)
        
        for session in sessions:
            hour = session.start_time.hour
            hourly_bytes[hour] += session.bytes_sent + session.bytes_received
            
        if hourly_bytes:
            peak_hour = max(hourly_bytes.items(), key=lambda x: x[1])
            return {
                'hour': peak_hour[0],
                'bytes': peak_hour[1],
                'time': f"{peak_hour[0]:02d}:00 - {(peak_hour[0]+1) % 24:02d}:00"
            }
            
        return None
