"""
Analytics Service
Provides comprehensive time-based analytics and historical data analysis
"""

from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, desc, asc
from collections import defaultdict, Counter
import json
import statistics

import os

# Check if enhanced features should be enabled
ENABLE_ENHANCED = os.getenv('ENABLE_ENHANCED', '0').lower() in ('1', 'true', 'yes')

if ENABLE_ENHANCED:
    from src.models.enhanced_network import (
        User, Device, TrafficSession, WebsiteVisit, ContentAnalysis, 
        EnrichedData, NetworkStats, UserSession, db
    )
else:
    # Use base models only
    from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats
    from src.models.user import User, db
    # Create dummy classes for enhanced features
    class ContentAnalysis:
        pass
    class UserSession:
        pass

class AnalyticsService:
    """Comprehensive analytics service for network monitoring data"""
    
    def __init__(self):
        self.time_periods = {
            '1h': timedelta(hours=1),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30),
            '90d': timedelta(days=90),
            '1y': timedelta(days=365)
        }
    
    def get_time_range(self, period='24h', custom_start=None, custom_end=None):
        """Get time range for analysis"""
        if custom_start and custom_end:
            return custom_start, custom_end
        
        end_time = datetime.utcnow()
        if period in self.time_periods:
            start_time = end_time - self.time_periods[period]
        else:
            start_time = end_time - self.time_periods['24h']
        
        return start_time, end_time
    
    def get_overview_analytics(self, period='24h', user_id=None):
        """Get overview analytics for dashboard"""
        start_time, end_time = self.get_time_range(period)
        
        analytics = {
            'period': period,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'summary': {},
            'trends': {},
            'top_items': {}
        }
        
        # Base query filters
        time_filter = and_(
            TrafficSession.start_time >= start_time,
            TrafficSession.start_time <= end_time
        )
        
        website_time_filter = and_(
            WebsiteVisit.timestamp >= start_time,
            WebsiteVisit.timestamp <= end_time
        )
        
        # User filtering
        if user_id:
            user_devices = db.session.query(Device.mac_address).filter_by(user_id=user_id).all()
            device_macs = [mac[0] for mac in user_devices]
            
            if device_macs:
                time_filter = and_(time_filter, TrafficSession.src_mac.in_(device_macs))
                website_time_filter = and_(website_time_filter, WebsiteVisit.device_mac.in_(device_macs))
            else:
                # No devices for user, return empty analytics
                analytics['summary'] = self._get_empty_summary()
                return analytics
        
        # Summary statistics
        analytics['summary'] = self._get_summary_stats(time_filter, website_time_filter, user_id)
        
        # Trends and comparisons
        analytics['trends'] = self._get_trend_analysis(period, user_id)
        
        # Top items
        analytics['top_items'] = self._get_top_items(time_filter, website_time_filter)
        
        return analytics
    
    def _get_summary_stats(self, time_filter, website_time_filter, user_id=None):
        """Get summary statistics"""
        # Total users
        total_users = User.query.filter_by(is_active=True).count()
        
        # Total devices
        device_query = Device.query.filter_by(is_active=True)
        if user_id:
            device_query = device_query.filter_by(user_id=user_id)
        total_devices = device_query.count()
        
        # Active devices (seen in time period)
        active_devices = db.session.query(func.count(func.distinct(TrafficSession.src_mac))).filter(time_filter).scalar() or 0
        
        # Traffic statistics
        traffic_stats = db.session.query(
            func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('total_bytes'),
            func.count(TrafficSession.id).label('total_sessions'),
            func.count(func.distinct(TrafficSession.src_mac)).label('unique_devices')
        ).filter(time_filter).first()
        
        # Website statistics
        website_stats = db.session.query(
            func.count(WebsiteVisit.id).label('total_visits'),
            func.count(func.distinct(WebsiteVisit.domain)).label('unique_domains'),
            func.sum(WebsiteVisit.bytes_transferred).label('total_web_bytes')
        ).filter(website_time_filter).first()
        
        # User sessions
        session_count = 0
        if user_id:
            session_count = UserSession.query.filter(
                UserSession.user_id == user_id,
                UserSession.start_time >= time_filter.left.left,
                UserSession.start_time <= time_filter.left.right
            ).count()
        else:
            session_count = UserSession.query.filter(
                UserSession.start_time >= time_filter.left.left,
                UserSession.start_time <= time_filter.left.right
            ).count()
        
        return {
            'total_users': total_users,
            'total_devices': total_devices,
            'active_devices': active_devices,
            'total_traffic_bytes': traffic_stats.total_bytes or 0,
            'total_sessions': traffic_stats.total_sessions or 0,
            'total_website_visits': website_stats.total_visits or 0,
            'unique_domains': website_stats.unique_domains or 0,
            'total_web_bytes': website_stats.total_web_bytes or 0,
            'user_sessions': session_count,
            'device_utilization': round((active_devices / total_devices * 100) if total_devices > 0 else 0, 2)
        }
    
    def _get_empty_summary(self):
        """Return empty summary for users with no devices"""
        return {
            'total_users': 0,
            'total_devices': 0,
            'active_devices': 0,
            'total_traffic_bytes': 0,
            'total_sessions': 0,
            'total_website_visits': 0,
            'unique_domains': 0,
            'total_web_bytes': 0,
            'user_sessions': 0,
            'device_utilization': 0
        }
    
    def _get_trend_analysis(self, period, user_id=None):
        """Get trend analysis comparing with previous period"""
        current_start, current_end = self.get_time_range(period)
        
        # Calculate previous period
        period_duration = current_end - current_start
        previous_start = current_start - period_duration
        previous_end = current_start
        
        # Get current period stats
        current_filter = and_(
            TrafficSession.start_time >= current_start,
            TrafficSession.start_time <= current_end
        )
        
        # Get previous period stats
        previous_filter = and_(
            TrafficSession.start_time >= previous_start,
            TrafficSession.start_time <= previous_end
        )
        
        # Apply user filtering if needed
        if user_id:
            user_devices = db.session.query(Device.mac_address).filter_by(user_id=user_id).all()
            device_macs = [mac[0] for mac in user_devices]
            
            if device_macs:
                current_filter = and_(current_filter, TrafficSession.src_mac.in_(device_macs))
                previous_filter = and_(previous_filter, TrafficSession.src_mac.in_(device_macs))
        
        # Current period metrics
        current_metrics = db.session.query(
            func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('bytes'),
            func.count(TrafficSession.id).label('sessions'),
            func.count(func.distinct(TrafficSession.src_mac)).label('devices')
        ).filter(current_filter).first()
        
        # Previous period metrics
        previous_metrics = db.session.query(
            func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('bytes'),
            func.count(TrafficSession.id).label('sessions'),
            func.count(func.distinct(TrafficSession.src_mac)).label('devices')
        ).filter(previous_filter).first()
        
        def calculate_change(current, previous):
            if previous and previous > 0:
                return round(((current - previous) / previous) * 100, 2)
            return 0
        
        return {
            'traffic_change': calculate_change(
                current_metrics.bytes or 0,
                previous_metrics.bytes or 0
            ),
            'sessions_change': calculate_change(
                current_metrics.sessions or 0,
                previous_metrics.sessions or 0
            ),
            'devices_change': calculate_change(
                current_metrics.devices or 0,
                previous_metrics.devices or 0
            )
        }
    
    def _get_top_items(self, time_filter, website_time_filter):
        """Get top items (domains, applications, etc.)"""
        # Top domains
        top_domains = db.session.query(
            WebsiteVisit.domain,
            func.count(WebsiteVisit.id).label('visit_count'),
            func.sum(WebsiteVisit.bytes_transferred).label('total_bytes')
        ).filter(website_time_filter).group_by(
            WebsiteVisit.domain
        ).order_by(desc('visit_count')).limit(10).all()
        
        # Top applications
        top_applications = db.session.query(
            TrafficSession.application,
            func.count(TrafficSession.id).label('session_count'),
            func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('total_bytes')
        ).filter(
            time_filter,
            TrafficSession.application.isnot(None)
        ).group_by(
            TrafficSession.application
        ).order_by(desc('session_count')).limit(10).all()
        
        # Top protocols
        top_protocols = db.session.query(
            TrafficSession.protocol,
            func.count(TrafficSession.id).label('session_count'),
            func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('total_bytes')
        ).filter(time_filter).group_by(
            TrafficSession.protocol
        ).order_by(desc('session_count')).limit(10).all()
        
        return {
            'domains': [
                {
                    'domain': domain,
                    'visits': visit_count,
                    'bytes': total_bytes
                }
                for domain, visit_count, total_bytes in top_domains
            ],
            'applications': [
                {
                    'application': app,
                    'sessions': session_count,
                    'bytes': total_bytes
                }
                for app, session_count, total_bytes in top_applications
            ],
            'protocols': [
                {
                    'protocol': protocol,
                    'sessions': session_count,
                    'bytes': total_bytes
                }
                for protocol, session_count, total_bytes in top_protocols
            ]
        }
    
    def get_user_analytics(self, user_id, period='24h'):
        """Get detailed analytics for a specific user"""
        user = User.query.get(user_id)
        if not user:
            return None
        
        start_time, end_time = self.get_time_range(period)
        
        # Get user's devices
        devices = Device.query.filter_by(user_id=user_id).all()
        device_macs = [device.mac_address for device in devices]
        
        if not device_macs:
            return {
                'user': user.to_dict(),
                'period': period,
                'summary': self._get_empty_summary(),
                'activity_timeline': [],
                'device_breakdown': [],
                'category_analysis': {},
                'time_patterns': {}
            }
        
        # Summary for user
        summary = self.get_overview_analytics(period, user_id)['summary']
        
        # Activity timeline
        timeline = self._get_user_timeline(device_macs, start_time, end_time)
        
        # Device breakdown
        device_breakdown = self._get_device_breakdown(device_macs, start_time, end_time)
        
        # Category analysis
        category_analysis = self._get_category_analysis(device_macs, start_time, end_time)
        
        # Time patterns
        time_patterns = self._get_time_patterns(device_macs, start_time, end_time)
        
        return {
            'user': user.to_dict(),
            'period': period,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'summary': summary,
            'activity_timeline': timeline,
            'device_breakdown': device_breakdown,
            'category_analysis': category_analysis,
            'time_patterns': time_patterns
        }
    
    def _get_user_timeline(self, device_macs, start_time, end_time):
        """Get user activity timeline"""
        # Website visits
        visits = WebsiteVisit.query.filter(
            WebsiteVisit.device_mac.in_(device_macs),
            WebsiteVisit.timestamp >= start_time,
            WebsiteVisit.timestamp <= end_time
        ).order_by(desc(WebsiteVisit.timestamp)).limit(50).all()
        
        # Traffic sessions (significant ones only)
        sessions = TrafficSession.query.filter(
            TrafficSession.src_mac.in_(device_macs),
            TrafficSession.start_time >= start_time,
            TrafficSession.start_time <= end_time,
            (TrafficSession.bytes_sent + TrafficSession.bytes_received) > 1024  # > 1KB
        ).order_by(desc(TrafficSession.start_time)).limit(50).all()
        
        # Combine and sort timeline
        timeline = []
        
        for visit in visits:
            timeline.append({
                'type': 'website_visit',
                'timestamp': visit.timestamp.isoformat(),
                'data': {
                    'domain': visit.domain,
                    'url': visit.url,
                    'title': visit.title,
                    'category': visit.category,
                    'bytes': visit.bytes_transferred,
                    'device_mac': visit.device_mac
                }
            })
        
        for session in sessions:
            if session.application:  # Only include sessions with identified applications
                timeline.append({
                    'type': 'traffic_session',
                    'timestamp': session.start_time.isoformat(),
                    'data': {
                        'application': session.application,
                        'protocol': session.protocol,
                        'dst_ip': session.dst_ip,
                        'bytes': session.bytes_sent + session.bytes_received,
                        'duration': session.flow_duration,
                        'device_mac': session.src_mac
                    }
                })
        
        # Sort by timestamp (most recent first)
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return timeline[:100]  # Return top 100 events
    
    def _get_device_breakdown(self, device_macs, start_time, end_time):
        """Get breakdown by device"""
        breakdown = []
        
        for mac in device_macs:
            device = Device.query.filter_by(mac_address=mac).first()
            if not device:
                continue
            
            # Traffic for this device
            traffic_stats = db.session.query(
                func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received).label('total_bytes'),
                func.count(TrafficSession.id).label('session_count')
            ).filter(
                TrafficSession.src_mac == mac,
                TrafficSession.start_time >= start_time,
                TrafficSession.start_time <= end_time
            ).first()
            
            # Website visits for this device
            visit_count = WebsiteVisit.query.filter(
                WebsiteVisit.device_mac == mac,
                WebsiteVisit.timestamp >= start_time,
                WebsiteVisit.timestamp <= end_time
            ).count()
            
            breakdown.append({
                'device': device.to_dict(),
                'traffic_bytes': traffic_stats.total_bytes or 0,
                'session_count': traffic_stats.session_count or 0,
                'website_visits': visit_count
            })
        
        # Sort by traffic bytes
        breakdown.sort(key=lambda x: x['traffic_bytes'], reverse=True)
        
        return breakdown
    
    def _get_category_analysis(self, device_macs, start_time, end_time):
        """Get website category analysis"""
        categories = db.session.query(
            WebsiteVisit.category,
            func.count(WebsiteVisit.id).label('visit_count'),
            func.sum(WebsiteVisit.bytes_transferred).label('total_bytes'),
            func.sum(WebsiteVisit.duration).label('total_duration')
        ).filter(
            WebsiteVisit.device_mac.in_(device_macs),
            WebsiteVisit.timestamp >= start_time,
            WebsiteVisit.timestamp <= end_time,
            WebsiteVisit.category.isnot(None)
        ).group_by(WebsiteVisit.category).order_by(desc('visit_count')).all()
        
        category_data = {}
        for category, visits, bytes_total, duration in categories:
            category_data[category] = {
                'visits': visits,
                'bytes': bytes_total or 0,
                'duration': duration or 0,
                'avg_duration': round((duration or 0) / visits, 2) if visits > 0 else 0
            }
        
        return category_data
    
    def _get_time_patterns(self, device_macs, start_time, end_time):
        """Get time-based usage patterns"""
        # Hourly breakdown
        hourly_data = defaultdict(lambda: {'visits': 0, 'bytes': 0})
        
        visits = WebsiteVisit.query.filter(
            WebsiteVisit.device_mac.in_(device_macs),
            WebsiteVisit.timestamp >= start_time,
            WebsiteVisit.timestamp <= end_time
        ).all()
        
        for visit in visits:
            hour = visit.timestamp.hour
            hourly_data[hour]['visits'] += 1
            hourly_data[hour]['bytes'] += visit.bytes_transferred or 0
        
        # Daily breakdown (for longer periods)
        daily_data = defaultdict(lambda: {'visits': 0, 'bytes': 0})
        
        for visit in visits:
            day = visit.timestamp.strftime('%Y-%m-%d')
            daily_data[day]['visits'] += 1
            daily_data[day]['bytes'] += visit.bytes_transferred or 0
        
        return {
            'hourly': dict(hourly_data),
            'daily': dict(daily_data)
        }
    
    def get_traffic_analytics(self, period='24h', user_id=None, device_id=None):
        """Get detailed traffic analytics"""
        start_time, end_time = self.get_time_range(period)
        
        # Base query
        query = TrafficSession.query.filter(
            TrafficSession.start_time >= start_time,
            TrafficSession.start_time <= end_time
        )
        
        # Apply filters
        if user_id:
            user_devices = db.session.query(Device.mac_address).filter_by(user_id=user_id).all()
            device_macs = [mac[0] for mac in user_devices]
            if device_macs:
                query = query.filter(TrafficSession.src_mac.in_(device_macs))
        
        if device_id:
            device = Device.query.get(device_id)
            if device:
                query = query.filter(TrafficSession.src_mac == device.mac_address)
        
        sessions = query.all()
        
        # Analyze traffic patterns
        protocol_stats = defaultdict(lambda: {'sessions': 0, 'bytes': 0})
        application_stats = defaultdict(lambda: {'sessions': 0, 'bytes': 0})
        destination_stats = defaultdict(lambda: {'sessions': 0, 'bytes': 0})
        
        total_bytes = 0
        total_sessions = len(sessions)
        
        for session in sessions:
            bytes_total = session.bytes_sent + session.bytes_received
            total_bytes += bytes_total
            
            # Protocol stats
            protocol_stats[session.protocol]['sessions'] += 1
            protocol_stats[session.protocol]['bytes'] += bytes_total
            
            # Application stats
            if session.application:
                application_stats[session.application]['sessions'] += 1
                application_stats[session.application]['bytes'] += bytes_total
            
            # Destination stats
            destination_stats[session.dst_ip]['sessions'] += 1
            destination_stats[session.dst_ip]['bytes'] += bytes_total
        
        return {
            'period': period,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'summary': {
                'total_sessions': total_sessions,
                'total_bytes': total_bytes,
                'avg_session_size': round(total_bytes / total_sessions, 2) if total_sessions > 0 else 0
            },
            'protocol_distribution': dict(protocol_stats),
            'application_distribution': dict(application_stats),
            'top_destinations': dict(sorted(
                destination_stats.items(),
                key=lambda x: x[1]['bytes'],
                reverse=True
            )[:20])
        }
    
    def get_website_analytics(self, period='24h', user_id=None, device_id=None, category=None):
        """Get detailed website analytics"""
        start_time, end_time = self.get_time_range(period)
        
        # Base query
        query = WebsiteVisit.query.filter(
            WebsiteVisit.timestamp >= start_time,
            WebsiteVisit.timestamp <= end_time
        )
        
        # Apply filters
        if user_id:
            user_devices = db.session.query(Device.mac_address).filter_by(user_id=user_id).all()
            device_macs = [mac[0] for mac in user_devices]
            if device_macs:
                query = query.filter(WebsiteVisit.device_mac.in_(device_macs))
        
        if device_id:
            device = Device.query.get(device_id)
            if device:
                query = query.filter(WebsiteVisit.device_mac == device.mac_address)
        
        if category:
            query = query.filter(WebsiteVisit.category == category)
        
        visits = query.all()
        
        # Analyze website patterns
        domain_stats = defaultdict(lambda: {
            'visits': 0, 'bytes': 0, 'duration': 0, 'category': None
        })
        category_stats = defaultdict(lambda: {
            'visits': 0, 'bytes': 0, 'duration': 0
        })
        
        total_visits = len(visits)
        total_bytes = 0
        total_duration = 0
        
        for visit in visits:
            total_bytes += visit.bytes_transferred or 0
            total_duration += visit.duration or 0
            
            # Domain stats
            domain_stats[visit.domain]['visits'] += 1
            domain_stats[visit.domain]['bytes'] += visit.bytes_transferred or 0
            domain_stats[visit.domain]['duration'] += visit.duration or 0
            domain_stats[visit.domain]['category'] = visit.category
            
            # Category stats
            if visit.category:
                category_stats[visit.category]['visits'] += 1
                category_stats[visit.category]['bytes'] += visit.bytes_transferred or 0
                category_stats[visit.category]['duration'] += visit.duration or 0
        
        return {
            'period': period,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'summary': {
                'total_visits': total_visits,
                'total_bytes': total_bytes,
                'total_duration': total_duration,
                'avg_duration': round(total_duration / total_visits, 2) if total_visits > 0 else 0,
                'unique_domains': len(domain_stats)
            },
            'top_domains': dict(sorted(
                domain_stats.items(),
                key=lambda x: x[1]['visits'],
                reverse=True
            )[:20]),
            'category_distribution': dict(category_stats)
        }
    
    def get_historical_comparison(self, metric, periods=['7d', '30d', '90d']):
        """Get historical comparison for a specific metric"""
        comparisons = {}
        
        for period in periods:
            start_time, end_time = self.get_time_range(period)
            
            if metric == 'traffic':
                result = db.session.query(
                    func.sum(TrafficSession.bytes_sent + TrafficSession.bytes_received)
                ).filter(
                    TrafficSession.start_time >= start_time,
                    TrafficSession.start_time <= end_time
                ).scalar()
                
            elif metric == 'visits':
                result = WebsiteVisit.query.filter(
                    WebsiteVisit.timestamp >= start_time,
                    WebsiteVisit.timestamp <= end_time
                ).count()
                
            elif metric == 'devices':
                result = db.session.query(
                    func.count(func.distinct(TrafficSession.src_mac))
                ).filter(
                    TrafficSession.start_time >= start_time,
                    TrafficSession.start_time <= end_time
                ).scalar()
            
            else:
                result = 0
            
            comparisons[period] = result or 0
        
        return comparisons
    
    def generate_report(self, user_id=None, period='30d', include_details=True):
        """Generate comprehensive analytics report"""
        start_time, end_time = self.get_time_range(period)
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'period': period,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'user_id': user_id
        }
        
        if user_id:
            # User-specific report
            user_analytics = self.get_user_analytics(user_id, period)
            report.update(user_analytics)
        else:
            # System-wide report
            report['overview'] = self.get_overview_analytics(period)
            report['traffic'] = self.get_traffic_analytics(period)
            report['websites'] = self.get_website_analytics(period)
            
            if include_details:
                # Top users by activity
                top_users = db.session.query(
                    User.id, User.username, User.full_name,
                    func.count(UserSession.id).label('session_count')
                ).join(UserSession).filter(
                    UserSession.start_time >= start_time,
                    UserSession.start_time <= end_time
                ).group_by(User.id).order_by(desc('session_count')).limit(10).all()
                
                report['top_users'] = [
                    {
                        'user_id': user_id,
                        'username': username,
                        'full_name': full_name,
                        'session_count': session_count
                    }
                    for user_id, username, full_name, session_count in top_users
                ]
        
        return report

