#!/usr/bin/env python3
"""
Time Utilities
Helper functions for time-based analysis and calculations
Author: SOC Team
"""

from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
import re


class TimeUtils:
    """Utility class for time-based operations and analysis"""
    
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """
        Parse various timestamp formats into datetime object
        
        Args:
            timestamp_str: Timestamp string to parse
            
        Returns:
            datetime object or None if parsing fails
        """
        
        if not timestamp_str:
            return None
        
        timestamp_str = timestamp_str.strip()
        
        # Common timestamp formats
        formats = [
            # ISO formats
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            
            # Standard formats
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            
            # Syslog format
            "%b %d %H:%M:%S",
            
            # Other common formats
            "%Y%m%d %H:%M:%S",
            "%d-%b-%Y %H:%M:%S",
        ]
        
        # Try ISO format with timezone first
        try:
            if 'T' in timestamp_str and ('Z' in timestamp_str or '+' in timestamp_str or '-' in timestamp_str[-6:]):
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            pass
        
        # Try other formats
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                # Handle syslog format (add current year)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except (ValueError, TypeError):
                continue
        
        return None
    
    @staticmethod
    def calculate_time_span(entries: List[Dict]) -> timedelta:
        """
        Calculate time span between first and last log entry
        
        Args:
            entries: List of log entries with timestamp fields
            
        Returns:
            timedelta representing the time span
        """
        
        if len(entries) < 2:
            return timedelta(0)
        
        timestamps = []
        
        for entry in entries:
            timestamp_str = entry.get('timestamp', '')
            if timestamp_str:
                dt = TimeUtils.parse_timestamp(timestamp_str)
                if dt:
                    timestamps.append(dt)
        
        if len(timestamps) < 2:
            return timedelta(0)
        
        timestamps.sort()
        return timestamps[-1] - timestamps[0]
    
    @staticmethod
    def group_by_time_window(entries: List[Dict], window_minutes: int = 5) -> Dict[datetime, List[Dict]]:
        """
        Group log entries by time windows
        
        Args:
            entries: List of log entries
            window_minutes: Size of time window in minutes
            
        Returns:
            Dictionary mapping window start times to entries
        """
        
        windows = {}
        
        for entry in entries:
            timestamp_str = entry.get('timestamp', '')
            dt = TimeUtils.parse_timestamp(timestamp_str)
            
            if dt:
                # Calculate window start time
                window_start = dt.replace(
                    minute=(dt.minute // window_minutes) * window_minutes,
                    second=0,
                    microsecond=0
                )
                
                if window_start not in windows:
                    windows[window_start] = []
                
                windows[window_start].append(entry)
        
        return windows
    
    @staticmethod
    def detect_periodic_pattern(timestamps: List[datetime], tolerance_seconds: int = 30) -> Dict:
        """
        Detect if timestamps follow a periodic pattern (e.g., beaconing)
        
        Args:
            timestamps: List of datetime objects
            tolerance_seconds: Allowed deviation from average interval
            
        Returns:
            Dictionary with pattern analysis results
        """
        
        if len(timestamps) < 3:
            return {'is_periodic': False, 'reason': 'Insufficient data points'}
        
        # Sort timestamps
        timestamps.sort()
        
        # Calculate intervals between consecutive timestamps
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return {'is_periodic': False, 'reason': 'No intervals calculated'}
        
        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals)
        
        # Check for consistency
        consistent_intervals = 0
        for interval in intervals:
            if abs(interval - avg_interval) <= tolerance_seconds:
                consistent_intervals += 1
        
        consistency_percentage = (consistent_intervals / len(intervals)) * 100
        
        # Determine if pattern is periodic
        is_periodic = consistency_percentage >= 70  # 70% of intervals must be consistent
        
        return {
            'is_periodic': is_periodic,
            'avg_interval_seconds': avg_interval,
            'consistency_percentage': consistency_percentage,
            'consistent_intervals': consistent_intervals,
            'total_intervals': len(intervals),
            'period_description': TimeUtils.format_duration_seconds(avg_interval),
            'confidence': 'HIGH' if consistency_percentage >= 80 else 'MEDIUM' if consistency_percentage >= 70 else 'LOW'
        }
    
    @staticmethod
    def is_business_hours(dt: datetime, start_hour: int = 9, end_hour: int = 17) -> bool:
        """
        Check if datetime falls within business hours
        
        Args:
            dt: datetime to check
            start_hour: Business day start hour (24h format)
            end_hour: Business day end hour (24h format)
            
        Returns:
            True if within business hours, False otherwise
        """
        
        # Check if it's a weekday (Monday=0, Sunday=6)
        if dt.weekday() >= 5:  # Weekend
            return False
        
        # Check if within business hours
        return start_hour <= dt.hour < end_hour
    
    @staticmethod
    def analyze_time_distribution(entries: List[Dict]) -> Dict:
        """
        Analyze time distribution of log entries
        
        Args:
            entries: List of log entries with timestamps
            
        Returns:
            Dictionary with time distribution analysis
        """
        
        hour_counts = [0] * 24
        weekday_counts = [0] * 7  # Monday=0, Sunday=6
        business_hours_count = 0
        off_hours_count = 0
        weekend_count = 0
        
        valid_timestamps = 0
        
        for entry in entries:
            timestamp_str = entry.get('timestamp', '')
            dt = TimeUtils.parse_timestamp(timestamp_str)
            
            if dt:
                valid_timestamps += 1
                
                # Hour distribution
                hour_counts[dt.hour] += 1
                
                # Weekday distribution
                weekday_counts[dt.weekday()] += 1
                
                # Business hours analysis
                if TimeUtils.is_business_hours(dt):
                    business_hours_count += 1
                else:
                    off_hours_count += 1
                
                # Weekend analysis
                if dt.weekday() >= 5:
                    weekend_count += 1
        
        if valid_timestamps == 0:
            return {'error': 'No valid timestamps found'}
        
        # Find peak hours
        peak_hour = hour_counts.index(max(hour_counts))
        peak_weekday = weekday_counts.index(max(weekday_counts))
        
        weekday_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        return {
            'total_entries': len(entries),
            'valid_timestamps': valid_timestamps,
            'hour_distribution': hour_counts,
            'weekday_distribution': weekday_counts,
            'peak_hour': peak_hour,
            'peak_weekday': weekday_names[peak_weekday],
            'business_hours_count': business_hours_count,
            'off_hours_count': off_hours_count,
            'weekend_count': weekend_count,
            'business_hours_percentage': (business_hours_count / valid_timestamps) * 100,
            'off_hours_percentage': (off_hours_count / valid_timestamps) * 100,
            'weekend_percentage': (weekend_count / valid_timestamps) * 100
        }
    
    @staticmethod
    def find_time_anomalies(entries: List[Dict], threshold_multiplier: float = 3.0) -> List[Dict]:
        """
        Find time-based anomalies in log entries
        
        Args:
            entries: List of log entries
            threshold_multiplier: Multiplier for standard deviation threshold
            
        Returns:
            List of anomalous time periods
        """
        
        # Group entries by hour
        hourly_groups = TimeUtils.group_by_time_window(entries, window_minutes=60)
        
        if len(hourly_groups) < 3:
            return []
        
        # Count entries per hour
        hourly_counts = list(hourly_groups.values())
        counts = [len(group) for group in hourly_counts]
        
        # Calculate statistics
        avg_count = sum(counts) / len(counts)
        variance = sum((x - avg_count) ** 2 for x in counts) / len(counts)
        std_dev = variance ** 0.5
        
        # Find anomalies
        anomalies = []
        threshold = avg_count + (threshold_multiplier * std_dev)
        
        for time_window, group in hourly_groups.items():
            entry_count = len(group)
            
            if entry_count > threshold:
                anomalies.append({
                    'time_window': time_window.isoformat(),
                    'entry_count': entry_count,
                    'expected_count': avg_count,
                    'deviation': entry_count - avg_count,
                    'anomaly_score': (entry_count - avg_count) / std_dev if std_dev > 0 else 0,
                    'severity': 'HIGH' if entry_count > threshold * 1.5 else 'MEDIUM'
                })
        
        return sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)
    
    @staticmethod
    def calculate_activity_rate(entries: List[Dict], window_minutes: int = 60) -> Dict:
        """
        Calculate activity rate (entries per time window)
        
        Args:
            entries: List of log entries
            window_minutes: Time window size in minutes
            
        Returns:
            Dictionary with activity rate statistics
        """
        
        if not entries:
            return {'error': 'No entries provided'}
        
        time_windows = TimeUtils.group_by_time_window(entries, window_minutes)
        
        if not time_windows:
            return {'error': 'No valid timestamps found'}
        
        # Calculate rates
        rates = [len(group) for group in time_windows.values()]
        
        return {
            'total_windows': len(time_windows),
            'avg_rate': sum(rates) / len(rates),
            'max_rate': max(rates),
            'min_rate': min(rates),
            'window_minutes': window_minutes,
            'rate_description': f"Average {sum(rates) / len(rates):.1f} entries per {window_minutes} minutes"
        }
    
    @staticmethod
    def format_duration(td: timedelta) -> str:
        """
        Format timedelta in human-readable format
        
        Args:
            td: timedelta object
            
        Returns:
            Human-readable duration string
        """
        
        total_seconds = int(td.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d {hours}h"
    
    @staticmethod
    def format_duration_seconds(seconds: float) -> str:
        """
        Format duration in seconds to human-readable format
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Human-readable duration string
        """
        
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        else:
            return f"{seconds/86400:.1f} days"
    
    @staticmethod
    def get_time_context(dt: datetime) -> str:
        """
        Get contextual description of a datetime
        
        Args:
            dt: datetime object
            
        Returns:
            Context description string
        """
        
        now = datetime.now()
        
        # Calculate relative time
        if dt.date() == now.date():
            time_context = "Today"
        elif dt.date() == (now - timedelta(days=1)).date():
            time_context = "Yesterday"
        elif dt.date() > (now - timedelta(days=7)).date():
            time_context = "This week"
        else:
            time_context = "Older"
        
        # Add time of day context
        hour = dt.hour
        if 5 <= hour < 12:
            time_of_day = "Morning"
        elif 12 <= hour < 17:
            time_of_day = "Afternoon"
        elif 17 <= hour < 21:
            time_of_day = "Evening"
        else:
            time_of_day = "Night"
        
        # Business hours context
        business_context = "Business hours" if TimeUtils.is_business_hours(dt) else "Off-hours"
        
        return f"{time_context}, {time_of_day}, {business_context}"
    
    @staticmethod
    def create_timeline(entries: List[Dict], max_points: int = 50) -> List[Dict]:
        """
        Create a timeline representation of log entries
        
        Args:
            entries: List of log entries
            max_points: Maximum number of timeline points
            
        Returns:
            List of timeline points
        """
        
        if not entries:
            return []
        
        # Parse and sort timestamps
        timestamped_entries = []
        for entry in entries:
            dt = TimeUtils.parse_timestamp(entry.get('timestamp', ''))
            if dt:
                timestamped_entries.append((dt, entry))
        
        if not timestamped_entries:
            return []
        
        timestamped_entries.sort(key=lambda x: x[0])
        
        # If we have fewer entries than max_points, return all
        if len(timestamped_entries) <= max_points:
            return [
                {
                    'timestamp': dt.isoformat(),
                    'count': 1,
                    'sample_entry': entry
                }
                for dt, entry in timestamped_entries
            ]
        
        # Group entries into time buckets
        start_time = timestamped_entries[0][0]
        end_time = timestamped_entries[-1][0]
        time_span = end_time - start_time
        bucket_size = time_span / max_points
        
        timeline = []
        current_bucket_start = start_time
        current_bucket_entries = []
        
        for dt, entry in timestamped_entries:
            if dt >= current_bucket_start + bucket_size:
                # Finalize current bucket
                if current_bucket_entries:
                    timeline.append({
                        'timestamp': current_bucket_start.isoformat(),
                        'count': len(current_bucket_entries),
                        'sample_entry': current_bucket_entries[0][1]  # First entry as sample
                    })
                
                # Start new bucket
                current_bucket_start += bucket_size
                current_bucket_entries = [(dt, entry)]
            else:
                current_bucket_entries.append((dt, entry))
        
        # Don't forget the last bucket
        if current_bucket_entries:
            timeline.append({
                'timestamp': current_bucket_start.isoformat(),
                'count': len(current_bucket_entries),
                'sample_entry': current_bucket_entries[0][1]
            })
        
        return timeline
