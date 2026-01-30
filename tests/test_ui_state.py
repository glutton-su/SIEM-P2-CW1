"""
Unit tests for UI state management.
Tests event counting, filtering, and state management without GUI.
"""

import unittest
import sys
import os
from collections import deque
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MockSIEMApplication:
    """Mock SIEM application for testing state management without GUI"""
    
    def __init__(self):
        # Event storage
        self.events = deque(maxlen=5000)
        self.alerts = deque(maxlen=500)
        
        # Statistics
        self.event_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        self.category_counts = {}
        self.hourly_counts = {}
        
        # State
        self.is_monitoring = False
        self.alert_threshold = 'HIGH'
    
    def add_event(self, event):
        """Add event to system"""
        self.events.appendleft(event)
        
        # Update severity count
        severity = event.get('severity', 'INFO')
        if severity in self.event_counts:
            self.event_counts[severity] += 1
        
        # Update category count
        category = event.get('category', 'Unknown')
        self.category_counts[category] = self.category_counts.get(category, 0) + 1
        
        # Update hourly count
        timestamp = event.get('timestamp', '')
        if timestamp:
            hour = timestamp.split(' ')[1].split(':')[0] if ' ' in timestamp else '00'
            self.hourly_counts[hour] = self.hourly_counts.get(hour, 0) + 1
        
        # Check for alert
        if self._should_alert(event):
            self.add_alert(event)
    
    def add_alert(self, event):
        """Add alert"""
        alert = event.copy()
        alert['alert_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alerts.appendleft(alert)
    
    def _should_alert(self, event):
        """Determine if event should trigger alert"""
        severity = event.get('severity', 'INFO')
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        if severity not in severity_order:
            return False
        
        event_level = severity_order.index(severity)
        threshold_level = severity_order.index(self.alert_threshold)
        
        return event_level >= threshold_level
    
    def get_total_events(self):
        """Get total event count"""
        return sum(self.event_counts.values())
    
    def get_events_by_severity(self, severity):
        """Get events filtered by severity"""
        return [e for e in self.events if e.get('severity') == severity]
    
    def get_events_by_category(self, category):
        """Get events filtered by category"""
        return [e for e in self.events if e.get('category') == category]
    
    def search_events(self, query):
        """Search events by query string"""
        query = query.lower()
        return [
            e for e in self.events 
            if query in str(e.get('message', '')).lower() or
               query in str(e.get('source', '')).lower()
        ]
    
    def clear_events(self):
        """Clear all events"""
        self.events.clear()
        self.alerts.clear()
        for key in self.event_counts:
            self.event_counts[key] = 0
        self.category_counts.clear()
        self.hourly_counts.clear()


class TestEventCounting(unittest.TestCase):
    """Test event counting functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = MockSIEMApplication()
    
    def test_initial_counts_zero(self):
        """Test that initial counts are zero"""
        for severity, count in self.app.event_counts.items():
            self.assertEqual(count, 0, f"{severity} should be 0")
    
    def test_single_event_count(self):
        """Test counting single event"""
        self.app.add_event({'severity': 'HIGH', 'category': 'Test'})
        
        self.assertEqual(self.app.event_counts['HIGH'], 1)
        self.assertEqual(self.app.get_total_events(), 1)
    
    def test_multiple_events_same_severity(self):
        """Test counting multiple events of same severity"""
        for _ in range(5):
            self.app.add_event({'severity': 'INFO', 'category': 'Test'})
        
        self.assertEqual(self.app.event_counts['INFO'], 5)
    
    def test_multiple_severities(self):
        """Test counting events of different severities"""
        self.app.add_event({'severity': 'CRITICAL'})
        self.app.add_event({'severity': 'HIGH'})
        self.app.add_event({'severity': 'HIGH'})
        self.app.add_event({'severity': 'MEDIUM'})
        self.app.add_event({'severity': 'LOW'})
        self.app.add_event({'severity': 'INFO'})
        
        self.assertEqual(self.app.event_counts['CRITICAL'], 1)
        self.assertEqual(self.app.event_counts['HIGH'], 2)
        self.assertEqual(self.app.event_counts['MEDIUM'], 1)
        self.assertEqual(self.app.event_counts['LOW'], 1)
        self.assertEqual(self.app.event_counts['INFO'], 1)
        self.assertEqual(self.app.get_total_events(), 6)
    
    def test_category_counting(self):
        """Test category counting"""
        self.app.add_event({'severity': 'INFO', 'category': 'Authentication'})
        self.app.add_event({'severity': 'HIGH', 'category': 'Authentication'})
        self.app.add_event({'severity': 'INFO', 'category': 'Network'})
        
        self.assertEqual(self.app.category_counts['Authentication'], 2)
        self.assertEqual(self.app.category_counts['Network'], 1)
    
    def test_unknown_severity_handling(self):
        """Test handling of unknown severity"""
        self.app.add_event({'severity': 'UNKNOWN', 'category': 'Test'})
        
        # Should not crash, unknown severity not counted
        self.assertEqual(self.app.get_total_events(), 0)


class TestAlertGeneration(unittest.TestCase):
    """Test alert generation based on threshold"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = MockSIEMApplication()
    
    def test_high_threshold_default(self):
        """Test that default threshold is HIGH"""
        self.assertEqual(self.app.alert_threshold, 'HIGH')
    
    def test_alert_for_high_event(self):
        """Test alert generated for HIGH severity"""
        self.app.add_event({
            'severity': 'HIGH',
            'message': 'Test high event'
        })
        
        self.assertEqual(len(self.app.alerts), 1)
    
    def test_alert_for_critical_event(self):
        """Test alert generated for CRITICAL severity"""
        self.app.add_event({
            'severity': 'CRITICAL',
            'message': 'Test critical event'
        })
        
        self.assertEqual(len(self.app.alerts), 1)
    
    def test_no_alert_for_low_event(self):
        """Test no alert for LOW severity with HIGH threshold"""
        self.app.add_event({
            'severity': 'LOW',
            'message': 'Test low event'
        })
        
        self.assertEqual(len(self.app.alerts), 0)
    
    def test_no_alert_for_info_event(self):
        """Test no alert for INFO severity"""
        self.app.add_event({
            'severity': 'INFO',
            'message': 'Test info event'
        })
        
        self.assertEqual(len(self.app.alerts), 0)
    
    def test_medium_threshold(self):
        """Test alert with MEDIUM threshold"""
        self.app.alert_threshold = 'MEDIUM'
        
        self.app.add_event({'severity': 'MEDIUM'})
        self.app.add_event({'severity': 'LOW'})
        
        self.assertEqual(len(self.app.alerts), 1)
    
    def test_critical_threshold(self):
        """Test alert with CRITICAL threshold"""
        self.app.alert_threshold = 'CRITICAL'
        
        self.app.add_event({'severity': 'HIGH'})
        self.app.add_event({'severity': 'CRITICAL'})
        
        self.assertEqual(len(self.app.alerts), 1)
    
    def test_alert_contains_event_data(self):
        """Test that alert contains original event data"""
        event = {
            'severity': 'HIGH',
            'source': 'Test-Source',
            'message': 'Test message',
            'category': 'Test'
        }
        
        self.app.add_event(event)
        
        alert = self.app.alerts[0]
        self.assertEqual(alert['source'], 'Test-Source')
        self.assertEqual(alert['message'], 'Test message')
    
    def test_alert_has_timestamp(self):
        """Test that alert has alert_time timestamp"""
        self.app.add_event({'severity': 'HIGH'})
        
        alert = self.app.alerts[0]
        self.assertIn('alert_time', alert)


class TestEventFiltering(unittest.TestCase):
    """Test event filtering functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = MockSIEMApplication()
        
        # Add test events
        self.app.add_event({
            'severity': 'CRITICAL',
            'category': 'Authentication',
            'source': 'Windows-Security',
            'message': 'Failed login from admin'
        })
        self.app.add_event({
            'severity': 'HIGH',
            'category': 'Authentication',
            'source': 'Syslog-192.168.1.1',
            'message': 'Multiple failed attempts'
        })
        self.app.add_event({
            'severity': 'INFO',
            'category': 'System',
            'source': 'Windows-System',
            'message': 'Service started'
        })
        self.app.add_event({
            'severity': 'MEDIUM',
            'category': 'Network',
            'source': 'Firewall',
            'message': 'Connection blocked'
        })
    
    def test_filter_by_severity(self):
        """Test filtering events by severity"""
        critical_events = self.app.get_events_by_severity('CRITICAL')
        
        self.assertEqual(len(critical_events), 1)
        self.assertEqual(critical_events[0]['severity'], 'CRITICAL')
    
    def test_filter_by_category(self):
        """Test filtering events by category"""
        auth_events = self.app.get_events_by_category('Authentication')
        
        self.assertEqual(len(auth_events), 2)
    
    def test_search_in_message(self):
        """Test searching in message content"""
        results = self.app.search_events('failed')
        
        self.assertEqual(len(results), 2)
    
    def test_search_in_source(self):
        """Test searching in source"""
        results = self.app.search_events('syslog')
        
        self.assertEqual(len(results), 1)
    
    def test_search_case_insensitive(self):
        """Test that search is case insensitive"""
        results = self.app.search_events('FAILED')
        
        self.assertEqual(len(results), 2)
    
    def test_search_no_results(self):
        """Test search with no matching results"""
        results = self.app.search_events('nonexistent')
        
        self.assertEqual(len(results), 0)


class TestEventStorage(unittest.TestCase):
    """Test event storage and limits"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = MockSIEMApplication()
    
    def test_events_stored_in_order(self):
        """Test events stored in reverse chronological order"""
        self.app.add_event({'id': 1})
        self.app.add_event({'id': 2})
        self.app.add_event({'id': 3})
        
        # Most recent first (deque appendleft)
        self.assertEqual(self.app.events[0]['id'], 3)
        self.assertEqual(self.app.events[1]['id'], 2)
        self.assertEqual(self.app.events[2]['id'], 1)
    
    def test_max_events_limit(self):
        """Test that events are limited to maxlen"""
        # Add more events than maxlen
        for i in range(6000):
            self.app.add_event({'id': i, 'severity': 'INFO'})
        
        # Should be limited to 5000
        self.assertLessEqual(len(self.app.events), 5000)
    
    def test_max_alerts_limit(self):
        """Test that alerts are limited to maxlen"""
        # Add many high severity events
        for i in range(600):
            self.app.add_event({'id': i, 'severity': 'HIGH'})
        
        # Should be limited to 500
        self.assertLessEqual(len(self.app.alerts), 500)
    
    def test_clear_events(self):
        """Test clearing all events"""
        # Add events
        for _ in range(10):
            self.app.add_event({'severity': 'HIGH', 'category': 'Test'})
        
        self.app.clear_events()
        
        self.assertEqual(len(self.app.events), 0)
        self.assertEqual(len(self.app.alerts), 0)
        self.assertEqual(self.app.get_total_events(), 0)
        self.assertEqual(len(self.app.category_counts), 0)


class TestMonitoringState(unittest.TestCase):
    """Test monitoring state management"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = MockSIEMApplication()
    
    def test_initial_state_not_monitoring(self):
        """Test initial monitoring state is False"""
        self.assertFalse(self.app.is_monitoring)
    
    def test_start_monitoring(self):
        """Test starting monitoring"""
        self.app.is_monitoring = True
        self.assertTrue(self.app.is_monitoring)
    
    def test_stop_monitoring(self):
        """Test stopping monitoring"""
        self.app.is_monitoring = True
        self.app.is_monitoring = False
        
        self.assertFalse(self.app.is_monitoring)


if __name__ == '__main__':
    unittest.main(verbosity=2)
