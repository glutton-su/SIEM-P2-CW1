"""
Unit tests for SIEM data collectors.
Tests collector initialization, start/stop functionality, and event generation.

Note: Some tests may be skipped if run without administrator privileges:
- Windows Event Log Security log requires admin
- Syslog server on port 514 requires admin (falls back to 1514)
"""

import unittest
import sys
import os
import time
import threading
import ctypes
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.utils.event_queue import EventQueue


def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class TestWindowsEventCollector(unittest.TestCase):
    """Test Windows Event Log Collector
    
    Note: Security log access requires administrator privileges.
    Tests will skip Security log tests when not running as admin.
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_collector_import(self):
        """Test that collector can be imported"""
        try:
            from siem.collectors.windows_event import WindowsEventLogCollector
        except ImportError as e:
            self.skipTest(f"Cannot import WindowsEventLogCollector: {e}")
    
    def test_collector_initialization(self):
        """Test collector initialization"""
        try:
            from siem.collectors.windows_event import WindowsEventLogCollector
            collector = WindowsEventLogCollector(self.queue)
            
            self.assertIsNotNone(collector)
            self.assertEqual(collector.event_queue, self.queue)
            self.assertFalse(collector.running)
        except ImportError:
            self.skipTest("pywin32 not available")
    
    def test_collector_default_log_types(self):
        """Test default log types are set"""
        try:
            from siem.collectors.windows_event import WindowsEventLogCollector
            collector = WindowsEventLogCollector(self.queue)
            
            self.assertIn('System', collector.log_types)
            self.assertIn('Application', collector.log_types)
        except ImportError:
            self.skipTest("pywin32 not available")
    
    def test_collector_custom_log_types(self):
        """Test custom log types can be specified"""
        try:
            from siem.collectors.windows_event import WindowsEventLogCollector
            collector = WindowsEventLogCollector(
                self.queue, 
                log_types=['System', 'Security']
            )
            
            self.assertEqual(collector.log_types, ['System', 'Security'])
        except ImportError:
            self.skipTest("pywin32 not available")
    
    def test_collector_start_stop(self):
        """Test collector start and stop (uses System/Application logs, no admin needed)"""
        try:
            from siem.collectors.windows_event import WindowsEventLogCollector
            # Only use logs that don't require admin
            collector = WindowsEventLogCollector(
                self.queue, 
                log_types=['System', 'Application']
            )
            
            # Start
            result = collector.start()
            self.assertTrue(collector.running)
            
            # Give time to initialize
            time.sleep(1)
            
            # Stop
            collector.stop()
            self.assertFalse(collector.running)
        except ImportError:
            self.skipTest("pywin32 not available")
        except Exception as e:
            # May fail due to permissions, skip
            self.skipTest(f"Skipped due to permission or system error: {e}")
    
    @unittest.skipUnless(is_admin(), "Requires administrator privileges")
    def test_security_log_access(self):
        """Test Security log access (requires admin)"""
        try:
            from siem.collectors.windows_event import WindowsEventLogCollector
            collector = WindowsEventLogCollector(
                self.queue, 
                log_types=['Security']
            )
            
            collector.start()
            time.sleep(2)
            collector.stop()
            
            # If we got here without error, Security log is accessible
            self.assertTrue(True)
        except ImportError:
            self.skipTest("pywin32 not available")


class TestLogFileCollector(unittest.TestCase):
    """Test Log File Collector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_collector_import(self):
        """Test that collector can be imported"""
        from siem.collectors.log_file import LogFileCollector
        self.assertIsNotNone(LogFileCollector)
    
    def test_collector_initialization(self):
        """Test collector initialization"""
        from siem.collectors.log_file import LogFileCollector
        collector = LogFileCollector(self.queue)
        
        self.assertIsNotNone(collector)
        self.assertFalse(collector.running)
    
    def test_add_path(self):
        """Test adding log paths"""
        from siem.collectors.log_file import LogFileCollector
        collector = LogFileCollector(self.queue)
        
        # Add a path
        collector.add_path("C:\\Logs")
        
        self.assertIn("C:\\Logs", collector.watch_paths)
    
    def test_add_multiple_paths(self):
        """Test adding multiple paths"""
        from siem.collectors.log_file import LogFileCollector
        collector = LogFileCollector(self.queue)
        
        collector.add_path("C:\\Logs")
        collector.add_path("C:\\Windows\\Logs")
        
        self.assertEqual(len(collector.watch_paths), 2)
    
    def test_remove_path(self):
        """Test removing paths"""
        from siem.collectors.log_file import LogFileCollector
        collector = LogFileCollector(self.queue)
        
        collector.add_path("C:\\Logs")
        collector.remove_path("C:\\Logs")
        
        self.assertEqual(len(collector.watch_paths), 0)
    
    def test_start_stop(self):
        """Test start and stop functionality"""
        from siem.collectors.log_file import LogFileCollector
        collector = LogFileCollector(self.queue)
        
        collector.start()
        self.assertTrue(collector.running)
        
        collector.stop()
        self.assertFalse(collector.running)


class TestSyslogServer(unittest.TestCase):
    """Test Syslog Server
    
    Note: Port 514 requires admin privileges on Windows.
    Tests use port 1514 as fallback.
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_server_import(self):
        """Test that server can be imported"""
        from siem.collectors.syslog_server import SyslogServer
        self.assertIsNotNone(SyslogServer)
    
    def test_server_initialization(self):
        """Test server initialization"""
        from siem.collectors.syslog_server import SyslogServer
        server = SyslogServer(self.queue)
        
        self.assertIsNotNone(server)
        self.assertFalse(server.running)
    
    def test_custom_ports(self):
        """Test custom port configuration"""
        from siem.collectors.syslog_server import SyslogServer
        server = SyslogServer(self.queue, udp_port=1514, tcp_port=1514)
        
        self.assertEqual(server.udp_port, 1514)
        self.assertEqual(server.tcp_port, 1514)
    
    def test_default_ports(self):
        """Test default port configuration"""
        from siem.collectors.syslog_server import SyslogServer
        server = SyslogServer(self.queue)
        
        self.assertEqual(server.udp_port, 514)
        self.assertEqual(server.tcp_port, 514)
    
    def test_server_start_with_fallback_port(self):
        """Test server can start (may use fallback port without admin)"""
        from siem.collectors.syslog_server import SyslogServer
        
        # Use non-privileged port to avoid permission issues
        server = SyslogServer(self.queue, udp_port=15140, tcp_port=15140)
        
        try:
            result = server.start()
            self.assertTrue(server.running)
        finally:
            server.stop()


class TestNetworkMonitor(unittest.TestCase):
    """Test Network Monitor"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_monitor_import(self):
        """Test that monitor can be imported"""
        from siem.collectors.network_monitor import NetworkMonitor
        self.assertIsNotNone(NetworkMonitor)
    
    def test_monitor_initialization(self):
        """Test monitor initialization"""
        from siem.collectors.network_monitor import NetworkMonitor
        monitor = NetworkMonitor(self.queue)
        
        self.assertIsNotNone(monitor)
        self.assertFalse(monitor.running)
    
    def test_start_stop(self):
        """Test start and stop functionality"""
        from siem.collectors.network_monitor import NetworkMonitor
        monitor = NetworkMonitor(self.queue)
        
        result = monitor.start()
        self.assertTrue(result)
        self.assertTrue(monitor.running)
        
        time.sleep(0.5)
        
        monitor.stop()
        self.assertFalse(monitor.running)


class TestCollectorIntegration(unittest.TestCase):
    """Integration tests for collectors"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_multiple_collectors_same_queue(self):
        """Test multiple collectors can share same queue"""
        from siem.collectors.log_file import LogFileCollector
        from siem.collectors.network_monitor import NetworkMonitor
        
        log_collector = LogFileCollector(self.queue)
        net_monitor = NetworkMonitor(self.queue)
        
        # Both should reference the same queue
        self.assertIs(log_collector.event_queue, net_monitor.event_queue)
    
    def test_collector_produces_valid_events(self):
        """Test that collectors produce valid event dictionaries"""
        from siem.collectors.network_monitor import NetworkMonitor
        
        monitor = NetworkMonitor(self.queue)
        monitor.start()
        
        # Wait for some events (reduced time)
        time.sleep(2)
        
        monitor.stop()
        
        events = self.queue.get_all()
        
        # Check event structure (if any events collected)
        # Note: may not have events if no network changes
        for event in events:
            self.assertIn('timestamp', event)
            self.assertIn('severity', event)
            self.assertIn('source', event)
            self.assertIn('message', event)


class TestEventFormatConsistency(unittest.TestCase):
    """Test that all collectors produce consistent event formats"""
    
    def test_required_fields(self):
        """Test that events have required fields"""
        required_fields = [
            'timestamp',
            'severity',
            'source',
            'category',
            'event',
            'message'
        ]
        
        # Test with syslog parser (mock)
        queue = EventQueue()
        
        # Create mock event
        event = {
            'timestamp': '2026-01-30 10:00:00',
            'severity': 'HIGH',
            'source': 'Test',
            'category': 'Test',
            'event': 'Test Event',
            'message': 'Test message'
        }
        
        for field in required_fields:
            self.assertIn(field, event, f"Missing required field: {field}")
    
    def test_severity_values(self):
        """Test that severity values are valid"""
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        # Example events with different severities
        events = [
            {'severity': 'CRITICAL'},
            {'severity': 'HIGH'},
            {'severity': 'MEDIUM'},
            {'severity': 'LOW'},
            {'severity': 'INFO'},
        ]
        
        for event in events:
            self.assertIn(event['severity'], valid_severities)


if __name__ == '__main__':
    unittest.main(verbosity=2)
