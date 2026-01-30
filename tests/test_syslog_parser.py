"""
Unit tests for Syslog parsing functionality.
Tests priority extraction, message parsing, and pattern matching.
"""

import unittest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.utils.event_queue import EventQueue


class MockSyslogServer:
    """Mock SyslogServer for testing parse functionality without network"""
    
    def __init__(self, event_queue):
        self.event_queue = event_queue
        # Import patterns
        from siem.config import SECURITY_PATTERNS
        self.security_patterns = SECURITY_PATTERNS
    
    def _parse_syslog(self, message, source_ip):
        """Parse syslog message - extracted from SyslogServer"""
        import re
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Try to extract syslog priority
        severity = 'INFO'
        priority_match = re.match(r'<(\d+)>', message)
        if priority_match:
            priority = int(priority_match.group(1))
            sev_level = priority % 8
            if sev_level <= 2:
                severity = 'CRITICAL'
            elif sev_level <= 3:
                severity = 'HIGH'
            elif sev_level <= 4:
                severity = 'MEDIUM'
            elif sev_level <= 5:
                severity = 'LOW'
            else:
                severity = 'INFO'
            message = message[priority_match.end():]
        
        # Determine category based on content
        category = 'System'
        event_name = 'Syslog Event'
        
        for pattern, (cat, evt, sev) in self.security_patterns.items():
            if re.search(pattern, message):
                category = cat
                event_name = evt
                if sev in ['CRITICAL', 'HIGH']:
                    severity = sev
                break
        
        return {
            'timestamp': timestamp,
            'severity': severity,
            'source': f"Syslog-{source_ip}",
            'category': category,
            'event': event_name,
            'ip': source_ip,
            'message': message[:300],
            'id': hash(f"{timestamp}{message[:50]}{source_ip}")
        }


class TestSyslogPriorityParsing(unittest.TestCase):
    """Test syslog priority value parsing"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
        self.server = MockSyslogServer(self.queue)
    
    def test_emergency_priority(self):
        """Test priority 0 (Emergency) maps to CRITICAL"""
        # Priority 0 = Facility 0 * 8 + Severity 0
        result = self.server._parse_syslog("<0>System emergency", "127.0.0.1")
        self.assertEqual(result['severity'], 'CRITICAL')
    
    def test_alert_priority(self):
        """Test priority 1 (Alert) maps to CRITICAL"""
        result = self.server._parse_syslog("<1>Alert message", "127.0.0.1")
        self.assertEqual(result['severity'], 'CRITICAL')
    
    def test_critical_priority(self):
        """Test priority 2 (Critical) maps to CRITICAL"""
        result = self.server._parse_syslog("<2>Critical error", "127.0.0.1")
        self.assertEqual(result['severity'], 'CRITICAL')
    
    def test_error_priority(self):
        """Test priority 3 (Error) maps to HIGH"""
        result = self.server._parse_syslog("<3>Error message", "127.0.0.1")
        self.assertEqual(result['severity'], 'HIGH')
    
    def test_warning_priority(self):
        """Test priority 4 (Warning) maps to MEDIUM"""
        result = self.server._parse_syslog("<4>Warning message", "127.0.0.1")
        self.assertEqual(result['severity'], 'MEDIUM')
    
    def test_notice_priority(self):
        """Test priority 5 (Notice) maps to LOW"""
        result = self.server._parse_syslog("<5>Notice message", "127.0.0.1")
        self.assertEqual(result['severity'], 'LOW')
    
    def test_info_priority(self):
        """Test priority 6 (Informational) maps to INFO"""
        result = self.server._parse_syslog("<6>Info message", "127.0.0.1")
        self.assertEqual(result['severity'], 'INFO')
    
    def test_debug_priority(self):
        """Test priority 7 (Debug) maps to INFO"""
        result = self.server._parse_syslog("<7>Debug message", "127.0.0.1")
        self.assertEqual(result['severity'], 'INFO')
    
    def test_facility_included_priority(self):
        """Test priority with facility (kern.error = 3)"""
        # Facility 0 (kern) * 8 + Severity 3 (error) = 3
        result = self.server._parse_syslog("<3>Kernel error", "127.0.0.1")
        self.assertEqual(result['severity'], 'HIGH')
    
    def test_auth_facility_priority(self):
        """Test auth facility priority (auth.warning = 36)"""
        # Facility 4 (auth) * 8 + Severity 4 (warning) = 36
        result = self.server._parse_syslog("<36>Auth warning", "127.0.0.1")
        self.assertEqual(result['severity'], 'MEDIUM')
    
    def test_no_priority_defaults_to_info(self):
        """Test message without priority defaults to INFO"""
        result = self.server._parse_syslog("Plain message without priority", "127.0.0.1")
        self.assertEqual(result['severity'], 'INFO')


class TestSyslogMessageParsing(unittest.TestCase):
    """Test syslog message content parsing"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
        self.server = MockSyslogServer(self.queue)
    
    def test_priority_stripped_from_message(self):
        """Test that priority prefix is removed from message"""
        result = self.server._parse_syslog("<34>Test message content", "127.0.0.1")
        self.assertNotIn('<34>', result['message'])
        self.assertIn('Test message content', result['message'])
    
    def test_source_ip_captured(self):
        """Test that source IP is captured"""
        result = self.server._parse_syslog("<6>Test", "192.168.1.100")
        
        self.assertEqual(result['ip'], '192.168.1.100')
        self.assertEqual(result['source'], 'Syslog-192.168.1.100')
    
    def test_timestamp_format(self):
        """Test timestamp is in expected format"""
        result = self.server._parse_syslog("<6>Test", "127.0.0.1")
        
        # Should be parseable datetime
        try:
            datetime.strptime(result['timestamp'], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail("Timestamp not in expected format")
    
    def test_message_truncation(self):
        """Test long messages are truncated to 300 chars"""
        long_message = "A" * 500
        result = self.server._parse_syslog(f"<6>{long_message}", "127.0.0.1")
        
        self.assertLessEqual(len(result['message']), 300)
    
    def test_event_id_generated(self):
        """Test that unique event ID is generated"""
        result = self.server._parse_syslog("<6>Test", "127.0.0.1")
        
        self.assertIn('id', result)
        self.assertIsNotNone(result['id'])


class TestSyslogPatternMatching(unittest.TestCase):
    """Test security pattern matching in syslog messages"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
        self.server = MockSyslogServer(self.queue)
    
    def test_auth_failure_detection(self):
        """Test authentication failure is detected"""
        messages = [
            "<34>Jan 30 10:00:00 host sshd: Failed password for admin",
            "<34>Login failure for user root",
            "<34>Authentication failed from 10.0.0.1"
        ]
        
        for msg in messages:
            result = self.server._parse_syslog(msg, "127.0.0.1")
            self.assertEqual(result['category'], 'Authentication', 
                f"Failed to detect auth failure: {msg}")
    
    def test_auth_failure_severity_escalation(self):
        """Test that auth failures escalate to HIGH"""
        result = self.server._parse_syslog(
            "<6>Failed login attempt", "127.0.0.1"
        )
        # Even if syslog priority is INFO (6), pattern should escalate to HIGH
        self.assertEqual(result['severity'], 'HIGH')
    
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        result = self.server._parse_syslog(
            "<34>Brute force attack detected from 10.0.0.50", "127.0.0.1"
        )
        
        self.assertEqual(result['severity'], 'CRITICAL')
    
    def test_malware_detection(self):
        """Test malware detection in message"""
        result = self.server._parse_syslog(
            "<34>Malware detected: trojan.gen in /tmp/evil.exe", "127.0.0.1"
        )
        
        self.assertEqual(result['category'], 'Malware')
        self.assertEqual(result['severity'], 'CRITICAL')
    
    def test_service_start_detection(self):
        """Test service start detection"""
        result = self.server._parse_syslog(
            "<6>Service apache2 started", "127.0.0.1"
        )
        
        self.assertEqual(result['category'], 'System')
        self.assertEqual(result['event'], 'Service Started')
    
    def test_no_pattern_match_uses_defaults(self):
        """Test that unmatched messages use default category"""
        result = self.server._parse_syslog(
            "<6>Random log message with no keywords", "127.0.0.1"
        )
        
        self.assertEqual(result['category'], 'System')
        self.assertEqual(result['event'], 'Syslog Event')


class TestSyslogEdgeCases(unittest.TestCase):
    """Test edge cases in syslog parsing"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
        self.server = MockSyslogServer(self.queue)
    
    def test_empty_message(self):
        """Test handling of empty message"""
        result = self.server._parse_syslog("", "127.0.0.1")
        
        self.assertIsNotNone(result)
        self.assertEqual(result['message'], "")
    
    def test_only_priority(self):
        """Test message with only priority"""
        result = self.server._parse_syslog("<6>", "127.0.0.1")
        
        self.assertIsNotNone(result)
        self.assertEqual(result['message'], "")
    
    def test_invalid_priority_format(self):
        """Test message with invalid priority format"""
        result = self.server._parse_syslog("<abc>Test message", "127.0.0.1")
        
        # Should not extract priority, treat as INFO
        self.assertEqual(result['severity'], 'INFO')
        self.assertIn('<abc>', result['message'])
    
    def test_special_characters(self):
        """Test handling of special characters"""
        msg = '<6>Test "quoted" & <escaped> message'
        result = self.server._parse_syslog(msg, "127.0.0.1")
        
        self.assertIn('"quoted"', result['message'])
    
    def test_newlines_in_message(self):
        """Test handling of newlines"""
        msg = "<6>Line 1\nLine 2\nLine 3"
        result = self.server._parse_syslog(msg, "127.0.0.1")
        
        self.assertIn("Line 1", result['message'])
    
    def test_unicode_message(self):
        """Test handling of Unicode content"""
        msg = "<6>用户登录失败 - ユーザー認証"
        result = self.server._parse_syslog(msg, "127.0.0.1")
        
        self.assertIn("用户", result['message'])
    
    def test_ipv6_source(self):
        """Test handling of IPv6 source address"""
        result = self.server._parse_syslog(
            "<6>Test", "::1"
        )
        
        self.assertEqual(result['ip'], '::1')
        self.assertEqual(result['source'], 'Syslog-::1')
    
    def test_large_priority_value(self):
        """Test handling of large priority values"""
        # Facility 23 * 8 + Severity 7 = 191
        result = self.server._parse_syslog("<191>Local7.debug message", "127.0.0.1")
        
        # Severity 7 = debug = INFO
        self.assertEqual(result['severity'], 'INFO')


if __name__ == '__main__':
    unittest.main(verbosity=2)
