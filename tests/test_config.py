"""
Unit tests for SIEM configuration.
Tests color schemes, security patterns, and event mappings.
"""

import unittest
import re
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.config import COLORS, SEVERITY_COLORS, SECURITY_PATTERNS, WINDOWS_EVENT_MAPPING


class TestColorConfiguration(unittest.TestCase):
    """Test color configuration"""
    
    def test_colors_not_empty(self):
        """Test that COLORS dictionary is not empty"""
        self.assertTrue(len(COLORS) > 0)
    
    def test_required_colors_exist(self):
        """Test that all required color keys exist"""
        required_keys = [
            'bg_dark', 'bg_secondary', 'bg_tertiary',
            'text_primary', 'text_secondary',
            'accent_blue', 'accent_green', 'accent_yellow', 
            'accent_red', 'accent_orange'
        ]
        
        for key in required_keys:
            self.assertIn(key, COLORS, f"Missing required color: {key}")
    
    def test_color_format_valid(self):
        """Test that all colors are valid hex format"""
        hex_pattern = re.compile(r'^#[0-9A-Fa-f]{6}$')
        
        for name, color in COLORS.items():
            self.assertTrue(
                hex_pattern.match(color),
                f"Invalid color format for {name}: {color}"
            )
    
    def test_severity_colors_complete(self):
        """Test that all severity levels have colors"""
        severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        for level in severity_levels:
            self.assertIn(level, SEVERITY_COLORS, 
                         f"Missing color for severity: {level}")
    
    def test_severity_colors_valid(self):
        """Test that severity colors reference valid COLORS"""
        for severity, color in SEVERITY_COLORS.items():
            self.assertTrue(
                color in COLORS.values(),
                f"Severity {severity} color not in COLORS: {color}"
            )


class TestSecurityPatterns(unittest.TestCase):
    """Test security pattern matching"""
    
    def test_patterns_not_empty(self):
        """Test that SECURITY_PATTERNS is not empty"""
        self.assertTrue(len(SECURITY_PATTERNS) > 0)
    
    def test_pattern_value_format(self):
        """Test that all patterns have correct tuple format"""
        for pattern, value in SECURITY_PATTERNS.items():
            self.assertIsInstance(value, tuple, 
                f"Pattern value should be tuple: {pattern}")
            self.assertEqual(len(value), 3, 
                f"Pattern tuple should have 3 elements: {pattern}")
            
            category, event_name, severity = value
            self.assertIsInstance(category, str)
            self.assertIsInstance(event_name, str)
            self.assertIn(severity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
    
    def test_patterns_are_valid_regex(self):
        """Test that all patterns are valid regex"""
        for pattern in SECURITY_PATTERNS.keys():
            try:
                re.compile(pattern)
            except re.error as e:
                self.fail(f"Invalid regex pattern: {pattern}, error: {e}")
    
    def test_authentication_failure_detection(self):
        """Test detection of authentication failures"""
        test_messages = [
            "Failed login attempt for user admin",
            "Authentication failure for root",
            "Password failure on account",
            "failed password for invalid user"
        ]
        
        for msg in test_messages:
            matched = False
            for pattern, (category, _, _) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg):
                    if category == 'Authentication':
                        matched = True
                        break
            self.assertTrue(matched, f"Should detect auth failure: {msg}")
    
    def test_brute_force_detection(self):
        """Test detection of brute force attempts"""
        test_messages = [
            "Brute force attack detected",
            "Multiple failed login attempts",
            "brute-force attack from IP"
        ]
        
        for msg in test_messages:
            matched = False
            for pattern, (_, event_name, severity) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg):
                    self.assertEqual(severity, 'CRITICAL',
                        f"Brute force should be CRITICAL: {msg}")
                    matched = True
                    break
            # At least one should match
            self.assertTrue(matched, f"Should detect brute force: {msg}")
    
    def test_malware_detection(self):
        """Test detection of malware-related events"""
        test_messages = [
            "Malware detected in file.exe",
            "Virus found: trojan.gen",
            "Ransomware activity detected",
            "Trojan horse blocked"
        ]
        
        for msg in test_messages:
            matched = False
            for pattern, (category, _, severity) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg):
                    self.assertEqual(category, 'Malware')
                    self.assertEqual(severity, 'CRITICAL')
                    matched = True
                    break
    
    def test_network_attack_detection(self):
        """Test detection of network attacks"""
        test_messages = [
            "Port scan detected from 192.168.1.100",
            "DDoS attack in progress",
            "DOS attack detected"
        ]
        
        for msg in test_messages:
            for pattern, (category, _, severity) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg):
                    self.assertIn(severity, ['HIGH', 'CRITICAL'])
                    break
    
    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation"""
        test_messages = [
            "Privilege escalation detected",
            "User elevated privileges",
            "privilege escalation attempt"
        ]
        
        for msg in test_messages:
            matched = False
            for pattern, (_, _, severity) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg):
                    self.assertEqual(severity, 'CRITICAL',
                        f"Privilege escalation should be CRITICAL")
                    matched = True
                    break


class TestWindowsEventMapping(unittest.TestCase):
    """Test Windows Event ID mapping"""
    
    def test_mapping_not_empty(self):
        """Test that WINDOWS_EVENT_MAPPING is not empty"""
        self.assertTrue(len(WINDOWS_EVENT_MAPPING) > 0)
    
    def test_mapping_value_format(self):
        """Test that all mappings have correct tuple format"""
        for event_id, value in WINDOWS_EVENT_MAPPING.items():
            self.assertIsInstance(event_id, int, 
                f"Event ID should be int: {event_id}")
            self.assertIsInstance(value, tuple,
                f"Mapping value should be tuple: {event_id}")
            self.assertEqual(len(value), 3,
                f"Mapping tuple should have 3 elements: {event_id}")
            
            category, event_name, severity = value
            self.assertIsInstance(category, str)
            self.assertIsInstance(event_name, str)
            self.assertIn(severity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
    
    def test_login_success_event(self):
        """Test Event ID 4624 (Login Success) mapping"""
        self.assertIn(4624, WINDOWS_EVENT_MAPPING)
        category, event_name, severity = WINDOWS_EVENT_MAPPING[4624]
        
        self.assertEqual(category, 'Authentication')
        self.assertEqual(event_name, 'Login Success')
        self.assertEqual(severity, 'INFO')
    
    def test_login_failed_event(self):
        """Test Event ID 4625 (Login Failed) mapping"""
        self.assertIn(4625, WINDOWS_EVENT_MAPPING)
        category, event_name, severity = WINDOWS_EVENT_MAPPING[4625]
        
        self.assertEqual(category, 'Authentication')
        self.assertEqual(event_name, 'Login Failed')
        self.assertEqual(severity, 'HIGH')
    
    def test_account_lockout_event(self):
        """Test Event ID 4740 (Account Locked) mapping"""
        self.assertIn(4740, WINDOWS_EVENT_MAPPING)
        category, event_name, severity = WINDOWS_EVENT_MAPPING[4740]
        
        self.assertEqual(category, 'Authentication')
        self.assertEqual(severity, 'HIGH')
    
    def test_new_service_installed_event(self):
        """Test Event ID 7045 (New Service Installed) mapping"""
        self.assertIn(7045, WINDOWS_EVENT_MAPPING)
        category, event_name, severity = WINDOWS_EVENT_MAPPING[7045]
        
        self.assertEqual(category, 'System')
        self.assertEqual(event_name, 'New Service Installed')
        self.assertEqual(severity, 'HIGH')
    
    def test_unexpected_shutdown_event(self):
        """Test Event ID 41 (Unexpected Shutdown) mapping"""
        self.assertIn(41, WINDOWS_EVENT_MAPPING)
        category, event_name, severity = WINDOWS_EVENT_MAPPING[41]
        
        self.assertEqual(category, 'System')
        self.assertEqual(severity, 'CRITICAL')
    
    def test_firewall_events_exist(self):
        """Test that firewall event mappings exist"""
        firewall_events = [5152, 5153, 5156, 5157]
        
        for event_id in firewall_events:
            self.assertIn(event_id, WINDOWS_EVENT_MAPPING,
                f"Missing firewall event: {event_id}")
            category, _, _ = WINDOWS_EVENT_MAPPING[event_id]
            self.assertEqual(category, 'Firewall')
    
    def test_audit_policy_change_severity(self):
        """Test that audit policy changes are properly classified"""
        if 4719 in WINDOWS_EVENT_MAPPING:
            _, _, severity = WINDOWS_EVENT_MAPPING[4719]
            self.assertEqual(severity, 'HIGH')


class TestPatternSeverityConsistency(unittest.TestCase):
    """Test consistency between patterns and severity classifications"""
    
    def test_critical_events_are_serious(self):
        """Test that CRITICAL events are for serious security issues"""
        critical_patterns = [
            pattern for pattern, (_, _, severity) 
            in SECURITY_PATTERNS.items() 
            if severity == 'CRITICAL'
        ]
        
        # Should have some critical patterns
        self.assertTrue(len(critical_patterns) > 0,
            "Should have at least some CRITICAL patterns")
    
    def test_info_events_are_non_threatening(self):
        """Test that INFO events are for non-threatening activities"""
        info_patterns = [
            pattern for pattern, (_, event_name, severity) 
            in SECURITY_PATTERNS.items() 
            if severity == 'INFO'
        ]
        
        # INFO patterns should not contain threat keywords
        threat_keywords = ['attack', 'malware', 'threat', 'intrusion', 'brute']
        
        for pattern in info_patterns:
            for keyword in threat_keywords:
                self.assertNotIn(keyword.lower(), pattern.lower(),
                    f"INFO pattern should not contain '{keyword}': {pattern}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
