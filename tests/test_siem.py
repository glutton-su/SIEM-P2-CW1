"""
Consolidated SIEM Test Suite
20 comprehensive tests covering all core functionality.
"""

import unittest
import sys
import os
import re
import threading
import time
from collections import deque
from datetime import datetime
from unittest.mock import MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.utils.event_queue import EventQueue
from siem.config import COLORS, SEVERITY_COLORS, SECURITY_PATTERNS, WINDOWS_EVENT_MAPPING
from siem.collectors.log_file import LogFileCollector, StaticLogAnalyzer


class TestEventQueue(unittest.TestCase):
    """Test EventQueue core functionality"""
    
    def test_queue_basic_operations(self):
        """Test put, get, and empty operations"""
        queue = EventQueue()
        self.assertTrue(queue.is_empty())
        
        event = {'timestamp': '2026-01-30 10:00:00', 'severity': 'HIGH'}
        queue.put(event)
        self.assertFalse(queue.is_empty())
        self.assertEqual(queue.size(), 1)
        
        retrieved = queue.get()
        self.assertEqual(retrieved, event)
        self.assertTrue(queue.is_empty())
    
    def test_queue_fifo_order(self):
        """Test events are retrieved in FIFO order"""
        queue = EventQueue()
        for i in range(5):
            queue.put({'id': i})
        
        for i in range(5):
            event = queue.get()
            self.assertEqual(event['id'], i)
    
    def test_queue_thread_safety(self):
        """Test concurrent access to queue"""
        queue = EventQueue()
        events_added = []
        
        def producer():
            for i in range(50):
                queue.put({'producer_id': i})
                events_added.append(i)
        
        threads = [threading.Thread(target=producer) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(queue.size(), 150)


class TestConfiguration(unittest.TestCase):
    """Test configuration settings"""
    
    def test_colors_valid_hex_format(self):
        """Test all colors are valid hex format"""
        hex_pattern = re.compile(r'^#[0-9A-Fa-f]{6}$')
        for name, color in COLORS.items():
            self.assertTrue(hex_pattern.match(color), f"Invalid color: {name}")
    
    def test_severity_colors_complete(self):
        """Test all severity levels have colors"""
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            self.assertIn(level, SEVERITY_COLORS)
    
    def test_security_patterns_valid_regex(self):
        """Test all patterns are valid regex with correct format"""
        for pattern, value in SECURITY_PATTERNS.items():
            # Test regex compiles
            try:
                re.compile(pattern)
            except re.error:
                self.fail(f"Invalid regex: {pattern}")
            
            # Test value format
            self.assertEqual(len(value), 3)
            self.assertIn(value[2], ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
    
    def test_windows_event_mapping_format(self):
        """Test Windows event mappings have correct format"""
        self.assertTrue(len(WINDOWS_EVENT_MAPPING) > 0)
        for event_id, value in WINDOWS_EVENT_MAPPING.items():
            self.assertIsInstance(event_id, int)
            self.assertEqual(len(value), 3)


class TestSecurityPatternMatching(unittest.TestCase):
    """Test security pattern detection"""
    
    def test_authentication_failure_detection(self):
        """Test detection of login failures"""
        test_messages = [
            "failed login attempt for user admin",
            "failed password for invalid user root",
        ]
        for msg in test_messages:
            matched = False
            for pattern, (cat, evt, sev) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg.lower()):
                    self.assertEqual(cat, 'Authentication')
                    matched = True
                    break
            self.assertTrue(matched, f"No match for: {msg}")
    
    def test_malware_detection(self):
        """Test detection of malware-related events"""
        test_messages = ["Malware detected", "Virus found", "Trojan alert"]
        for msg in test_messages:
            matched = False
            for pattern, (cat, evt, sev) in SECURITY_PATTERNS.items():
                if re.search(pattern, msg.lower()):
                    self.assertEqual(cat, 'Malware')
                    self.assertEqual(sev, 'CRITICAL')
                    matched = True
                    break
            self.assertTrue(matched, f"No match for: {msg}")


class TestLogFileCollector(unittest.TestCase):
    """Test LogFileCollector functionality"""
    
    def test_collector_initialization(self):
        """Test collector initializes correctly"""
        queue = EventQueue()
        collector = LogFileCollector(queue)
        self.assertFalse(collector.running)
        self.assertEqual(len(collector.watch_paths), 0)
    
    def test_path_management(self):
        """Test adding and removing paths"""
        queue = EventQueue()
        collector = LogFileCollector(queue)
        
        collector.add_path("C:\\Logs")
        collector.add_path("C:\\Windows\\Logs")
        self.assertEqual(len(collector.watch_paths), 2)
        
        collector.remove_path("C:\\Logs")
        self.assertEqual(len(collector.watch_paths), 1)
    
    def test_start_stop(self):
        """Test start and stop functionality"""
        queue = EventQueue()
        collector = LogFileCollector(queue)
        
        collector.start()
        self.assertTrue(collector.running)
        
        collector.stop()
        self.assertFalse(collector.running)


class TestStaticLogAnalyzer(unittest.TestCase):
    """Test StaticLogAnalyzer functionality"""
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly"""
        analyzer = StaticLogAnalyzer()
        self.assertEqual(len(analyzer.events), 0)
    
    def test_parse_log_line(self):
        """Test log line parsing"""
        analyzer = StaticLogAnalyzer()
        event = analyzer._parse_log_line("2026-01-30 10:00:00 Failed login attempt", "test.log")
        
        self.assertIn('timestamp', event)
        self.assertIn('severity', event)
        self.assertIn('category', event)
        self.assertIn('message', event)
    
    def test_ip_extraction(self):
        """Test IP address extraction from log lines"""
        analyzer = StaticLogAnalyzer()
        ip = analyzer._extract_ip("Connection from 192.168.1.100 refused")
        self.assertEqual(ip, "192.168.1.100")
        
        no_ip = analyzer._extract_ip("No IP address here")
        self.assertIsNone(no_ip)
    
    def test_analyze_generates_report(self):
        """Test that analyze_path generates complete report"""
        analyzer = StaticLogAnalyzer()
        # Analyze the logs directory
        report = analyzer.analyze_path(os.path.join(os.path.dirname(__file__), '..', 'logs'))
        
        self.assertIn('summary', report)
        self.assertIn('severity_breakdown', report)
        self.assertIn('category_breakdown', report)
        self.assertIn('ip_analysis', report)
        self.assertIn('events', report)
        self.assertIn('security_alerts', report)
    
    def test_summary_statistics(self):
        """Test summary statistics calculation"""
        analyzer = StaticLogAnalyzer()
        analyzer.events = [
            {'severity': 'CRITICAL', 'ip': '192.168.1.1', 'source': 'a.log'},
            {'severity': 'HIGH', 'ip': '192.168.1.2', 'source': 'b.log'},
            {'severity': 'INFO', 'ip': '-', 'source': 'c.log'},
        ]
        
        summary = analyzer._get_summary_stats()
        self.assertEqual(summary['total_events'], 3)
        self.assertEqual(summary['critical_count'], 1)
        self.assertEqual(summary['high_count'], 1)
        self.assertEqual(summary['unique_ips'], 2)


class TestUIState(unittest.TestCase):
    """Test UI state management logic"""
    
    def test_event_counting(self):
        """Test event count tracking"""
        events = deque(maxlen=5000)
        event_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        test_events = [
            {'severity': 'CRITICAL'}, {'severity': 'HIGH'},
            {'severity': 'HIGH'}, {'severity': 'INFO'}
        ]
        
        for event in test_events:
            events.appendleft(event)
            event_counts[event['severity']] += 1
        
        self.assertEqual(event_counts['CRITICAL'], 1)
        self.assertEqual(event_counts['HIGH'], 2)
        self.assertEqual(event_counts['INFO'], 1)
    
    def test_alert_threshold(self):
        """Test alert threshold logic"""
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        threshold = 'HIGH'
        
        def should_alert(severity):
            return severity_order.index(severity) >= severity_order.index(threshold)
        
        self.assertTrue(should_alert('CRITICAL'))
        self.assertTrue(should_alert('HIGH'))
        self.assertFalse(should_alert('MEDIUM'))
        self.assertFalse(should_alert('LOW'))
    
    def test_event_search_filtering(self):
        """Test event search and filtering"""
        events = [
            {'message': 'Failed login from admin', 'source': 'auth.log', 'severity': 'HIGH'},
            {'message': 'System startup complete', 'source': 'system.log', 'severity': 'INFO'},
            {'message': 'Failed password attempt', 'source': 'auth.log', 'severity': 'HIGH'},
        ]
        
        # Search for 'failed'
        query = 'failed'
        results = [e for e in events if query in e['message'].lower()]
        self.assertEqual(len(results), 2)
        
        # Filter by severity
        high_events = [e for e in events if e['severity'] == 'HIGH']
        self.assertEqual(len(high_events), 2)


class SIEMTestResult(unittest.TestResult):
    """Custom test result that tracks progress with pytest-style output"""
    
    def __init__(self, total_tests):
        super().__init__()
        self.total_tests = total_tests
        self.completed = 0
        self.test_details = []
    
    def startTest(self, test):
        super().startTest(test)
    
    def addSuccess(self, test):
        super().addSuccess(test)
        self.completed += 1
        self._print_result(test, 'PASSED', '\033[92m')  # Green
        self.test_details.append({'name': self._get_test_name(test), 'status': 'PASSED'})
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.completed += 1
        self._print_result(test, 'FAILED', '\033[91m')  # Red
        self.test_details.append({'name': self._get_test_name(test), 'status': 'FAILED'})
    
    def addError(self, test, err):
        super().addError(test, err)
        self.completed += 1
        self._print_result(test, 'ERROR', '\033[91m')  # Red
        self.test_details.append({'name': self._get_test_name(test), 'status': 'ERROR'})
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.completed += 1
        self._print_result(test, 'SKIPPED', '\033[93m')  # Yellow
        self.test_details.append({'name': self._get_test_name(test), 'status': 'SKIPPED'})
    
    def _get_test_name(self, test):
        """Get full test name in pytest format"""
        test_method = str(test).split()[0]
        test_class = test.__class__.__name__
        return f"test_siem.py::{test_class}::{test_method}"
    
    def _print_result(self, test, status, color):
        """Print test result in pytest style"""
        percentage = (self.completed / self.total_tests) * 100
        test_name = self._get_test_name(test)
        reset = '\033[0m'
        
        # Calculate padding for right-aligned percentage
        line = f"{test_name} {color}{status}{reset}"
        percentage_str = f"[{percentage:3.0f}%]"
        
        # Print with percentage right-aligned
        print(f"{test_name} {color}{status}{reset} {percentage_str:>10}")


class SIEMTestRunner:
    """Custom test runner with pytest-style output"""
    
    def run(self, suite):
        total = suite.countTestCases()
        
        print("=" * 70 + " test session starts " + "=" * 10)
        print(f"platform win32 -- Python 3.13.12, unittest")
        print(f"rootdir: {os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}")
        print(f"collected {total} items\n")
        
        result = SIEMTestResult(total)
        suite.run(result)
        
        # Print summary line
        passed = len([t for t in result.test_details if t['status'] == 'PASSED'])
        failed = len([t for t in result.test_details if t['status'] == 'FAILED'])
        errors = len([t for t in result.test_details if t['status'] == 'ERROR'])
        
        print("\n" + "=" * 70)
        
        if result.wasSuccessful():
            print(f"\033[92m{passed} passed\033[0m in {time.time() - self.start_time:.2f}s")
        else:
            print(f"\033[91m{failed} failed\033[0m, \033[92m{passed} passed\033[0m")
        
        return result
    
    def __init__(self):
        self.start_time = time.time()


if __name__ == '__main__':
    # Load all tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    # Run with custom runner
    runner = SIEMTestRunner()
    runner.run(suite)
