"""
Windows Event Log Collector
Collects security events from Windows Event Logs (System, Application, Security).
"""

import threading
import time
import re

# Try to import Windows-specific modules
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    print("Note: pywin32 not installed. Install with: pip install pywin32")

from ..config import WINDOWS_EVENT_MAPPING


class WindowsEventLogCollector:
    """Collects events from Windows Event Logs"""
    
    def __init__(self, event_queue, log_types=None):
        self.event_queue = event_queue
        # Try System and Application first (no admin needed), then Security
        self.log_types = log_types or ['System', 'Application', 'Security']
        self.running = False
        self.last_records = {}
        self.accessible_logs = []
        self.thread = None
        self.initial_load_done = False
        
    def start(self):
        """Start collecting Windows Event Logs"""
        if not HAS_WIN32:
            print("Windows Event Log collection requires pywin32. Install with: pip install pywin32")
            return False
        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        """Stop the collector"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _collect_loop(self):
        """Main collection loop"""
        # First, check which logs are accessible and load initial events
        for log_type in self.log_types:
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                self.last_records[log_type] = total
                self.accessible_logs.append(log_type)
                win32evtlog.CloseEventLog(hand)
                print(f"✓ {log_type} log accessible ({total} events)")
                
                # Load recent events from this log
                self._load_recent_events(log_type, count=50)
                
            except Exception as e:
                print(f"✗ {log_type} log not accessible (needs admin): {e}")
                self.last_records[log_type] = 0
        
        self.initial_load_done = True
        print(f"Monitoring {len(self.accessible_logs)} Windows Event Logs...")
        
        # Now monitor for new events
        while self.running:
            for log_type in self.accessible_logs:
                try:
                    self._read_new_events(log_type)
                except Exception as e:
                    pass  # Silently handle errors
            time.sleep(2)  # Poll every 2 seconds
    
    def _load_recent_events(self, log_type, count=50):
        """Load recent events from a log"""
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events_loaded = 0
            while events_loaded < count:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    if events_loaded >= count:
                        break
                    parsed = self._parse_windows_event(event, log_type)
                    if parsed:
                        self.event_queue.put(parsed)
                        events_loaded += 1
            
            win32evtlog.CloseEventLog(hand)
            print(f"  Loaded {events_loaded} recent events from {log_type}")
        except Exception as e:
            print(f"Error loading events from {log_type}: {e}")
    
    def _read_new_events(self, log_type):
        """Read new events from a specific log"""
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            last_count = self.last_records.get(log_type, total)
            
            if total > last_count:
                # New events available
                new_count = min(total - last_count, 100)  # Max 100 at a time
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                processed = 0
                for event in events:
                    if processed >= new_count:
                        break
                    
                    parsed = self._parse_windows_event(event, log_type)
                    if parsed:
                        self.event_queue.put(parsed)
                    processed += 1
                
                self.last_records[log_type] = total
            
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            pass
    
    def _parse_windows_event(self, event, log_type):
        """Parse a Windows event into our format"""
        try:
            event_id = event.EventID & 0xFFFF  # Mask to get actual ID
            
            # Get event details from mapping or use defaults
            if event_id in WINDOWS_EVENT_MAPPING:
                category, event_name, severity = WINDOWS_EVENT_MAPPING[event_id]
            else:
                # Determine severity from event type
                event_type = event.EventType
                if event_type == win32con.EVENTLOG_ERROR_TYPE:
                    severity = 'HIGH'
                    category = 'System'
                    event_name = 'Error Event'
                elif event_type == win32con.EVENTLOG_WARNING_TYPE:
                    severity = 'MEDIUM'
                    category = 'System'
                    event_name = 'Warning Event'
                elif event_type == win32con.EVENTLOG_AUDIT_FAILURE:
                    severity = 'HIGH'
                    category = 'Security'
                    event_name = 'Audit Failure'
                elif event_type == win32con.EVENTLOG_AUDIT_SUCCESS:
                    severity = 'INFO'
                    category = 'Security'
                    event_name = 'Audit Success'
                else:
                    severity = 'INFO'
                    category = log_type
                    event_name = 'Information Event'
            
            # Get message
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_type)
                if message:
                    message = message[:200]  # Truncate
            except:
                message = f"Event ID {event_id}"
            
            # Extract source IP if present in message
            ip = self._extract_ip(str(message) if message else '')
            
            return {
                'timestamp': event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S"),
                'severity': severity,
                'source': f"Windows-{log_type}",
                'category': category,
                'event': event_name,
                'event_id': event_id,
                'ip': ip or '-',
                'message': message or f"Event ID: {event_id}",
                'computer': event.ComputerName or '-',
                'id': hash(f"{event.TimeGenerated}{event_id}{event.RecordNumber}")
            }
        except Exception as e:
            return None
    
    def _extract_ip(self, text):
        """Extract IP address from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
