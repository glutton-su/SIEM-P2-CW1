"""
SIEM - Security Information and Event Management System
A real working SIEM with actual data collection from:
- Windows Event Logs (Security, System, Application)
- Log File Monitoring
- Syslog Server (UDP/TCP)
- Network Traffic Monitoring
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import json
import os
import socket
import re
import subprocess
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path
import queue
import hashlib

# Try to import Windows-specific modules
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    print("Note: pywin32 not installed. Install with: pip install pywin32")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    print("Note: watchdog not installed. Install with: pip install watchdog")

# ==================== Color Scheme ====================
COLORS = {
    'bg_dark': '#0d1117',
    'bg_secondary': '#161b22',
    'bg_tertiary': '#21262d',
    'border': '#30363d',
    'text_primary': '#f0f6fc',
    'text_secondary': '#8b949e',
    'accent_blue': '#58a6ff',
    'accent_green': '#3fb950',
    'accent_yellow': '#d29922',
    'accent_red': '#f85149',
    'accent_purple': '#a371f7',
    'accent_orange': '#db6d28',
    'success': '#238636',
    'warning': '#9e6a03',
    'danger': '#da3633',
    'info': '#1f6feb',
}

SEVERITY_COLORS = {
    'CRITICAL': COLORS['accent_red'],
    'HIGH': COLORS['accent_orange'],
    'MEDIUM': COLORS['accent_yellow'],
    'LOW': COLORS['accent_blue'],
    'INFO': COLORS['accent_green'],
}

# ==================== Security Event Patterns ====================
SECURITY_PATTERNS = {
    # Authentication patterns
    r'(?i)(failed|failure).*(login|logon|auth|password)': ('Authentication', 'Login Failed', 'HIGH'),
    r'(?i)(success).*(login|logon|auth)': ('Authentication', 'Login Success', 'INFO'),
    r'(?i)(logout|logoff)': ('Authentication', 'Logout', 'INFO'),
    r'(?i)(password).*(change|reset|expire)': ('Authentication', 'Password Change', 'MEDIUM'),
    r'(?i)(account).*(lock|disable|block)': ('Authentication', 'Account Locked', 'HIGH'),
    r'(?i)(brute.?force|multiple.?failed)': ('Authentication', 'Brute Force Attempt', 'CRITICAL'),
    
    # Network patterns
    r'(?i)(connection).*(refused|denied|blocked)': ('Network', 'Connection Blocked', 'MEDIUM'),
    r'(?i)(port.?scan|scanning)': ('Network', 'Port Scan Detected', 'HIGH'),
    r'(?i)(ddos|dos.?attack|flood)': ('Network', 'DDoS Attempt', 'CRITICAL'),
    r'(?i)(firewall).*(block|deny|drop)': ('Firewall', 'Packet Dropped', 'MEDIUM'),
    r'(?i)(intrusion|ids|ips).*(detect|alert)': ('Firewall', 'Intrusion Detected', 'CRITICAL'),
    
    # Malware patterns
    r'(?i)(malware|virus|trojan|ransomware|worm)': ('Malware', 'Threat Detected', 'CRITICAL'),
    r'(?i)(quarantine|isolat)': ('Malware', 'Quarantine Action', 'HIGH'),
    r'(?i)(scan).*(complete|finish)': ('Malware', 'Scan Complete', 'INFO'),
    
    # System patterns
    r'(?i)(service).*(start|begin)': ('System', 'Service Started', 'INFO'),
    r'(?i)(service).*(stop|end|terminat)': ('System', 'Service Stopped', 'MEDIUM'),
    r'(?i)(privilege).*(escalat|elevat)': ('System', 'Privilege Escalation', 'CRITICAL'),
    r'(?i)(config|setting).*(change|modif|update)': ('System', 'Configuration Change', 'MEDIUM'),
    r'(?i)(error|critical|fatal)': ('System', 'System Error', 'HIGH'),
    r'(?i)(warning|warn)': ('System', 'System Warning', 'MEDIUM'),
    
    # Data patterns
    r'(?i)(file).*(access|open|read|write|delete)': ('Data', 'File Access', 'LOW'),
    r'(?i)(data).*(export|transfer|copy)': ('Data', 'Data Export', 'MEDIUM'),
    r'(?i)(encrypt|decrypt)': ('Data', 'Encryption Event', 'LOW'),
    r'(?i)(backup).*(complete|success|fail)': ('Data', 'Backup Event', 'INFO'),
    r'(?i)(unauthorized|permission.?denied|access.?denied)': ('Data', 'Unauthorized Access', 'HIGH'),
}

# Windows Event IDs and their meanings (System & Application logs work without admin)
WINDOWS_EVENT_MAPPING = {
    # ===== SYSTEM LOG EVENTS (No admin needed) =====
    1: ('System', 'System Event', 'INFO'),
    6: ('System', 'Driver Loaded', 'INFO'),
    7: ('System', 'Driver Load Failed', 'HIGH'),
    10: ('System', 'Event Processing Error', 'MEDIUM'),
    12: ('System', 'OS Starting', 'INFO'),
    13: ('System', 'OS Shutdown', 'INFO'),
    20: ('System', 'Boot Notification', 'INFO'),
    41: ('System', 'Unexpected Shutdown', 'CRITICAL'),
    104: ('System', 'Event Log Cleared', 'HIGH'),
    1001: ('System', 'Windows Error Report', 'MEDIUM'),
    1014: ('System', 'DNS Resolution Timeout', 'MEDIUM'),
    1074: ('System', 'System Shutdown/Restart', 'INFO'),
    6005: ('System', 'Event Log Started', 'INFO'),
    6006: ('System', 'Event Log Stopped', 'INFO'),
    6008: ('System', 'Unexpected Shutdown', 'HIGH'),
    6009: ('System', 'OS Version Info', 'INFO'),
    6013: ('System', 'System Uptime', 'INFO'),
    7000: ('System', 'Service Start Failed', 'HIGH'),
    7001: ('System', 'Service Dependency Failed', 'HIGH'),
    7009: ('System', 'Service Connect Timeout', 'MEDIUM'),
    7011: ('System', 'Service Timeout', 'MEDIUM'),
    7022: ('System', 'Service Hung', 'HIGH'),
    7023: ('System', 'Service Terminated Error', 'HIGH'),
    7024: ('System', 'Service Terminated', 'MEDIUM'),
    7026: ('System', 'Boot Driver Failed', 'HIGH'),
    7031: ('System', 'Service Crashed', 'HIGH'),
    7032: ('System', 'Service Recovery', 'MEDIUM'),
    7034: ('System', 'Service Crashed Unexpectedly', 'HIGH'),
    7035: ('System', 'Service Control Sent', 'INFO'),
    7036: ('System', 'Service State Changed', 'INFO'),
    7040: ('System', 'Service Start Type Changed', 'MEDIUM'),
    7045: ('System', 'New Service Installed', 'HIGH'),
    10000: ('System', 'COM+ Event', 'INFO'),
    10001: ('System', 'COM+ Error', 'MEDIUM'),
    10010: ('System', 'COM Server Start Timeout', 'MEDIUM'),
    10016: ('System', 'DCOM Permission Error', 'MEDIUM'),
    
    # ===== APPLICATION LOG EVENTS (No admin needed) =====
    0: ('Application', 'Application Event', 'INFO'),
    1000: ('Application', 'Application Error', 'HIGH'),
    1001: ('Application', 'Application Fault', 'HIGH'),
    1002: ('Application', 'Application Hang', 'HIGH'),
    1026: ('Application', '.NET Runtime Error', 'HIGH'),
    1033: ('Application', 'Windows Installer', 'INFO'),
    1034: ('Application', 'Windows Update Removed', 'MEDIUM'),
    1040: ('Application', 'DCOM Service Started', 'INFO'),
    11707: ('Application', 'Installation Success', 'INFO'),
    11708: ('Application', 'Installation Failed', 'HIGH'),
    11724: ('Application', 'Uninstall Complete', 'INFO'),
    1034: ('Application', 'App Reconfigured', 'INFO'),
    
    # ===== SECURITY LOG EVENTS (Needs admin) =====
    4624: ('Authentication', 'Login Success', 'INFO'),
    4625: ('Authentication', 'Login Failed', 'HIGH'),
    4634: ('Authentication', 'Logout', 'INFO'),
    4648: ('Authentication', 'Explicit Credential Logon', 'MEDIUM'),
    4672: ('Authentication', 'Admin Login', 'MEDIUM'),
    4720: ('Authentication', 'User Account Created', 'MEDIUM'),
    4722: ('Authentication', 'User Account Enabled', 'LOW'),
    4723: ('Authentication', 'Password Change Attempt', 'LOW'),
    4724: ('Authentication', 'Password Reset Attempt', 'MEDIUM'),
    4725: ('Authentication', 'User Account Disabled', 'MEDIUM'),
    4726: ('Authentication', 'User Account Deleted', 'HIGH'),
    4740: ('Authentication', 'Account Locked Out', 'HIGH'),
    4767: ('Authentication', 'Account Unlocked', 'MEDIUM'),
    4768: ('Authentication', 'Kerberos TGT Request', 'INFO'),
    4769: ('Authentication', 'Kerberos Service Ticket', 'INFO'),
    4771: ('Authentication', 'Kerberos Pre-Auth Failed', 'HIGH'),
    4776: ('Authentication', 'NTLM Authentication', 'INFO'),
    
    # Object Access
    4656: ('Data', 'Object Handle Request', 'LOW'),
    4658: ('Data', 'Object Handle Closed', 'LOW'),
    4660: ('Data', 'Object Deleted', 'MEDIUM'),
    4663: ('Data', 'Object Access Attempt', 'LOW'),
    4670: ('Data', 'Permissions Changed', 'MEDIUM'),
    
    # Policy Changes
    4704: ('System', 'User Right Assigned', 'MEDIUM'),
    4705: ('System', 'User Right Removed', 'MEDIUM'),
    4706: ('System', 'Trust Created', 'HIGH'),
    4713: ('System', 'Kerberos Policy Changed', 'HIGH'),
    4719: ('System', 'Audit Policy Changed', 'HIGH'),
    4739: ('System', 'Domain Policy Changed', 'HIGH'),
    
    # Firewall Events
    5152: ('Firewall', 'Packet Dropped', 'LOW'),
    5153: ('Firewall', 'Packet Permitted', 'INFO'),
    5154: ('Firewall', 'Listen Allowed', 'INFO'),
    5155: ('Firewall', 'Listen Blocked', 'MEDIUM'),
    5156: ('Firewall', 'Connection Allowed', 'INFO'),
    5157: ('Firewall', 'Connection Blocked', 'MEDIUM'),
}


class EventQueue:
    """Thread-safe event queue"""
    def __init__(self):
        self.queue = queue.Queue()
    
    def put(self, event):
        self.queue.put(event)
    
    def get(self):
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_all(self):
        events = []
        while True:
            event = self.get()
            if event is None:
                break
            events.append(event)
        return events


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
        if not HAS_WIN32:
            print("Windows Event Log collection requires pywin32. Install with: pip install pywin32")
            return False
        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
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


class LogFileCollector:
    """Monitors and collects events from log files"""
    
    def __init__(self, event_queue, watch_paths=None):
        self.event_queue = event_queue
        self.watch_paths = watch_paths or []
        self.running = False
        self.file_positions = {}
        self.observer = None
        self.thread = None
    
    def add_path(self, path):
        """Add a path to monitor"""
        if path not in self.watch_paths:
            self.watch_paths.append(path)
    
    def remove_path(self, path):
        """Remove a path from monitoring"""
        if path in self.watch_paths:
            self.watch_paths.remove(path)
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
        if self.thread:
            self.thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            for path in self.watch_paths:
                try:
                    if os.path.isfile(path):
                        self._read_file(path)
                    elif os.path.isdir(path):
                        self._read_directory(path)
                except Exception as e:
                    print(f"Error monitoring {path}: {e}")
            time.sleep(1)
    
    def _read_directory(self, directory):
        """Read all log files in a directory"""
        log_extensions = ['.log', '.txt', '.csv', '.json']
        try:
            for file in os.listdir(directory):
                if any(file.lower().endswith(ext) for ext in log_extensions):
                    self._read_file(os.path.join(directory, file))
        except Exception as e:
            pass
    
    def _read_file(self, filepath):
        """Read new lines from a log file"""
        try:
            current_size = os.path.getsize(filepath)
            last_pos = self.file_positions.get(filepath, 0)
            
            # If file was truncated, start from beginning
            if current_size < last_pos:
                last_pos = 0
            
            if current_size > last_pos:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    self.file_positions[filepath] = f.tell()
                
                for line in new_lines:
                    line = line.strip()
                    if line:
                        event = self._parse_log_line(line, filepath)
                        if event:
                            self.event_queue.put(event)
        except Exception as e:
            pass
    
    def _parse_log_line(self, line, filepath):
        """Parse a log line into our event format"""
        # Try to extract timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Common timestamp patterns
        ts_patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in ts_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp = match.group(1)
                except:
                    pass
                break
        
        # Determine category and severity based on content
        category = 'System'
        event_name = 'Log Entry'
        severity = 'INFO'
        
        for pattern, (cat, evt, sev) in SECURITY_PATTERNS.items():
            if re.search(pattern, line):
                category = cat
                event_name = evt
                severity = sev
                break
        
        # Extract IP if present
        ip = self._extract_ip(line)
        
        return {
            'timestamp': timestamp,
            'severity': severity,
            'source': os.path.basename(filepath),
            'category': category,
            'event': event_name,
            'ip': ip or '-',
            'message': line[:300],
            'id': hash(f"{timestamp}{line[:50]}")
        }
    
    def _extract_ip(self, text):
        """Extract IP address from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None


class SyslogServer:
    """Simple Syslog server (UDP and TCP)"""
    
    def __init__(self, event_queue, udp_port=514, tcp_port=514):
        self.event_queue = event_queue
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.running = False
        self.udp_socket = None
        self.tcp_socket = None
        self.udp_thread = None
        self.tcp_thread = None
    
    def start(self):
        self.running = True
        
        # Start UDP listener
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind(('0.0.0.0', self.udp_port))
            self.udp_socket.settimeout(1)
            self.udp_thread = threading.Thread(target=self._udp_listener, daemon=True)
            self.udp_thread.start()
            print(f"Syslog UDP server started on port {self.udp_port}")
        except Exception as e:
            print(f"Could not start UDP syslog on port {self.udp_port}: {e}")
            # Try alternative port
            try:
                self.udp_port = 1514
                self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.udp_socket.bind(('0.0.0.0', self.udp_port))
                self.udp_socket.settimeout(1)
                self.udp_thread = threading.Thread(target=self._udp_listener, daemon=True)
                self.udp_thread.start()
                print(f"Syslog UDP server started on port {self.udp_port}")
            except Exception as e2:
                print(f"Could not start UDP syslog: {e2}")
        
        # Start TCP listener
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_socket.listen(5)
            self.tcp_socket.settimeout(1)
            self.tcp_thread = threading.Thread(target=self._tcp_listener, daemon=True)
            self.tcp_thread.start()
            print(f"Syslog TCP server started on port {self.tcp_port}")
        except Exception as e:
            # Try alternative port
            try:
                self.tcp_port = 1514
                self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
                self.tcp_socket.listen(5)
                self.tcp_socket.settimeout(1)
                self.tcp_thread = threading.Thread(target=self._tcp_listener, daemon=True)
                self.tcp_thread.start()
                print(f"Syslog TCP server started on port {self.tcp_port}")
            except Exception as e2:
                print(f"Could not start TCP syslog: {e2}")
        
        return True
    
    def stop(self):
        self.running = False
        if self.udp_socket:
            self.udp_socket.close()
        if self.tcp_socket:
            self.tcp_socket.close()
    
    def _udp_listener(self):
        """UDP syslog listener"""
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                message = data.decode('utf-8', errors='ignore')
                event = self._parse_syslog(message, addr[0])
                if event:
                    self.event_queue.put(event)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass
    
    def _tcp_listener(self):
        """TCP syslog listener"""
        while self.running:
            try:
                conn, addr = self.tcp_socket.accept()
                threading.Thread(target=self._handle_tcp_client, 
                               args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass
    
    def _handle_tcp_client(self, conn, addr):
        """Handle TCP client connection"""
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if data:
                message = data.decode('utf-8', errors='ignore')
                for line in message.split('\n'):
                    if line.strip():
                        event = self._parse_syslog(line, addr[0])
                        if event:
                            self.event_queue.put(event)
        except Exception as e:
            pass
        finally:
            conn.close()
    
    def _parse_syslog(self, message, source_ip):
        """Parse syslog message"""
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
        
        for pattern, (cat, evt, sev) in SECURITY_PATTERNS.items():
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


class NetworkMonitor:
    """Monitor network connections"""
    
    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.running = False
        self.thread = None
        self.known_connections = set()
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Monitor network connections using netstat"""
        while self.running:
            try:
                result = subprocess.run(
                    ['netstat', '-an'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                current_connections = set()
                for line in result.stdout.split('\n'):
                    if 'ESTABLISHED' in line or 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            conn_key = f"{parts[1]}:{parts[2]}"
                            current_connections.add(conn_key)
                            
                            if conn_key not in self.known_connections:
                                # New connection detected
                                self._create_network_event(line, parts)
                
                self.known_connections = current_connections
                
            except Exception as e:
                pass
            
            time.sleep(5)  # Check every 5 seconds
    
    def _create_network_event(self, line, parts):
        """Create event for new network connection"""
        try:
            local_addr = parts[1] if len(parts) > 1 else '-'
            remote_addr = parts[2] if len(parts) > 2 else '-'
            state = parts[3] if len(parts) > 3 else 'UNKNOWN'
            
            # Extract IP from remote address
            ip = remote_addr.split(':')[0] if ':' in remote_addr else remote_addr
            
            event = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'INFO',
                'source': 'Network-Monitor',
                'category': 'Network',
                'event': f"Connection {state}",
                'ip': ip,
                'message': f"Local: {local_addr} -> Remote: {remote_addr} ({state})",
                'id': hash(f"{datetime.now()}{line}")
            }
            
            self.event_queue.put(event)
        except Exception as e:
            pass


# ==================== UI Components ====================
class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    def __init__(self, parent, text, command=None, width=120, height=36, 
                 bg_color=COLORS['accent_blue'], hover_color=None, **kwargs):
        super().__init__(parent, width=width, height=height, 
                        bg=parent.cget('bg'), highlightthickness=0, **kwargs)
        
        self.bg_color = bg_color
        self.hover_color = hover_color or self._lighten_color(bg_color)
        self.command = command
        self.text = text
        self.width = width
        self.height = height
        
        self._draw_button(self.bg_color)
        
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
    
    def _lighten_color(self, color):
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        factor = 1.2
        r = min(255, int(r * factor))
        g = min(255, int(g * factor))
        b = min(255, int(b * factor))
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def _draw_button(self, color):
        self.delete('all')
        radius = 8
        self.create_arc(0, 0, radius*2, radius*2, start=90, extent=90, 
                       fill=color, outline=color)
        self.create_arc(self.width-radius*2, 0, self.width, radius*2, 
                       start=0, extent=90, fill=color, outline=color)
        self.create_arc(0, self.height-radius*2, radius*2, self.height, 
                       start=180, extent=90, fill=color, outline=color)
        self.create_arc(self.width-radius*2, self.height-radius*2, 
                       self.width, self.height, start=270, extent=90, 
                       fill=color, outline=color)
        self.create_rectangle(radius, 0, self.width-radius, self.height, 
                             fill=color, outline=color)
        self.create_rectangle(0, radius, self.width, self.height-radius, 
                             fill=color, outline=color)
        self.create_text(self.width//2, self.height//2, text=self.text, 
                        fill='white', font=('Segoe UI', 10, 'bold'))
    
    def _on_enter(self, e):
        self._draw_button(self.hover_color)
    
    def _on_leave(self, e):
        self._draw_button(self.bg_color)
    
    def _on_click(self, e):
        if self.command:
            self.command()
    
    def update_text(self, text):
        self.text = text
        self._draw_button(self.bg_color)


class StatCard(tk.Frame):
    """Modern stat card widget"""
    def __init__(self, parent, title, value, icon="●", color=COLORS['accent_blue'], **kwargs):
        super().__init__(parent, bg=COLORS['bg_secondary'], **kwargs)
        
        self.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        icon_label = tk.Label(self, text=icon, font=('Segoe UI', 24), 
                             fg=color, bg=COLORS['bg_secondary'])
        icon_label.pack(side='left', padx=15, pady=15)
        
        text_frame = tk.Frame(self, bg=COLORS['bg_secondary'])
        text_frame.pack(side='left', fill='both', expand=True, pady=15, padx=(0, 15))
        
        title_label = tk.Label(text_frame, text=title, font=('Segoe UI', 10), 
                              fg=COLORS['text_secondary'], bg=COLORS['bg_secondary'])
        title_label.pack(anchor='w')
        
        self.value_label = tk.Label(text_frame, text=value, font=('Segoe UI', 20, 'bold'), 
                                   fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        self.value_label.pack(anchor='w')
    
    def update_value(self, value):
        self.value_label.configure(text=value)


class MiniChart(tk.Canvas):
    """Simple bar chart widget"""
    def __init__(self, parent, data=None, width=200, height=80, **kwargs):
        super().__init__(parent, width=width, height=height, 
                        bg=COLORS['bg_secondary'], highlightthickness=0, **kwargs)
        self.data = data or [0] * 12
        self.width = width
        self.height = height
        self.draw_chart()
    
    def draw_chart(self):
        self.delete('all')
        if not self.data or max(self.data) == 0:
            return
        
        bar_width = (self.width - 20) / len(self.data)
        max_val = max(self.data) or 1
        
        for i, val in enumerate(self.data):
            bar_height = (val / max_val) * (self.height - 20)
            x1 = 10 + i * bar_width + 2
            x2 = 10 + (i + 1) * bar_width - 2
            y1 = self.height - 10 - bar_height
            y2 = self.height - 10
            
            intensity = val / max_val
            color = self._interpolate_color(COLORS['accent_blue'], COLORS['accent_purple'], intensity)
            self.create_rectangle(x1, y1, x2, y2, fill=color, outline='')
    
    def _interpolate_color(self, color1, color2, factor):
        r1, g1, b1 = int(color1[1:3], 16), int(color1[3:5], 16), int(color1[5:7], 16)
        r2, g2, b2 = int(color2[1:3], 16), int(color2[3:5], 16), int(color2[5:7], 16)
        r = int(r1 + (r2 - r1) * factor)
        g = int(g1 + (g2 - g1) * factor)
        b = int(b1 + (b2 - b1) * factor)
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def update_data(self, data):
        self.data = data
        self.draw_chart()


class CircularProgress(tk.Canvas):
    """Circular progress indicator"""
    def __init__(self, parent, size=100, progress=0, color=COLORS['accent_green'], **kwargs):
        super().__init__(parent, width=size, height=size, 
                        bg=COLORS['bg_secondary'], highlightthickness=0, **kwargs)
        self.size = size
        self.color = color
        self.progress = progress
        self.draw_progress()
    
    def draw_progress(self):
        self.delete('all')
        padding = 10
        
        self.create_oval(padding, padding, self.size-padding, self.size-padding,
                        outline=COLORS['border'], width=8)
        
        extent = (self.progress / 100) * 360
        self.create_arc(padding, padding, self.size-padding, self.size-padding,
                       start=90, extent=-extent, outline=self.color, 
                       width=8, style='arc')
        
        self.create_text(self.size//2, self.size//2, text=f"{self.progress}%",
                        font=('Segoe UI', 14, 'bold'), fill=COLORS['text_primary'])
    
    def update_progress(self, progress):
        self.progress = min(100, max(0, progress))
        self.draw_progress()


class SIEMApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ SIEM - Security Information & Event Management")
        self.root.geometry("1400x850")
        self.root.configure(bg=COLORS['bg_dark'])
        self.root.minsize(1200, 700)
        
        # Data storage
        self.events = deque(maxlen=5000)
        self.alerts = deque(maxlen=500)
        self.event_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        self.hourly_events = [0] * 24
        self.category_counts = {}
        
        # Event queue for thread-safe communication
        self.event_queue = EventQueue()
        
        # Data collectors
        self.windows_collector = WindowsEventLogCollector(self.event_queue)
        self.log_collector = LogFileCollector(self.event_queue)
        self.syslog_server = SyslogServer(self.event_queue)
        self.network_monitor = NetworkMonitor(self.event_queue)
        
        # Monitoring state
        self.is_monitoring = False
        self.collector_status = {
            'windows': False,
            'logfiles': False,
            'syslog': False,
            'network': False
        }
        
        # Configure styles
        self.setup_styles()
        
        # Build UI
        self.create_ui()
        
        # Start event processing
        self.process_events()
        
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("Custom.Treeview",
                       background=COLORS['bg_secondary'],
                       foreground=COLORS['text_primary'],
                       fieldbackground=COLORS['bg_secondary'],
                       borderwidth=0,
                       font=('Segoe UI', 9))
        style.configure("Custom.Treeview.Heading",
                       background=COLORS['bg_tertiary'],
                       foreground=COLORS['text_primary'],
                       borderwidth=0,
                       font=('Segoe UI', 9, 'bold'))
        style.map("Custom.Treeview",
                 background=[('selected', COLORS['accent_blue'])],
                 foreground=[('selected', 'white')])
        
        style.configure("Custom.Vertical.TScrollbar",
                       background=COLORS['bg_tertiary'],
                       troughcolor=COLORS['bg_secondary'],
                       borderwidth=0,
                       arrowcolor=COLORS['text_secondary'])
        
        style.configure("Custom.TNotebook",
                       background=COLORS['bg_dark'],
                       borderwidth=0)
        style.configure("Custom.TNotebook.Tab",
                       background=COLORS['bg_tertiary'],
                       foreground=COLORS['text_secondary'],
                       padding=[20, 10],
                       font=('Segoe UI', 10))
        style.map("Custom.TNotebook.Tab",
                 background=[('selected', COLORS['bg_secondary'])],
                 foreground=[('selected', COLORS['text_primary'])])

    def create_ui(self):
        """Create the main UI layout"""
        self.create_header()
        
        main_container = tk.Frame(self.root, bg=COLORS['bg_dark'])
        main_container.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.create_sidebar(main_container)
        
        content_frame = tk.Frame(main_container, bg=COLORS['bg_dark'])
        content_frame.pack(side='left', fill='both', expand=True, padx=(20, 0))
        
        self.notebook = ttk.Notebook(content_frame, style="Custom.TNotebook")
        self.notebook.pack(fill='both', expand=True)
        
        self.create_dashboard_tab()
        self.create_events_tab()
        self.create_alerts_tab()
        self.create_sources_tab()
        self.create_analytics_tab()
        self.create_settings_tab()
    
    def create_header(self):
        """Create the application header"""
        header = tk.Frame(self.root, bg=COLORS['bg_secondary'], height=70)
        header.pack(fill='x', padx=20, pady=20)
        header.pack_propagate(False)
        
        title_frame = tk.Frame(header, bg=COLORS['bg_secondary'])
        title_frame.pack(side='left', padx=20)
        
        logo = tk.Label(title_frame, text="🛡️", font=('Segoe UI', 28), 
                       bg=COLORS['bg_secondary'])
        logo.pack(side='left')
        
        title = tk.Label(title_frame, text="SIEM", font=('Segoe UI', 22, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        title.pack(side='left', padx=(10, 5))
        
        subtitle = tk.Label(title_frame, text="Real-Time Security Monitoring",
                           font=('Segoe UI', 10), fg=COLORS['text_secondary'],
                           bg=COLORS['bg_secondary'])
        subtitle.pack(side='left', padx=10)
        
        # Status indicators
        status_frame = tk.Frame(header, bg=COLORS['bg_secondary'])
        status_frame.pack(side='left', padx=30)
        
        self.status_labels = {}
        statuses = [('WIN', 'windows'), ('LOG', 'logfiles'), ('SYS', 'syslog'), ('NET', 'network')]
        for label, key in statuses:
            frame = tk.Frame(status_frame, bg=COLORS['bg_secondary'])
            frame.pack(side='left', padx=5)
            indicator = tk.Label(frame, text="●", font=('Segoe UI', 10),
                               fg=COLORS['text_secondary'], bg=COLORS['bg_secondary'])
            indicator.pack(side='left')
            tk.Label(frame, text=label, font=('Segoe UI', 8),
                    fg=COLORS['text_secondary'], bg=COLORS['bg_secondary']).pack(side='left')
            self.status_labels[key] = indicator
        
        controls = tk.Frame(header, bg=COLORS['bg_secondary'])
        controls.pack(side='right', padx=20)
        
        self.time_label = tk.Label(controls, font=('Segoe UI', 10),
                                  fg=COLORS['text_secondary'],
                                  bg=COLORS['bg_secondary'])
        self.time_label.pack(side='left', padx=20)
        self.update_time()
        
        self.monitor_btn = ModernButton(controls, "▶ Start Monitor", 
                                       command=self.toggle_monitoring,
                                       width=140, bg_color=COLORS['success'])
        self.monitor_btn.pack(side='left', padx=5)
    
    def create_sidebar(self, parent):
        """Create the left sidebar with stats"""
        sidebar = tk.Frame(parent, bg=COLORS['bg_secondary'], width=280)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        
        sidebar_header = tk.Label(sidebar, text="📊 Live Statistics", 
                                 font=('Segoe UI', 14, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        sidebar_header.pack(pady=20, padx=20, anchor='w')
        
        self.stat_cards = {}
        
        stats_data = [
            ('total_events', 'Total Events', '0', '📋', COLORS['accent_blue']),
            ('critical', 'Critical Alerts', '0', '🔴', COLORS['accent_red']),
            ('high', 'High Priority', '0', '🟠', COLORS['accent_orange']),
            ('medium', 'Medium Priority', '0', '🟡', COLORS['accent_yellow']),
            ('sources', 'Active Sources', '0', '🖥️', COLORS['accent_purple']),
        ]
        
        for key, title, value, icon, color in stats_data:
            card = StatCard(sidebar, title, value, icon, color)
            card.pack(fill='x', padx=15, pady=5)
            self.stat_cards[key] = card
        
        chart_label = tk.Label(sidebar, text="📈 Events (Last 24h)",
                              font=('Segoe UI', 12, 'bold'),
                              fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        chart_label.pack(pady=(20, 10), padx=20, anchor='w')
        
        self.mini_chart = MiniChart(sidebar, width=250, height=100)
        self.mini_chart.pack(padx=15, pady=5)
        
        health_label = tk.Label(sidebar, text="💚 Collection Status",
                               font=('Segoe UI', 12, 'bold'),
                               fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        health_label.pack(pady=(20, 10), padx=20, anchor='w')
        
        self.health_progress = CircularProgress(sidebar, size=120, progress=0,
                                                color=COLORS['accent_green'])
        self.health_progress.pack(pady=10)
    
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(dashboard, text="  📊 Dashboard  ")
        
        # Status banner
        status_frame = tk.Frame(dashboard, bg=COLORS['bg_secondary'])
        status_frame.pack(fill='x', padx=10, pady=10)
        
        self.status_banner = tk.Label(status_frame, 
                                     text="⚠️ Click 'Start Monitor' to begin collecting real security events",
                                     font=('Segoe UI', 12),
                                     fg=COLORS['accent_yellow'], bg=COLORS['bg_secondary'])
        self.status_banner.pack(pady=15, padx=20)
        
        # Stats row
        stats_row = tk.Frame(dashboard, bg=COLORS['bg_dark'])
        stats_row.pack(fill='x', padx=10, pady=10)
        
        severity_stats = [
            ('Critical', COLORS['accent_red'], 'critical_dash'),
            ('High', COLORS['accent_orange'], 'high_dash'),
            ('Medium', COLORS['accent_yellow'], 'medium_dash'),
            ('Low', COLORS['accent_blue'], 'low_dash'),
            ('Info', COLORS['accent_green'], 'info_dash'),
        ]
        
        self.dash_stats = {}
        for severity, color, key in severity_stats:
            frame = tk.Frame(stats_row, bg=COLORS['bg_secondary'])
            frame.pack(side='left', fill='both', expand=True, padx=5)
            
            label = tk.Label(frame, text=severity, font=('Segoe UI', 10),
                           fg=COLORS['text_secondary'], bg=COLORS['bg_secondary'])
            label.pack(pady=(15, 5))
            
            value = tk.Label(frame, text="0", font=('Segoe UI', 24, 'bold'),
                           fg=color, bg=COLORS['bg_secondary'])
            value.pack(pady=(0, 15))
            
            self.dash_stats[key] = value
        
        # Recent events preview
        recent_frame = tk.Frame(dashboard, bg=COLORS['bg_secondary'])
        recent_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        recent_header = tk.Frame(recent_frame, bg=COLORS['bg_secondary'])
        recent_header.pack(fill='x', padx=15, pady=15)
        
        recent_title = tk.Label(recent_header, text="🔔 Live Event Feed",
                               font=('Segoe UI', 14, 'bold'),
                               fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        recent_title.pack(side='left')
        
        self.recent_events_frame = tk.Frame(recent_frame, bg=COLORS['bg_secondary'])
        self.recent_events_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
    
    def create_events_tab(self):
        """Create the events tab with log viewer"""
        events_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(events_frame, text="  📋 Events  ")
        
        # Toolbar
        toolbar = tk.Frame(events_frame, bg=COLORS['bg_secondary'])
        toolbar.pack(fill='x', padx=10, pady=10)
        
        search_frame = tk.Frame(toolbar, bg=COLORS['bg_secondary'])
        search_frame.pack(side='left', padx=15, pady=10)
        
        tk.Label(search_frame, text="🔍", font=('Segoe UI', 12),
                bg=COLORS['bg_secondary']).pack(side='left')
        
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.filter_events_by_search())
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                               font=('Segoe UI', 10), width=30,
                               bg=COLORS['bg_tertiary'], fg=COLORS['text_primary'],
                               insertbackground=COLORS['text_primary'],
                               relief='flat')
        search_entry.pack(side='left', padx=10, ipady=8)
        
        filter_frame = tk.Frame(toolbar, bg=COLORS['bg_secondary'])
        filter_frame.pack(side='left', padx=20, pady=10)
        
        filters = [('All', None), ('Critical', 'CRITICAL'), ('High', 'HIGH'), 
                  ('Medium', 'MEDIUM'), ('Low', 'LOW')]
        
        for text, severity in filters:
            btn = ModernButton(filter_frame, text, 
                             command=lambda s=severity: self.filter_events(s),
                             width=80, height=32,
                             bg_color=SEVERITY_COLORS.get(severity, COLORS['bg_tertiary']))
            btn.pack(side='left', padx=3)
        
        action_frame = tk.Frame(toolbar, bg=COLORS['bg_secondary'])
        action_frame.pack(side='right', padx=15, pady=10)
        
        export_btn = ModernButton(action_frame, "📤 Export", 
                                 command=self.export_events,
                                 width=100, bg_color=COLORS['accent_purple'])
        export_btn.pack(side='left', padx=5)
        
        clear_btn = ModernButton(action_frame, "🗑️ Clear", 
                                command=self.clear_events,
                                width=100, bg_color=COLORS['danger'])
        clear_btn.pack(side='left', padx=5)
        
        # Events treeview
        tree_frame = tk.Frame(events_frame, bg=COLORS['bg_secondary'])
        tree_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        columns = ('timestamp', 'severity', 'source', 'category', 'event', 'ip', 'message')
        self.events_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show='headings', style="Custom.Treeview")
        
        headings = [('timestamp', 'Timestamp', 140), ('severity', 'Severity', 80),
                   ('source', 'Source', 120), ('category', 'Category', 100),
                   ('event', 'Event', 150), ('ip', 'IP Address', 110),
                   ('message', 'Details', 300)]
        
        for col, text, width in headings:
            self.events_tree.heading(col, text=text)
            self.events_tree.column(col, width=width, minwidth=60)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                 command=self.events_tree.yview,
                                 style="Custom.Vertical.TScrollbar")
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        self.events_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
        self.events_tree.tag_configure('CRITICAL', foreground=COLORS['accent_red'])
        self.events_tree.tag_configure('HIGH', foreground=COLORS['accent_orange'])
        self.events_tree.tag_configure('MEDIUM', foreground=COLORS['accent_yellow'])
        self.events_tree.tag_configure('LOW', foreground=COLORS['accent_blue'])
        self.events_tree.tag_configure('INFO', foreground=COLORS['accent_green'])
        
        # Double-click to view details
        self.events_tree.bind('<Double-1>', self.show_event_details)
    
    def create_alerts_tab(self):
        """Create the alerts tab"""
        alerts_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(alerts_frame, text="  🚨 Alerts  ")
        
        header = tk.Frame(alerts_frame, bg=COLORS['bg_secondary'])
        header.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header, text="🚨 Security Alerts (Critical & High Priority)",
                font=('Segoe UI', 16, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left', padx=20, pady=15)
        
        actions = tk.Frame(header, bg=COLORS['bg_secondary'])
        actions.pack(side='right', padx=20, pady=15)
        
        ack_btn = ModernButton(actions, "✓ Acknowledge All",
                              command=self.acknowledge_alerts,
                              width=140, bg_color=COLORS['success'])
        ack_btn.pack(side='left', padx=5)
        
        self.alerts_container = tk.Frame(alerts_frame, bg=COLORS['bg_dark'])
        self.alerts_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        canvas = tk.Canvas(self.alerts_container, bg=COLORS['bg_dark'], 
                          highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.alerts_container, orient='vertical',
                                 command=canvas.yview,
                                 style="Custom.Vertical.TScrollbar")
        
        self.alerts_scroll_frame = tk.Frame(canvas, bg=COLORS['bg_dark'])
        
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        
        canvas.create_window((0, 0), window=self.alerts_scroll_frame, anchor='nw')
        self.alerts_scroll_frame.bind('<Configure>', 
                                     lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
    
    def create_sources_tab(self):
        """Create the data sources configuration tab"""
        sources_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(sources_frame, text="  🔌 Sources  ")
        
        title = tk.Label(sources_frame, text="🔌 Data Source Configuration",
                        font=('Segoe UI', 18, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_dark'])
        title.pack(pady=20, padx=20, anchor='w')
        
        container = tk.Frame(sources_frame, bg=COLORS['bg_dark'])
        container.pack(fill='both', expand=True, padx=20)
        
        # Windows Event Logs
        win_frame = tk.LabelFrame(container, text=" 🪟 Windows Event Logs ",
                                 font=('Segoe UI', 11, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        win_frame.pack(fill='x', pady=10)
        
        win_status = "✅ pywin32 installed" if HAS_WIN32 else "❌ pywin32 not installed (pip install pywin32)"
        tk.Label(win_frame, text=win_status,
                font=('Segoe UI', 10),
                fg=COLORS['accent_green'] if HAS_WIN32 else COLORS['accent_red'],
                bg=COLORS['bg_secondary']).pack(pady=10, padx=20, anchor='w')
        
        self.win_enabled = tk.BooleanVar(value=HAS_WIN32)
        tk.Checkbutton(win_frame, text="Enable Windows Event Log Collection",
                      variable=self.win_enabled,
                      font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(pady=5, padx=20, anchor='w')
        
        tk.Label(win_frame, text="Collects from: Security, System, Application logs",
                font=('Segoe UI', 9),
                fg=COLORS['text_secondary'],
                bg=COLORS['bg_secondary']).pack(pady=(0, 10), padx=20, anchor='w')
        
        # Log File Monitoring
        log_frame = tk.LabelFrame(container, text=" 📁 Log File Monitoring ",
                                 font=('Segoe UI', 11, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        log_frame.pack(fill='x', pady=10)
        
        self.log_enabled = tk.BooleanVar(value=True)
        tk.Checkbutton(log_frame, text="Enable Log File Monitoring",
                      variable=self.log_enabled,
                      font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(pady=10, padx=20, anchor='w')
        
        path_frame = tk.Frame(log_frame, bg=COLORS['bg_secondary'])
        path_frame.pack(fill='x', padx=20, pady=5)
        
        tk.Label(path_frame, text="Watch Paths:",
                font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        self.log_paths_var = tk.StringVar()
        self.log_paths_entry = tk.Entry(path_frame, textvariable=self.log_paths_var,
                                       font=('Segoe UI', 10), width=50,
                                       bg=COLORS['bg_tertiary'], fg=COLORS['text_primary'],
                                       insertbackground=COLORS['text_primary'])
        self.log_paths_entry.pack(side='left', padx=10)
        
        browse_btn = ModernButton(path_frame, "📂 Browse",
                                 command=self.browse_log_path,
                                 width=90, height=30,
                                 bg_color=COLORS['accent_blue'])
        browse_btn.pack(side='left', padx=5)
        
        tk.Label(log_frame, text="Separate multiple paths with semicolons (;)",
                font=('Segoe UI', 9),
                fg=COLORS['text_secondary'],
                bg=COLORS['bg_secondary']).pack(pady=(0, 10), padx=20, anchor='w')
        
        # Syslog Server
        syslog_frame = tk.LabelFrame(container, text=" 📡 Syslog Server ",
                                    font=('Segoe UI', 11, 'bold'),
                                    fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        syslog_frame.pack(fill='x', pady=10)
        
        self.syslog_enabled = tk.BooleanVar(value=True)
        tk.Checkbutton(syslog_frame, text="Enable Syslog Server",
                      variable=self.syslog_enabled,
                      font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(pady=10, padx=20, anchor='w')
        
        port_frame = tk.Frame(syslog_frame, bg=COLORS['bg_secondary'])
        port_frame.pack(fill='x', padx=20, pady=5)
        
        tk.Label(port_frame, text="UDP/TCP Port:",
                font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        self.syslog_port_var = tk.StringVar(value="514")
        tk.Entry(port_frame, textvariable=self.syslog_port_var,
                font=('Segoe UI', 10), width=10,
                bg=COLORS['bg_tertiary'], fg=COLORS['text_primary'],
                insertbackground=COLORS['text_primary']).pack(side='left', padx=10)
        
        tk.Label(syslog_frame, text="Note: Port 514 may require admin privileges. Falls back to 1514 if unavailable.",
                font=('Segoe UI', 9),
                fg=COLORS['text_secondary'],
                bg=COLORS['bg_secondary']).pack(pady=(0, 10), padx=20, anchor='w')
        
        # Network Monitor
        net_frame = tk.LabelFrame(container, text=" 🌐 Network Monitor ",
                                 font=('Segoe UI', 11, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        net_frame.pack(fill='x', pady=10)
        
        self.net_enabled = tk.BooleanVar(value=True)
        tk.Checkbutton(net_frame, text="Enable Network Connection Monitoring",
                      variable=self.net_enabled,
                      font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(pady=10, padx=20, anchor='w')
        
        tk.Label(net_frame, text="Monitors new network connections using netstat",
                font=('Segoe UI', 9),
                fg=COLORS['text_secondary'],
                bg=COLORS['bg_secondary']).pack(pady=(0, 10), padx=20, anchor='w')
    
    def create_analytics_tab(self):
        """Create the analytics tab"""
        analytics_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(analytics_frame, text="  📈 Analytics  ")
        
        title = tk.Label(analytics_frame, text="📈 Security Analytics",
                        font=('Segoe UI', 18, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_dark'])
        title.pack(pady=20, padx=20, anchor='w')
        
        charts_frame = tk.Frame(analytics_frame, bg=COLORS['bg_dark'])
        charts_frame.pack(fill='both', expand=True, padx=10)
        
        left_chart = tk.Frame(charts_frame, bg=COLORS['bg_secondary'])
        left_chart.pack(side='left', fill='both', expand=True, padx=5, pady=10)
        
        tk.Label(left_chart, text="Events by Category",
                font=('Segoe UI', 12, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(pady=15)
        
        self.category_chart = tk.Canvas(left_chart, width=400, height=300,
                                       bg=COLORS['bg_secondary'], highlightthickness=0)
        self.category_chart.pack(pady=10, padx=20)
        
        right_chart = tk.Frame(charts_frame, bg=COLORS['bg_secondary'])
        right_chart.pack(side='right', fill='both', expand=True, padx=5, pady=10)
        
        tk.Label(right_chart, text="Events by Severity",
                font=('Segoe UI', 12, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(pady=15)
        
        self.severity_chart = tk.Canvas(right_chart, width=400, height=300,
                                       bg=COLORS['bg_secondary'], highlightthickness=0)
        self.severity_chart.pack(pady=10, padx=20)
        
        self.update_analytics_charts()
    
    def create_settings_tab(self):
        """Create the settings tab"""
        settings_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(settings_frame, text="  ⚙️ Settings  ")
        
        title = tk.Label(settings_frame, text="⚙️ Settings",
                        font=('Segoe UI', 18, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_dark'])
        title.pack(pady=20, padx=20, anchor='w')
        
        container = tk.Frame(settings_frame, bg=COLORS['bg_secondary'])
        container.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Alert Settings
        alert_section = tk.LabelFrame(container, text=" 🔔 Alert Settings ",
                                     font=('Segoe UI', 11, 'bold'),
                                     fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        alert_section.pack(fill='x', padx=20, pady=20)
        
        threshold_frame = tk.Frame(alert_section, bg=COLORS['bg_secondary'])
        threshold_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(threshold_frame, text="Alert on severity level:",
                font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        self.threshold_var = tk.StringVar(value="HIGH")
        threshold_combo = ttk.Combobox(threshold_frame, textvariable=self.threshold_var,
                                       values=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                                       state='readonly', width=15)
        threshold_combo.pack(side='left', padx=10)
        
        # Storage Settings
        storage_section = tk.LabelFrame(container, text=" 💾 Storage Settings ",
                                       font=('Segoe UI', 11, 'bold'),
                                       fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        storage_section.pack(fill='x', padx=20, pady=20)
        
        max_events_frame = tk.Frame(storage_section, bg=COLORS['bg_secondary'])
        max_events_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(max_events_frame, text="Maximum events to keep in memory:",
                font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        self.max_events_var = tk.StringVar(value="5000")
        tk.Spinbox(max_events_frame, from_=1000, to=50000, increment=1000,
                  textvariable=self.max_events_var,
                  width=10, font=('Segoe UI', 10),
                  bg=COLORS['bg_tertiary'], fg=COLORS['text_primary']).pack(side='left', padx=10)
        
        save_btn = ModernButton(container, "💾 Save Settings",
                               command=self.save_settings,
                               width=150, bg_color=COLORS['success'])
        save_btn.pack(pady=20)
    
    def update_time(self):
        """Update the time display"""
        now = datetime.now()
        self.time_label.configure(text=now.strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_time)
    
    def process_events(self):
        """Process events from the queue"""
        events = self.event_queue.get_all()
        for event in events:
            self.add_event(event)
        
        # Schedule next check
        self.root.after(100, self.process_events)
    
    def add_event(self, event):
        """Add an event to the system"""
        self.events.appendleft(event)
        self.event_counts[event.get('severity', 'INFO')] += 1
        
        # Update category counts
        cat = event.get('category', 'Unknown')
        self.category_counts[cat] = self.category_counts.get(cat, 0) + 1
        
        # Update hourly counts
        hour = datetime.now().hour
        self.hourly_events[hour] += 1
        
        # Add to treeview
        message = event.get('message', '')[:100]
        self.events_tree.insert('', 0, values=(
            event.get('timestamp', ''),
            event.get('severity', 'INFO'),
            event.get('source', '-'),
            event.get('category', '-'),
            event.get('event', '-'),
            event.get('ip', '-'),
            message
        ), tags=(event.get('severity', 'INFO'),))
        
        # Create alert for high severity
        threshold_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        threshold = self.threshold_var.get()
        threshold_idx = threshold_levels.index(threshold) if threshold in threshold_levels else 1
        event_sev = event.get('severity', 'INFO')
        event_idx = threshold_levels.index(event_sev) if event_sev in threshold_levels else 4
        
        if event_idx <= threshold_idx:
            self.add_alert(event)
        
        # Update UI
        self.update_stats()
        self.update_recent_events()
    
    def add_alert(self, event):
        """Add an alert"""
        self.alerts.appendleft(event)
        self.update_alerts_display()
    
    def update_stats(self):
        """Update all statistics"""
        total = sum(self.event_counts.values())
        
        self.stat_cards['total_events'].update_value(str(total))
        self.stat_cards['critical'].update_value(str(self.event_counts['CRITICAL']))
        self.stat_cards['high'].update_value(str(self.event_counts['HIGH']))
        self.stat_cards['medium'].update_value(str(self.event_counts['MEDIUM']))
        
        # Count active sources
        sources = set()
        for event in list(self.events)[:100]:
            sources.add(event.get('source', 'Unknown'))
        self.stat_cards['sources'].update_value(str(len(sources)))
        
        self.dash_stats['critical_dash'].configure(text=str(self.event_counts['CRITICAL']))
        self.dash_stats['high_dash'].configure(text=str(self.event_counts['HIGH']))
        self.dash_stats['medium_dash'].configure(text=str(self.event_counts['MEDIUM']))
        self.dash_stats['low_dash'].configure(text=str(self.event_counts['LOW']))
        self.dash_stats['info_dash'].configure(text=str(self.event_counts['INFO']))
        
        self.mini_chart.update_data(self.hourly_events)
        
        # Update health based on active collectors
        active = sum(1 for v in self.collector_status.values() if v)
        total_collectors = len(self.collector_status)
        health = int((active / total_collectors) * 100) if total_collectors > 0 else 0
        self.health_progress.update_progress(health)
    
    def update_recent_events(self):
        """Update recent events on dashboard"""
        for widget in self.recent_events_frame.winfo_children():
            widget.destroy()
        
        for event in list(self.events)[:10]:
            event_row = tk.Frame(self.recent_events_frame, bg=COLORS['bg_tertiary'])
            event_row.pack(fill='x', pady=2)
            
            color = SEVERITY_COLORS.get(event.get('severity', 'INFO'), COLORS['text_secondary'])
            indicator = tk.Label(event_row, text="●", font=('Segoe UI', 10),
                               fg=color, bg=COLORS['bg_tertiary'])
            indicator.pack(side='left', padx=10, pady=8)
            
            info = tk.Label(event_row, 
                          text=f"{event.get('timestamp', '')} | {event.get('source', '-')} | {event.get('event', '-')}",
                          font=('Segoe UI', 9),
                          fg=COLORS['text_primary'], bg=COLORS['bg_tertiary'])
            info.pack(side='left', pady=8)
            
            badge = tk.Label(event_row, text=event.get('severity', 'INFO'),
                           font=('Segoe UI', 8, 'bold'),
                           fg='white', bg=color)
            badge.pack(side='right', padx=10, pady=8)
    
    def update_alerts_display(self):
        """Update alerts display"""
        for widget in self.alerts_scroll_frame.winfo_children():
            widget.destroy()
        
        if not self.alerts:
            empty_label = tk.Label(self.alerts_scroll_frame, 
                                  text="No alerts to display",
                                  font=('Segoe UI', 12),
                                  fg=COLORS['text_secondary'],
                                  bg=COLORS['bg_dark'])
            empty_label.pack(pady=50)
            return
        
        for alert in list(self.alerts)[:30]:
            alert_card = tk.Frame(self.alerts_scroll_frame, bg=COLORS['bg_secondary'])
            alert_card.pack(fill='x', padx=10, pady=5)
            
            color = SEVERITY_COLORS.get(alert.get('severity', 'INFO'), COLORS['accent_blue'])
            border = tk.Frame(alert_card, bg=color, width=4)
            border.pack(side='left', fill='y')
            
            content = tk.Frame(alert_card, bg=COLORS['bg_secondary'])
            content.pack(side='left', fill='both', expand=True, padx=15, pady=10)
            
            header = tk.Frame(content, bg=COLORS['bg_secondary'])
            header.pack(fill='x')
            
            severity_label = tk.Label(header, text=f"🚨 {alert.get('severity', 'INFO')}", 
                                     font=('Segoe UI', 10, 'bold'),
                                     fg=color, bg=COLORS['bg_secondary'])
            severity_label.pack(side='left')
            
            time_label = tk.Label(header, text=alert.get('timestamp', ''),
                                 font=('Segoe UI', 9),
                                 fg=COLORS['text_secondary'],
                                 bg=COLORS['bg_secondary'])
            time_label.pack(side='right')
            
            details = tk.Label(content, 
                             text=f"{alert.get('category', '-')} - {alert.get('event', '-')}",
                             font=('Segoe UI', 11),
                             fg=COLORS['text_primary'],
                             bg=COLORS['bg_secondary'])
            details.pack(anchor='w', pady=(5, 0))
            
            source_info = tk.Label(content,
                                  text=f"Source: {alert.get('source', '-')} | IP: {alert.get('ip', '-')}",
                                  font=('Segoe UI', 9),
                                  fg=COLORS['text_secondary'],
                                  bg=COLORS['bg_secondary'])
            source_info.pack(anchor='w', pady=(2, 0))
    
    def update_analytics_charts(self):
        """Update analytics charts"""
        # Category chart
        self.category_chart.delete('all')
        
        if self.category_counts:
            max_val = max(self.category_counts.values()) or 1
            bar_height = 25
            y = 30
            
            colors = [COLORS['accent_blue'], COLORS['accent_purple'], 
                     COLORS['accent_green'], COLORS['accent_yellow'],
                     COLORS['accent_orange'], COLORS['accent_red']]
            
            for i, (cat, count) in enumerate(sorted(self.category_counts.items(), 
                                                    key=lambda x: x[1], reverse=True)[:8]):
                self.category_chart.create_text(10, y + bar_height//2, 
                                               text=cat[:12], anchor='w',
                                               font=('Segoe UI', 9),
                                               fill=COLORS['text_primary'])
                
                bar_width = (count / max_val) * 220
                self.category_chart.create_rectangle(100, y, 100 + bar_width, y + bar_height - 5,
                                                    fill=colors[i % len(colors)], outline='')
                
                self.category_chart.create_text(110 + bar_width, y + bar_height//2,
                                               text=str(count), anchor='w',
                                               font=('Segoe UI', 9),
                                               fill=COLORS['text_secondary'])
                y += bar_height + 5
        
        # Severity chart
        self.severity_chart.delete('all')
        
        total = sum(self.event_counts.values()) or 1
        y = 30
        bar_height = 35
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = self.event_counts[severity]
            percentage = (count / total) * 100
            color = SEVERITY_COLORS[severity]
            
            self.severity_chart.create_text(10, y + bar_height//2,
                                           text=severity, anchor='w',
                                           font=('Segoe UI', 10, 'bold'),
                                           fill=color)
            
            self.severity_chart.create_rectangle(100, y + 5, 320, y + bar_height - 5,
                                                fill=COLORS['bg_tertiary'], outline='')
            
            bar_width = (count / total) * 220 if total > 0 else 0
            self.severity_chart.create_rectangle(100, y + 5, 100 + bar_width, y + bar_height - 5,
                                                fill=color, outline='')
            
            self.severity_chart.create_text(330, y + bar_height//2,
                                           text=f"{count} ({percentage:.1f}%)",
                                           anchor='w',
                                           font=('Segoe UI', 9),
                                           fill=COLORS['text_secondary'])
            y += bar_height + 5
    
    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if self.is_monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start all collectors"""
        self.is_monitoring = True
        self.monitor_btn.text = "⏸ Stop Monitor"
        self.monitor_btn.bg_color = COLORS['danger']
        self.monitor_btn._draw_button(COLORS['danger'])
        
        self.status_banner.configure(
            text="✅ Monitoring active - Collecting real security events",
            fg=COLORS['accent_green']
        )
        
        # Start Windows Event Log collector
        if self.win_enabled.get() and HAS_WIN32:
            if self.windows_collector.start():
                self.collector_status['windows'] = True
                self.status_labels['windows'].configure(fg=COLORS['accent_green'])
        
        # Start Log File collector
        if self.log_enabled.get():
            paths = self.log_paths_var.get()
            if paths:
                for path in paths.split(';'):
                    path = path.strip()
                    if path:
                        self.log_collector.add_path(path)
            if self.log_collector.start():
                self.collector_status['logfiles'] = True
                self.status_labels['logfiles'].configure(fg=COLORS['accent_green'])
        
        # Start Syslog server
        if self.syslog_enabled.get():
            try:
                port = int(self.syslog_port_var.get())
                self.syslog_server.udp_port = port
                self.syslog_server.tcp_port = port
            except:
                pass
            if self.syslog_server.start():
                self.collector_status['syslog'] = True
                self.status_labels['syslog'].configure(fg=COLORS['accent_green'])
        
        # Start Network monitor
        if self.net_enabled.get():
            if self.network_monitor.start():
                self.collector_status['network'] = True
                self.status_labels['network'].configure(fg=COLORS['accent_green'])
        
        self.update_stats()
    
    def stop_monitoring(self):
        """Stop all collectors"""
        self.is_monitoring = False
        self.monitor_btn.text = "▶ Start Monitor"
        self.monitor_btn.bg_color = COLORS['success']
        self.monitor_btn._draw_button(COLORS['success'])
        
        self.status_banner.configure(
            text="⚠️ Monitoring stopped",
            fg=COLORS['accent_yellow']
        )
        
        # Stop all collectors
        self.windows_collector.stop()
        self.log_collector.stop()
        self.syslog_server.stop()
        self.network_monitor.stop()
        
        # Update status
        for key in self.collector_status:
            self.collector_status[key] = False
            self.status_labels[key].configure(fg=COLORS['text_secondary'])
        
        self.update_stats()
    
    def browse_log_path(self):
        """Browse for log file or directory"""
        path = filedialog.askdirectory(title="Select Log Directory")
        if path:
            current = self.log_paths_var.get()
            if current:
                self.log_paths_var.set(f"{current};{path}")
            else:
                self.log_paths_var.set(path)
    
    def filter_events(self, severity=None):
        """Filter events by severity"""
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        for event in self.events:
            if severity is None or event.get('severity') == severity:
                message = event.get('message', '')[:100]
                self.events_tree.insert('', 'end', values=(
                    event.get('timestamp', ''),
                    event.get('severity', 'INFO'),
                    event.get('source', '-'),
                    event.get('category', '-'),
                    event.get('event', '-'),
                    event.get('ip', '-'),
                    message
                ), tags=(event.get('severity', 'INFO'),))
    
    def filter_events_by_search(self):
        """Filter events by search text"""
        search_text = self.search_var.get().lower()
        
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        for event in self.events:
            # Search in all fields
            event_str = f"{event.get('source', '')} {event.get('category', '')} {event.get('event', '')} {event.get('ip', '')} {event.get('message', '')}".lower()
            
            if not search_text or search_text in event_str:
                message = event.get('message', '')[:100]
                self.events_tree.insert('', 'end', values=(
                    event.get('timestamp', ''),
                    event.get('severity', 'INFO'),
                    event.get('source', '-'),
                    event.get('category', '-'),
                    event.get('event', '-'),
                    event.get('ip', '-'),
                    message
                ), tags=(event.get('severity', 'INFO'),))
    
    def show_event_details(self, event):
        """Show full event details in a popup"""
        selection = self.events_tree.selection()
        if not selection:
            return
        
        item = self.events_tree.item(selection[0])
        values = item['values']
        
        # Find the full event
        for evt in self.events:
            if evt.get('timestamp') == values[0]:
                # Create popup
                popup = tk.Toplevel(self.root)
                popup.title("Event Details")
                popup.geometry("600x400")
                popup.configure(bg=COLORS['bg_dark'])
                
                text = tk.Text(popup, font=('Consolas', 10),
                              bg=COLORS['bg_secondary'], fg=COLORS['text_primary'],
                              wrap='word', padx=20, pady=20)
                text.pack(fill='both', expand=True, padx=20, pady=20)
                
                details = json.dumps(evt, indent=2, default=str)
                text.insert('1.0', details)
                text.configure(state='disabled')
                break
    
    def export_events(self):
        """Export events to JSON file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            if filename.endswith('.csv'):
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=['timestamp', 'severity', 'source', 'category', 'event', 'ip', 'message'])
                    writer.writeheader()
                    for event in self.events:
                        writer.writerow({
                            'timestamp': event.get('timestamp', ''),
                            'severity': event.get('severity', ''),
                            'source': event.get('source', ''),
                            'category': event.get('category', ''),
                            'event': event.get('event', ''),
                            'ip': event.get('ip', ''),
                            'message': event.get('message', '')
                        })
            else:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(list(self.events), f, indent=2, default=str)
            messagebox.showinfo("Export Complete", f"Events exported to {filename}")
    
    def clear_events(self):
        """Clear all events"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all events?"):
            self.events.clear()
            self.alerts.clear()
            self.event_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            self.category_counts = {}
            self.hourly_events = [0] * 24
            
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
            
            self.update_stats()
            self.update_recent_events()
            self.update_alerts_display()
            self.update_analytics_charts()
    
    def acknowledge_alerts(self):
        """Acknowledge all alerts"""
        self.alerts.clear()
        self.update_alerts_display()
        messagebox.showinfo("Alerts Acknowledged", "All alerts have been acknowledged.")
    
    def save_settings(self):
        """Save settings"""
        settings = {
            'threshold': self.threshold_var.get(),
            'max_events': self.max_events_var.get(),
            'win_enabled': self.win_enabled.get(),
            'log_enabled': self.log_enabled.get(),
            'log_paths': self.log_paths_var.get(),
            'syslog_enabled': self.syslog_enabled.get(),
            'syslog_port': self.syslog_port_var.get(),
            'net_enabled': self.net_enabled.get()
        }
        
        with open('siem_settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
        
        messagebox.showinfo("Settings Saved", "Your settings have been saved successfully.")
    
    def load_settings(self):
        """Load saved settings"""
        try:
            with open('siem_settings.json', 'r') as f:
                settings = json.load(f)
                self.threshold_var.set(settings.get('threshold', 'HIGH'))
                self.max_events_var.set(settings.get('max_events', '5000'))
                self.win_enabled.set(settings.get('win_enabled', HAS_WIN32))
                self.log_enabled.set(settings.get('log_enabled', True))
                self.log_paths_var.set(settings.get('log_paths', ''))
                self.syslog_enabled.set(settings.get('syslog_enabled', True))
                self.syslog_port_var.set(settings.get('syslog_port', '514'))
                self.net_enabled.set(settings.get('net_enabled', True))
        except:
            pass


def main():
    root = tk.Tk()
    
    root.update_idletasks()
    width = 1400
    height = 850
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    app = SIEMApplication(root)
    
    # Handle window close
    def on_closing():
        if app.is_monitoring:
            app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
