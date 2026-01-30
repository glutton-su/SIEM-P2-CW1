"""
Log File Collector
Monitors and collects events from log files and directories.
"""

import threading
import time
import os
import re
from datetime import datetime

from ..config import SECURITY_PATTERNS


class LogFileCollector:
    """Monitors and collects events from log files"""
    
    def __init__(self, event_queue, watch_paths=None):
        self.event_queue = event_queue
        self.watch_paths = watch_paths or []
        self.running = False
        self.file_positions = {}
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
        """Start monitoring log files"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        """Stop the collector"""
        self.running = False
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
