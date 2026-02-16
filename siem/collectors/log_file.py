"""
Log File Collector
Monitors and collects events from log files and directories.
Includes static log analysis capabilities.
"""

import threading
import time
import os
import re
from datetime import datetime
from collections import Counter, defaultdict

from ..config import SECURITY_PATTERNS


class StaticLogAnalyzer:
    """Performs static analysis on log files to generate security insights"""
    
    def __init__(self):
        self.events = []
        self.file_positions = {}
        self.log_extensions = ['.log', '.txt', '.csv', '.json']
    
    def analyze_path(self, path):
        """Analyze a file or directory and return comprehensive analysis results"""
        self.events = []
        files_processed = []
        
        if os.path.isfile(path):
            self._read_entire_file(path)
            files_processed.append(path)
        elif os.path.isdir(path):
            files_processed = self._read_directory_recursive(path)
        
        return self._generate_analysis_report(files_processed)
    
    def _read_directory_recursive(self, directory):
        """Recursively read all log files in a directory"""
        files_read = []
        try:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    filename_lower = filename.lower()
                    
                    # Check standard log extensions
                    if any(filename_lower.endswith(ext) for ext in self.log_extensions):
                        self._read_entire_file(full_path)
                        files_read.append(full_path)
                    # Rotated logs (e.g., .log.1, .log.0)
                    elif any(ext in filename_lower for ext in self.log_extensions):
                        self._read_entire_file(full_path)
                        files_read.append(full_path)
                    # Files without extension that might be logs
                    elif '_log' in filename_lower or filename_lower.endswith('_db'):
                        self._read_entire_file(full_path)
                        files_read.append(full_path)
        except Exception as e:
            pass
        return files_read
    
    def _read_entire_file(self, filepath):
        """Read all lines from a log file and parse them"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        event = self._parse_log_line(line, filepath)
                        if event:
                            self.events.append(event)
        except Exception as e:
            pass
    
    def _parse_log_line(self, line, filepath):
        """Parse a log line into event format"""
        line_lower = line.lower()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Extract timestamp
        ts_patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        ]
        for pattern in ts_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                break
        
        # Determine category and severity
        category = 'System'
        event_name = 'Log Entry'
        severity = 'INFO'
        
        for pattern, (cat, evt, sev) in SECURITY_PATTERNS.items():
            if re.search(pattern, line_lower):
                category = cat
                event_name = evt
                severity = sev
                break
        
        # Extract IP
        ip = self._extract_ip(line)
        
        return {
            'timestamp': timestamp,
            'severity': severity,
            'source': os.path.basename(filepath),
            'category': category,
            'event': event_name,
            'ip': ip or '-',
            'message': line[:500],
            'id': hash(f"{timestamp}{line[:50]}")
        }
    
    def _extract_ip(self, text):
        """Extract IP address from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
    
    def _generate_analysis_report(self, files_processed):
        """Generate comprehensive analysis report from collected events"""
        report = {
            'summary': self._get_summary_stats(),
            'severity_breakdown': self._get_severity_breakdown(),
            'category_breakdown': self._get_category_breakdown(),
            'ip_analysis': self._get_ip_analysis(),
            'timeline': self._get_timeline_analysis(),
            'top_events': self._get_top_events(),
            'security_alerts': self._get_security_alerts(),
            'files_analyzed': files_processed,
            'events': self.events
        }
        return report
    
    def _get_summary_stats(self):
        """Get high-level summary statistics"""
        total = len(self.events)
        critical = sum(1 for e in self.events if e['severity'] == 'CRITICAL')
        high = sum(1 for e in self.events if e['severity'] == 'HIGH')
        unique_ips = len(set(e['ip'] for e in self.events if e['ip'] != '-'))
        unique_sources = len(set(e['source'] for e in self.events))
        
        return {
            'total_events': total,
            'critical_count': critical,
            'high_count': high,
            'medium_count': sum(1 for e in self.events if e['severity'] == 'MEDIUM'),
            'low_count': sum(1 for e in self.events if e['severity'] == 'LOW'),
            'info_count': sum(1 for e in self.events if e['severity'] == 'INFO'),
            'unique_ips': unique_ips,
            'unique_sources': unique_sources,
            'threat_score': min(100, (critical * 10 + high * 5) if total > 0 else 0)
        }
    
    def _get_severity_breakdown(self):
        """Get event counts by severity"""
        counter = Counter(e['severity'] for e in self.events)
        return dict(counter)
    
    def _get_category_breakdown(self):
        """Get event counts by category"""
        counter = Counter(e['category'] for e in self.events)
        return dict(counter)
    
    def _get_ip_analysis(self):
        """Analyze IP addresses found in logs"""
        ip_events = defaultdict(list)
        for event in self.events:
            if event['ip'] != '-':
                ip_events[event['ip']].append(event)
        
        ip_analysis = []
        for ip, events in ip_events.items():
            severity_counts = Counter(e['severity'] for e in events)
            category_counts = Counter(e['category'] for e in events)
            
            # Calculate risk score
            risk_score = (
                severity_counts.get('CRITICAL', 0) * 10 +
                severity_counts.get('HIGH', 0) * 5 +
                severity_counts.get('MEDIUM', 0) * 2 +
                severity_counts.get('LOW', 0) * 1
            )
            
            ip_analysis.append({
                'ip': ip,
                'event_count': len(events),
                'risk_score': min(100, risk_score),
                'top_category': category_counts.most_common(1)[0][0] if category_counts else 'Unknown',
                'critical_events': severity_counts.get('CRITICAL', 0),
                'high_events': severity_counts.get('HIGH', 0),
                'first_seen': events[0]['timestamp'] if events else None,
                'last_seen': events[-1]['timestamp'] if events else None
            })
        
        # Sort by risk score
        ip_analysis.sort(key=lambda x: x['risk_score'], reverse=True)
        return ip_analysis[:50]  # Top 50 IPs
    
    def _get_timeline_analysis(self):
        """Analyze event distribution over time"""
        hour_counts = defaultdict(int)
        for event in self.events:
            # Try to extract hour from timestamp
            try:
                ts = event['timestamp']
                hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', ts)
                if hour_match:
                    hour = int(hour_match.group(1))
                    hour_counts[hour] += 1
            except:
                pass
        
        return dict(sorted(hour_counts.items()))
    
    def _get_top_events(self):
        """Get most common event types"""
        event_counter = Counter(e['event'] for e in self.events)
        return event_counter.most_common(10)
    
    def _get_security_alerts(self):
        """Extract high-priority security alerts"""
        alerts = []
        
        # Find critical and high severity events
        for event in self.events:
            if event['severity'] in ('CRITICAL', 'HIGH'):
                alerts.append({
                    'timestamp': event['timestamp'],
                    'severity': event['severity'],
                    'category': event['category'],
                    'event': event['event'],
                    'ip': event['ip'],
                    'source': event['source'],
                    'message': event['message'][:200]
                })
        
        # Sort by severity (CRITICAL first) then timestamp
        alerts.sort(key=lambda x: (0 if x['severity'] == 'CRITICAL' else 1, x['timestamp']), reverse=True)
        return alerts[:100]  # Top 100 alerts
    
    def export_report(self, report, filepath, format='json'):
        """Export analysis report to file"""
        import json
        import csv
        
        if format == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                # Convert events to serializable format
                export_data = {
                    'summary': report['summary'],
                    'severity_breakdown': report['severity_breakdown'],
                    'category_breakdown': report['category_breakdown'],
                    'ip_analysis': report['ip_analysis'],
                    'timeline': report['timeline'],
                    'top_events': report['top_events'],
                    'security_alerts': report['security_alerts'],
                    'files_analyzed': report['files_analyzed'],
                    'total_events': len(report['events'])
                }
                json.dump(export_data, f, indent=2, default=str)
        
        elif format == 'csv':
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Severity', 'Source', 'Category', 'Event', 'IP', 'Message'])
                for event in report['events']:
                    writer.writerow([
                        event['timestamp'],
                        event['severity'],
                        event['source'],
                        event['category'],
                        event['event'],
                        event['ip'],
                        event['message'][:200]
                    ])
        
        return filepath


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
        """Recursively read all log files in a directory and subdirectories"""
        log_extensions = ['.log', '.txt', '.csv', '.json']
        try:
            for entry in os.listdir(directory):
                full_path = os.path.join(directory, entry)
                if os.path.isdir(full_path):
                    # Recursively process subdirectories
                    self._read_directory(full_path)
                elif os.path.isfile(full_path):
                    entry_lower = entry.lower()
                    # Check for standard log extensions
                    if any(entry_lower.endswith(ext) for ext in log_extensions):
                        self._read_file(full_path)
                    # Also check for rotated logs with numeric suffixes (e.g., .log.1, .log.0)
                    elif any(ext in entry_lower for ext in log_extensions):
                        self._read_file(full_path)
                    # Check for files without extension that might be logs (e.g., audit_db, ssh_debug_log)
                    elif '_log' in entry_lower or entry_lower.endswith('_db'):
                        self._read_file(full_path)
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
        # Convert line to lowercase for case-insensitive matching
        line_lower = line.lower()

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
        
        matched = False
        for pattern, (cat, evt, sev) in SECURITY_PATTERNS.items():
            if re.search(pattern, line_lower):
                category = cat
                event_name = evt
                severity = sev
                matched = True
                break
        
        if not matched:
            print(f"No match for line: {line}")  # Debug logging for unmatched lines
        
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
