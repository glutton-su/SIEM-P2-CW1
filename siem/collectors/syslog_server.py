"""
Syslog Server
Simple Syslog server supporting UDP and TCP connections.
"""

import threading
import socket
import re
from datetime import datetime

from ..config import SECURITY_PATTERNS


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
        """Start the syslog server"""
        self.running = True
        
        # Start UDP listener
        self._start_udp_server()
        
        # Start TCP listener
        self._start_tcp_server()
        
        return True
    
    def _start_udp_server(self):
        """Start UDP syslog listener"""
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
    
    def _start_tcp_server(self):
        """Start TCP syslog listener"""
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
    
    def stop(self):
        """Stop the syslog server"""
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
