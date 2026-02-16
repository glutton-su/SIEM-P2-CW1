"""
Syslog Server
Simple Syslog server supporting UDP and TCP connections on multiple ports.
"""

import threading
import socket
import re
from datetime import datetime

from ..config import SECURITY_PATTERNS


class SyslogServer:
    """Simple Syslog server (UDP and TCP) supporting multiple ports"""
    
    def __init__(self, event_queue, udp_ports=None, tcp_ports=None):
        self.event_queue = event_queue
        # Support both single port (legacy) and multiple ports
        if udp_ports is None:
            udp_ports = [514]
        elif isinstance(udp_ports, int):
            udp_ports = [udp_ports]
        if tcp_ports is None:
            tcp_ports = [514]
        elif isinstance(tcp_ports, int):
            tcp_ports = [tcp_ports]
        
        self.udp_ports = list(udp_ports)
        self.tcp_ports = list(tcp_ports)
        self.running = False
        self.udp_sockets = {}  # port -> socket
        self.tcp_sockets = {}  # port -> socket
        self.threads = []
        
        # Legacy compatibility properties
        self._udp_port = self.udp_ports[0] if self.udp_ports else 514
        self._tcp_port = self.tcp_ports[0] if self.tcp_ports else 514
    
    @property
    def udp_port(self):
        return self._udp_port
    
    @udp_port.setter
    def udp_port(self, value):
        self._udp_port = value
        if value not in self.udp_ports:
            self.udp_ports = [value] + self.udp_ports
    
    @property
    def tcp_port(self):
        return self._tcp_port
    
    @tcp_port.setter
    def tcp_port(self, value):
        self._tcp_port = value
        if value not in self.tcp_ports:
            self.tcp_ports = [value] + self.tcp_ports
    
    def add_port(self, port, protocol='both'):
        """Add a port to listen on (can be called before start)"""
        if protocol in ('udp', 'both') and port not in self.udp_ports:
            self.udp_ports.append(port)
        if protocol in ('tcp', 'both') and port not in self.tcp_ports:
            self.tcp_ports.append(port)
    
    def remove_port(self, port, protocol='both'):
        """Remove a port from listening"""
        if protocol in ('udp', 'both') and port in self.udp_ports:
            self.udp_ports.remove(port)
            if port in self.udp_sockets:
                self.udp_sockets[port].close()
                del self.udp_sockets[port]
        if protocol in ('tcp', 'both') and port in self.tcp_ports:
            self.tcp_ports.remove(port)
            if port in self.tcp_sockets:
                self.tcp_sockets[port].close()
                del self.tcp_sockets[port]
    
    def start(self):
        """Start the syslog server on all configured ports"""
        self.running = True
        
        # Start UDP listeners for all ports
        for port in self.udp_ports:
            self._start_udp_server(port)
        
        # Start TCP listeners for all ports
        for port in self.tcp_ports:
            self._start_tcp_server(port)
        
        return True
    
    def _start_udp_server(self, port):
        """Start UDP syslog listener on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.settimeout(1)
            self.udp_sockets[port] = sock
            thread = threading.Thread(target=self._udp_listener, args=(sock, port), daemon=True)
            thread.start()
            self.threads.append(thread)
            print(f"Syslog UDP server started on port {port}")
        except Exception as e:
            print(f"Could not start UDP syslog on port {port}: {e}")
            # Try alternative port only for the primary port
            if port == 514 and 1514 not in self.udp_ports:
                self._start_udp_server(1514)
    
    def _start_tcp_server(self, port):
        """Start TCP syslog listener on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            sock.settimeout(1)
            self.tcp_sockets[port] = sock
            thread = threading.Thread(target=self._tcp_listener, args=(sock, port), daemon=True)
            thread.start()
            self.threads.append(thread)
            print(f"Syslog TCP server started on port {port}")
        except Exception as e:
            print(f"Could not start TCP syslog on port {port}: {e}")
            # Try alternative port only for the primary port
            if port == 514 and 1514 not in self.tcp_ports:
                self._start_tcp_server(1514)
    
    def stop(self):
        """Stop the syslog server"""
        self.running = False
        for sock in self.udp_sockets.values():
            try:
                sock.close()
            except:
                pass
        for sock in self.tcp_sockets.values():
            try:
                sock.close()
            except:
                pass
        self.udp_sockets.clear()
        self.tcp_sockets.clear()
    
    def _udp_listener(self, sock, port):
        """UDP syslog listener for a specific socket"""
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                message = data.decode('utf-8', errors='ignore')
                event = self._parse_syslog(message, addr[0], port)
                if event:
                    self.event_queue.put(event)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass
    
    def _tcp_listener(self, sock, port):
        """TCP syslog listener for a specific socket"""
        while self.running:
            try:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_tcp_client, 
                               args=(conn, addr, port), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass
    
    def _handle_tcp_client(self, conn, addr, port):
        """Handle TCP client connection"""
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if data:
                message = data.decode('utf-8', errors='ignore')
                for line in message.split('\n'):
                    if line.strip():
                        event = self._parse_syslog(line, addr[0], port)
                        if event:
                            self.event_queue.put(event)
        except Exception as e:
            pass
        finally:
            conn.close()
    
    def _parse_syslog(self, message, source_ip, port=None):
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
        
        port_info = f":{port}" if port else ""
        return {
            'timestamp': timestamp,
            'severity': severity,
            'source': f"Syslog-{source_ip}{port_info}",
            'category': category,
            'event': event_name,
            'ip': source_ip,
            'message': message[:300],
            'id': hash(f"{timestamp}{message[:50]}{source_ip}")
        }
