"""
Network Monitor
Monitors network connections using netstat.
"""

import threading
import time
import subprocess
from datetime import datetime


class NetworkMonitor:
    """Monitor network connections"""
    
    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.running = False
        self.thread = None
        self.known_connections = set()
    
    def start(self):
        """Start monitoring network connections"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        return True
    
    def stop(self):
        """Stop the monitor"""
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
