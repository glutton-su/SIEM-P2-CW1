"""
Thread-safe event queue for communication between collectors and UI.
"""

import queue


class EventQueue:
    """Thread-safe event queue for passing events between collectors and UI"""
    
    def __init__(self):
        self.queue = queue.Queue()
    
    def put(self, event):
        """Add an event to the queue"""
        self.queue.put(event)
    
    def get(self):
        """Get a single event from the queue (non-blocking)"""
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_all(self):
        """Get all available events from the queue"""
        events = []
        while True:
            event = self.get()
            if event is None:
                break
            events.append(event)
        return events
    
    def is_empty(self):
        """Check if queue is empty"""
        return self.queue.empty()
    
    def size(self):
        """Get approximate queue size"""
        return self.queue.qsize()
