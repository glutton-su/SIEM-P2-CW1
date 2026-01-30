"""
Unit tests for EventQueue class.
Tests thread safety, basic operations, and edge cases.
"""

import unittest
import threading
import time
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.utils.event_queue import EventQueue


class TestEventQueueBasicOperations(unittest.TestCase):
    """Test basic EventQueue operations"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_queue_initialization(self):
        """Test that queue initializes empty"""
        self.assertTrue(self.queue.is_empty())
        self.assertEqual(self.queue.size(), 0)
    
    def test_put_single_event(self):
        """Test adding a single event to queue"""
        event = {'timestamp': '2026-01-30 10:00:00', 'severity': 'HIGH'}
        self.queue.put(event)
        
        self.assertFalse(self.queue.is_empty())
        self.assertEqual(self.queue.size(), 1)
    
    def test_get_single_event(self):
        """Test retrieving a single event from queue"""
        event = {'timestamp': '2026-01-30 10:00:00', 'severity': 'INFO'}
        self.queue.put(event)
        
        retrieved = self.queue.get()
        
        self.assertEqual(retrieved, event)
        self.assertTrue(self.queue.is_empty())
    
    def test_get_from_empty_queue(self):
        """Test get returns None for empty queue"""
        result = self.queue.get()
        self.assertIsNone(result)
    
    def test_get_all_events(self):
        """Test retrieving all events at once"""
        events = [
            {'id': 1, 'severity': 'LOW'},
            {'id': 2, 'severity': 'MEDIUM'},
            {'id': 3, 'severity': 'HIGH'},
        ]
        
        for event in events:
            self.queue.put(event)
        
        retrieved = self.queue.get_all()
        
        self.assertEqual(len(retrieved), 3)
        self.assertEqual(retrieved, events)
        self.assertTrue(self.queue.is_empty())
    
    def test_get_all_from_empty_queue(self):
        """Test get_all returns empty list for empty queue"""
        result = self.queue.get_all()
        self.assertEqual(result, [])
    
    def test_fifo_order(self):
        """Test that events are retrieved in FIFO order"""
        for i in range(5):
            self.queue.put({'id': i})
        
        for i in range(5):
            event = self.queue.get()
            self.assertEqual(event['id'], i)
    
    def test_multiple_put_and_get(self):
        """Test multiple put and get operations"""
        self.queue.put({'id': 1})
        self.queue.put({'id': 2})
        
        self.assertEqual(self.queue.get()['id'], 1)
        
        self.queue.put({'id': 3})
        
        self.assertEqual(self.queue.get()['id'], 2)
        self.assertEqual(self.queue.get()['id'], 3)
        self.assertTrue(self.queue.is_empty())


class TestEventQueueThreadSafety(unittest.TestCase):
    """Test thread safety of EventQueue"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_concurrent_producers(self):
        """Test multiple threads adding events concurrently"""
        num_threads = 5
        events_per_thread = 100
        
        def producer(thread_id):
            for i in range(events_per_thread):
                self.queue.put({'thread': thread_id, 'id': i})
        
        threads = [threading.Thread(target=producer, args=(i,)) 
                   for i in range(num_threads)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Verify all events were added
        self.assertEqual(self.queue.size(), num_threads * events_per_thread)
    
    def test_producer_consumer(self):
        """Test producer-consumer pattern"""
        num_events = 500
        consumed = []
        producer_done = threading.Event()
        
        def producer():
            for i in range(num_events):
                self.queue.put({'id': i})
                time.sleep(0.001)  # Small delay
            producer_done.set()
        
        def consumer():
            while not producer_done.is_set() or not self.queue.is_empty():
                events = self.queue.get_all()
                consumed.extend(events)
                time.sleep(0.005)
        
        prod_thread = threading.Thread(target=producer)
        cons_thread = threading.Thread(target=consumer)
        
        prod_thread.start()
        cons_thread.start()
        
        prod_thread.join()
        cons_thread.join()
        
        # Verify all events were consumed
        self.assertEqual(len(consumed), num_events)
    
    def test_multiple_producers_single_consumer(self):
        """Test multiple producers with single consumer"""
        num_producers = 3
        events_per_producer = 50
        consumed = []
        all_done = threading.Event()
        active_producers = [num_producers]
        lock = threading.Lock()
        
        def producer(prod_id):
            for i in range(events_per_producer):
                self.queue.put({'producer': prod_id, 'id': i})
            with lock:
                active_producers[0] -= 1
                if active_producers[0] == 0:
                    all_done.set()
        
        def consumer():
            while not all_done.is_set() or not self.queue.is_empty():
                events = self.queue.get_all()
                consumed.extend(events)
                time.sleep(0.01)
        
        threads = [threading.Thread(target=producer, args=(i,)) 
                   for i in range(num_producers)]
        cons_thread = threading.Thread(target=consumer)
        
        cons_thread.start()
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        cons_thread.join()
        
        # Verify all events consumed
        self.assertEqual(len(consumed), num_producers * events_per_producer)


class TestEventQueueDataIntegrity(unittest.TestCase):
    """Test data integrity in EventQueue"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.queue = EventQueue()
    
    def test_complex_event_data(self):
        """Test handling of complex event data"""
        event = {
            'timestamp': '2026-01-30 12:00:00',
            'severity': 'CRITICAL',
            'source': 'Windows-System',
            'category': 'Authentication',
            'event': 'Login Failed',
            'ip': '192.168.1.100',
            'message': 'Failed login attempt from unknown user',
            'metadata': {
                'event_id': 4625,
                'computer': 'DESKTOP-ABC123',
                'user': 'admin'
            }
        }
        
        self.queue.put(event)
        retrieved = self.queue.get()
        
        self.assertEqual(retrieved, event)
        self.assertEqual(retrieved['metadata']['event_id'], 4625)
    
    def test_special_characters_in_message(self):
        """Test handling of special characters"""
        event = {
            'message': 'Error: "Connection failed" <timeout> & retry=false'
        }
        
        self.queue.put(event)
        retrieved = self.queue.get()
        
        self.assertEqual(retrieved['message'], event['message'])
    
    def test_unicode_content(self):
        """Test handling of Unicode content"""
        event = {
            'message': 'Пользователь вошел • 用户登录 • ユーザーログイン'
        }
        
        self.queue.put(event)
        retrieved = self.queue.get()
        
        self.assertEqual(retrieved['message'], event['message'])
    
    def test_empty_event(self):
        """Test handling of empty event dictionary"""
        event = {}
        
        self.queue.put(event)
        retrieved = self.queue.get()
        
        self.assertEqual(retrieved, {})
    
    def test_none_values_in_event(self):
        """Test handling of None values"""
        event = {
            'timestamp': None,
            'severity': 'INFO',
            'message': None
        }
        
        self.queue.put(event)
        retrieved = self.queue.get()
        
        self.assertIsNone(retrieved['timestamp'])
        self.assertIsNone(retrieved['message'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
