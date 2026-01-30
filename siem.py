"""
SIEM - Security Information and Event Management System
A beautiful Python Tkinter application for security monitoring
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import datetime
import threading
import time
import json
import os
from collections import deque

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

# ==================== Severity Levels ====================
SEVERITY_COLORS = {
    'CRITICAL': COLORS['accent_red'],
    'HIGH': COLORS['accent_orange'],
    'MEDIUM': COLORS['accent_yellow'],
    'LOW': COLORS['accent_blue'],
    'INFO': COLORS['accent_green'],
}

# ==================== Sample Data Generators ====================
EVENT_TYPES = [
    ('Authentication', ['Login Success', 'Login Failed', 'Logout', 'Password Change', 'MFA Triggered']),
    ('Network', ['Connection Established', 'Connection Blocked', 'Port Scan Detected', 'DDoS Attempt', 'DNS Query']),
    ('Firewall', ['Rule Triggered', 'Packet Dropped', 'Intrusion Attempt', 'Policy Violation']),
    ('Malware', ['Threat Detected', 'Quarantine Action', 'Scan Complete', 'Signature Update']),
    ('System', ['Service Started', 'Service Stopped', 'Configuration Change', 'Privilege Escalation']),
    ('Data', ['File Access', 'Data Export', 'Encryption Event', 'Backup Complete']),
]

SOURCES = ['Firewall-01', 'IDS-Main', 'WebServer-01', 'DB-Server', 'AD-Controller', 
           'Mail-Server', 'VPN-Gateway', 'Endpoint-Agent', 'Cloud-WAF', 'SIEM-Collector']

IP_RANGES = ['192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.', '198.51.100.']


class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    def __init__(self, parent, text, command=None, width=120, height=36, 
                 bg_color=COLORS['accent_blue'], hover_color=None, **kwargs):
        super().__init__(parent, width=width, height=height, 
                        bg=COLORS['bg_secondary'], highlightthickness=0, **kwargs)
        
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
        # Simple color lightening
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
        # Draw rounded rectangle
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
        # Draw text
        self.create_text(self.width//2, self.height//2, text=self.text, 
                        fill='white', font=('Segoe UI', 10, 'bold'))
    
    def _on_enter(self, e):
        self._draw_button(self.hover_color)
    
    def _on_leave(self, e):
        self._draw_button(self.bg_color)
    
    def _on_click(self, e):
        if self.command:
            self.command()


class StatCard(tk.Frame):
    """Modern stat card widget"""
    def __init__(self, parent, title, value, icon="●", color=COLORS['accent_blue'], **kwargs):
        super().__init__(parent, bg=COLORS['bg_secondary'], **kwargs)
        
        self.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        # Icon
        icon_label = tk.Label(self, text=icon, font=('Segoe UI', 24), 
                             fg=color, bg=COLORS['bg_secondary'])
        icon_label.pack(side='left', padx=15, pady=15)
        
        # Text container
        text_frame = tk.Frame(self, bg=COLORS['bg_secondary'])
        text_frame.pack(side='left', fill='both', expand=True, pady=15, padx=(0, 15))
        
        # Title
        title_label = tk.Label(text_frame, text=title, font=('Segoe UI', 10), 
                              fg=COLORS['text_secondary'], bg=COLORS['bg_secondary'])
        title_label.pack(anchor='w')
        
        # Value
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
            
            # Gradient effect based on value
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
        
        # Background circle
        self.create_oval(padding, padding, self.size-padding, self.size-padding,
                        outline=COLORS['border'], width=8)
        
        # Progress arc
        extent = (self.progress / 100) * 360
        self.create_arc(padding, padding, self.size-padding, self.size-padding,
                       start=90, extent=-extent, outline=self.color, 
                       width=8, style='arc')
        
        # Center text
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
        self.events = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.event_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        self.hourly_events = [0] * 24
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Configure styles
        self.setup_styles()
        
        # Build UI
        self.create_ui()
        
        # Start with some initial data
        self.generate_initial_data()
        
    def setup_styles(self):
        """Configure ttk styles for modern look"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Treeview style
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
        
        # Scrollbar style
        style.configure("Custom.Vertical.TScrollbar",
                       background=COLORS['bg_tertiary'],
                       troughcolor=COLORS['bg_secondary'],
                       borderwidth=0,
                       arrowcolor=COLORS['text_secondary'])
        
        # Notebook style
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
        # Header
        self.create_header()
        
        # Main content area
        main_container = tk.Frame(self.root, bg=COLORS['bg_dark'])
        main_container.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Left sidebar
        self.create_sidebar(main_container)
        
        # Main content
        content_frame = tk.Frame(main_container, bg=COLORS['bg_dark'])
        content_frame.pack(side='left', fill='both', expand=True, padx=(20, 0))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(content_frame, style="Custom.TNotebook")
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_events_tab()
        self.create_alerts_tab()
        self.create_analytics_tab()
        self.create_settings_tab()
    
    def create_header(self):
        """Create the application header"""
        header = tk.Frame(self.root, bg=COLORS['bg_secondary'], height=70)
        header.pack(fill='x', padx=20, pady=20)
        header.pack_propagate(False)
        
        # Logo and title
        title_frame = tk.Frame(header, bg=COLORS['bg_secondary'])
        title_frame.pack(side='left', padx=20)
        
        logo = tk.Label(title_frame, text="🛡️", font=('Segoe UI', 28), 
                       bg=COLORS['bg_secondary'])
        logo.pack(side='left')
        
        title = tk.Label(title_frame, text="SIEM", font=('Segoe UI', 22, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        title.pack(side='left', padx=(10, 5))
        
        subtitle = tk.Label(title_frame, text="Security Information & Event Management",
                           font=('Segoe UI', 10), fg=COLORS['text_secondary'],
                           bg=COLORS['bg_secondary'])
        subtitle.pack(side='left', padx=10)
        
        # Right side - Status and controls
        controls = tk.Frame(header, bg=COLORS['bg_secondary'])
        controls.pack(side='right', padx=20)
        
        # Status indicator
        self.status_indicator = tk.Label(controls, text="● Idle", 
                                        font=('Segoe UI', 10),
                                        fg=COLORS['text_secondary'],
                                        bg=COLORS['bg_secondary'])
        self.status_indicator.pack(side='left', padx=20)
        
        # Time display
        self.time_label = tk.Label(controls, font=('Segoe UI', 10),
                                  fg=COLORS['text_secondary'],
                                  bg=COLORS['bg_secondary'])
        self.time_label.pack(side='left', padx=20)
        self.update_time()
        
        # Monitor button
        self.monitor_btn = ModernButton(controls, "▶ Start Monitor", 
                                       command=self.toggle_monitoring,
                                       width=140, bg_color=COLORS['success'])
        self.monitor_btn.pack(side='left', padx=5)
    
    def create_sidebar(self, parent):
        """Create the left sidebar with stats"""
        sidebar = tk.Frame(parent, bg=COLORS['bg_secondary'], width=280)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        
        # Sidebar header
        sidebar_header = tk.Label(sidebar, text="📊 Quick Stats", 
                                 font=('Segoe UI', 14, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        sidebar_header.pack(pady=20, padx=20, anchor='w')
        
        # Stat cards
        self.stat_cards = {}
        
        stats_data = [
            ('total_events', 'Total Events', '0', '📋', COLORS['accent_blue']),
            ('critical', 'Critical Alerts', '0', '🔴', COLORS['accent_red']),
            ('high', 'High Priority', '0', '🟠', COLORS['accent_orange']),
            ('medium', 'Medium Priority', '0', '🟡', COLORS['accent_yellow']),
            ('sources', 'Active Sources', '10', '🖥️', COLORS['accent_purple']),
        ]
        
        for key, title, value, icon, color in stats_data:
            card = StatCard(sidebar, title, value, icon, color)
            card.pack(fill='x', padx=15, pady=5)
            self.stat_cards[key] = card
        
        # Mini chart section
        chart_label = tk.Label(sidebar, text="📈 Events (Last 24h)",
                              font=('Segoe UI', 12, 'bold'),
                              fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        chart_label.pack(pady=(20, 10), padx=20, anchor='w')
        
        self.mini_chart = MiniChart(sidebar, width=250, height=100)
        self.mini_chart.pack(padx=15, pady=5)
        
        # System health
        health_label = tk.Label(sidebar, text="💚 System Health",
                               font=('Segoe UI', 12, 'bold'),
                               fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        health_label.pack(pady=(20, 10), padx=20, anchor='w')
        
        self.health_progress = CircularProgress(sidebar, size=120, progress=98,
                                                color=COLORS['accent_green'])
        self.health_progress.pack(pady=10)
    
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(dashboard, text="  📊 Dashboard  ")
        
        # Welcome message
        welcome_frame = tk.Frame(dashboard, bg=COLORS['bg_secondary'])
        welcome_frame.pack(fill='x', padx=10, pady=10)
        
        welcome_title = tk.Label(welcome_frame, text="Welcome to SIEM Dashboard",
                                font=('Segoe UI', 18, 'bold'),
                                fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        welcome_title.pack(pady=15, padx=20, anchor='w')
        
        welcome_desc = tk.Label(welcome_frame, 
                               text="Monitor security events, analyze threats, and respond to incidents in real-time.",
                               font=('Segoe UI', 11),
                               fg=COLORS['text_secondary'], bg=COLORS['bg_secondary'])
        welcome_desc.pack(pady=(0, 15), padx=20, anchor='w')
        
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
        
        recent_title = tk.Label(recent_header, text="🔔 Recent Events",
                               font=('Segoe UI', 14, 'bold'),
                               fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        recent_title.pack(side='left')
        
        # Recent events list
        self.recent_events_frame = tk.Frame(recent_frame, bg=COLORS['bg_secondary'])
        self.recent_events_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
    
    def create_events_tab(self):
        """Create the events tab with log viewer"""
        events_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(events_frame, text="  📋 Events  ")
        
        # Toolbar
        toolbar = tk.Frame(events_frame, bg=COLORS['bg_secondary'])
        toolbar.pack(fill='x', padx=10, pady=10)
        
        # Search
        search_frame = tk.Frame(toolbar, bg=COLORS['bg_secondary'])
        search_frame.pack(side='left', padx=15, pady=10)
        
        tk.Label(search_frame, text="🔍", font=('Segoe UI', 12),
                bg=COLORS['bg_secondary']).pack(side='left')
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                               font=('Segoe UI', 10), width=30,
                               bg=COLORS['bg_tertiary'], fg=COLORS['text_primary'],
                               insertbackground=COLORS['text_primary'],
                               relief='flat')
        search_entry.pack(side='left', padx=10, ipady=8)
        search_entry.insert(0, "Search events...")
        search_entry.bind('<FocusIn>', lambda e: search_entry.delete(0, 'end') 
                         if search_entry.get() == "Search events..." else None)
        
        # Filter buttons
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
        
        # Action buttons
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
        
        columns = ('timestamp', 'severity', 'source', 'category', 'event', 'ip')
        self.events_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show='headings', style="Custom.Treeview")
        
        # Column headings
        headings = [('timestamp', 'Timestamp', 150), ('severity', 'Severity', 100),
                   ('source', 'Source', 120), ('category', 'Category', 120),
                   ('event', 'Event', 250), ('ip', 'IP Address', 120)]
        
        for col, text, width in headings:
            self.events_tree.heading(col, text=text)
            self.events_tree.column(col, width=width, minwidth=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                 command=self.events_tree.yview,
                                 style="Custom.Vertical.TScrollbar")
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        self.events_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
        # Tag colors for severity
        self.events_tree.tag_configure('CRITICAL', foreground=COLORS['accent_red'])
        self.events_tree.tag_configure('HIGH', foreground=COLORS['accent_orange'])
        self.events_tree.tag_configure('MEDIUM', foreground=COLORS['accent_yellow'])
        self.events_tree.tag_configure('LOW', foreground=COLORS['accent_blue'])
        self.events_tree.tag_configure('INFO', foreground=COLORS['accent_green'])
    
    def create_alerts_tab(self):
        """Create the alerts tab"""
        alerts_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(alerts_frame, text="  🚨 Alerts  ")
        
        # Header
        header = tk.Frame(alerts_frame, bg=COLORS['bg_secondary'])
        header.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header, text="🚨 Security Alerts",
                font=('Segoe UI', 16, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left', padx=20, pady=15)
        
        # Alert actions
        actions = tk.Frame(header, bg=COLORS['bg_secondary'])
        actions.pack(side='right', padx=20, pady=15)
        
        ack_btn = ModernButton(actions, "✓ Acknowledge All",
                              command=self.acknowledge_alerts,
                              width=140, bg_color=COLORS['success'])
        ack_btn.pack(side='left', padx=5)
        
        # Alerts container
        self.alerts_container = tk.Frame(alerts_frame, bg=COLORS['bg_dark'])
        self.alerts_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Scrollable frame for alerts
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
    
    def create_analytics_tab(self):
        """Create the analytics tab"""
        analytics_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(analytics_frame, text="  📈 Analytics  ")
        
        # Title
        title = tk.Label(analytics_frame, text="📈 Security Analytics",
                        font=('Segoe UI', 18, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_dark'])
        title.pack(pady=20, padx=20, anchor='w')
        
        # Charts container
        charts_frame = tk.Frame(analytics_frame, bg=COLORS['bg_dark'])
        charts_frame.pack(fill='both', expand=True, padx=10)
        
        # Left chart - Events by Category
        left_chart = tk.Frame(charts_frame, bg=COLORS['bg_secondary'])
        left_chart.pack(side='left', fill='both', expand=True, padx=5, pady=10)
        
        tk.Label(left_chart, text="Events by Category",
                font=('Segoe UI', 12, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(pady=15)
        
        self.category_chart = tk.Canvas(left_chart, width=400, height=300,
                                       bg=COLORS['bg_secondary'], highlightthickness=0)
        self.category_chart.pack(pady=10, padx=20)
        
        # Right chart - Events by Severity
        right_chart = tk.Frame(charts_frame, bg=COLORS['bg_secondary'])
        right_chart.pack(side='right', fill='both', expand=True, padx=5, pady=10)
        
        tk.Label(right_chart, text="Events by Severity",
                font=('Segoe UI', 12, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(pady=15)
        
        self.severity_chart = tk.Canvas(right_chart, width=400, height=300,
                                       bg=COLORS['bg_secondary'], highlightthickness=0)
        self.severity_chart.pack(pady=10, padx=20)
        
        # Draw initial charts
        self.update_analytics_charts()
    
    def create_settings_tab(self):
        """Create the settings tab"""
        settings_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(settings_frame, text="  ⚙️ Settings  ")
        
        # Title
        title = tk.Label(settings_frame, text="⚙️ Settings",
                        font=('Segoe UI', 18, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_dark'])
        title.pack(pady=20, padx=20, anchor='w')
        
        # Settings container
        container = tk.Frame(settings_frame, bg=COLORS['bg_secondary'])
        container.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Monitoring Settings
        monitor_section = tk.LabelFrame(container, text=" 🔄 Monitoring Settings ",
                                       font=('Segoe UI', 11, 'bold'),
                                       fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        monitor_section.pack(fill='x', padx=20, pady=20)
        
        # Event generation rate
        rate_frame = tk.Frame(monitor_section, bg=COLORS['bg_secondary'])
        rate_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(rate_frame, text="Event Generation Rate (events/sec):",
                font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        self.rate_var = tk.StringVar(value="2")
        rate_spin = tk.Spinbox(rate_frame, from_=1, to=10, textvariable=self.rate_var,
                              width=5, font=('Segoe UI', 10),
                              bg=COLORS['bg_tertiary'], fg=COLORS['text_primary'])
        rate_spin.pack(side='left', padx=10)
        
        # Alert threshold
        threshold_frame = tk.Frame(monitor_section, bg=COLORS['bg_secondary'])
        threshold_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(threshold_frame, text="Alert on severity level:",
                font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        self.threshold_var = tk.StringVar(value="HIGH")
        threshold_combo = ttk.Combobox(threshold_frame, textvariable=self.threshold_var,
                                       values=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                                       state='readonly', width=15)
        threshold_combo.pack(side='left', padx=10)
        
        # Notification Settings
        notif_section = tk.LabelFrame(container, text=" 🔔 Notification Settings ",
                                     font=('Segoe UI', 11, 'bold'),
                                     fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        notif_section.pack(fill='x', padx=20, pady=20)
        
        # Sound notifications
        sound_frame = tk.Frame(notif_section, bg=COLORS['bg_secondary'])
        sound_frame.pack(fill='x', padx=20, pady=15)
        
        self.sound_var = tk.BooleanVar(value=True)
        sound_check = tk.Checkbutton(sound_frame, text="Enable sound notifications",
                                    variable=self.sound_var,
                                    font=('Segoe UI', 10),
                                    fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                                    selectcolor=COLORS['bg_tertiary'],
                                    activebackground=COLORS['bg_secondary'])
        sound_check.pack(side='left')
        
        # Desktop notifications
        desktop_frame = tk.Frame(notif_section, bg=COLORS['bg_secondary'])
        desktop_frame.pack(fill='x', padx=20, pady=15)
        
        self.desktop_var = tk.BooleanVar(value=True)
        desktop_check = tk.Checkbutton(desktop_frame, text="Enable desktop notifications",
                                      variable=self.desktop_var,
                                      font=('Segoe UI', 10),
                                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                                      selectcolor=COLORS['bg_tertiary'],
                                      activebackground=COLORS['bg_secondary'])
        desktop_check.pack(side='left')
        
        # Save button
        save_btn = ModernButton(container, "💾 Save Settings",
                               command=self.save_settings,
                               width=150, bg_color=COLORS['success'])
        save_btn.pack(pady=20)
    
    def update_time(self):
        """Update the time display"""
        now = datetime.datetime.now()
        self.time_label.configure(text=now.strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_time)
    
    def generate_event(self):
        """Generate a random security event"""
        category, events = random.choice(EVENT_TYPES)
        event_name = random.choice(events)
        severity = random.choices(
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            weights=[5, 10, 25, 35, 25]
        )[0]
        
        event = {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'severity': severity,
            'source': random.choice(SOURCES),
            'category': category,
            'event': event_name,
            'ip': random.choice(IP_RANGES) + str(random.randint(1, 254)),
            'id': len(self.events) + 1
        }
        
        return event
    
    def add_event(self, event):
        """Add an event to the system"""
        self.events.appendleft(event)
        self.event_counts[event['severity']] += 1
        
        # Update hourly counts
        hour = datetime.datetime.now().hour
        self.hourly_events[hour] += 1
        
        # Add to treeview
        self.events_tree.insert('', 0, values=(
            event['timestamp'], event['severity'], event['source'],
            event['category'], event['event'], event['ip']
        ), tags=(event['severity'],))
        
        # Create alert for high severity
        threshold_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        threshold = self.threshold_var.get()
        threshold_idx = threshold_levels.index(threshold)
        event_idx = threshold_levels.index(event['severity']) if event['severity'] in threshold_levels else 4
        
        if event_idx <= threshold_idx:
            self.add_alert(event)
        
        # Update UI
        self.update_stats()
        self.update_recent_events()
    
    def add_alert(self, event):
        """Add an alert for high-severity events"""
        self.alerts.appendleft(event)
        self.update_alerts_display()
    
    def update_stats(self):
        """Update all statistics displays"""
        total = sum(self.event_counts.values())
        
        # Update sidebar stats
        self.stat_cards['total_events'].update_value(str(total))
        self.stat_cards['critical'].update_value(str(self.event_counts['CRITICAL']))
        self.stat_cards['high'].update_value(str(self.event_counts['HIGH']))
        self.stat_cards['medium'].update_value(str(self.event_counts['MEDIUM']))
        
        # Update dashboard stats
        self.dash_stats['critical_dash'].configure(text=str(self.event_counts['CRITICAL']))
        self.dash_stats['high_dash'].configure(text=str(self.event_counts['HIGH']))
        self.dash_stats['medium_dash'].configure(text=str(self.event_counts['MEDIUM']))
        self.dash_stats['low_dash'].configure(text=str(self.event_counts['LOW']))
        self.dash_stats['info_dash'].configure(text=str(self.event_counts['INFO']))
        
        # Update mini chart
        self.mini_chart.update_data(self.hourly_events)
        
        # Update analytics
        self.update_analytics_charts()
    
    def update_recent_events(self):
        """Update recent events display on dashboard"""
        # Clear existing
        for widget in self.recent_events_frame.winfo_children():
            widget.destroy()
        
        # Show last 8 events
        for event in list(self.events)[:8]:
            event_row = tk.Frame(self.recent_events_frame, bg=COLORS['bg_tertiary'])
            event_row.pack(fill='x', pady=2)
            
            # Severity indicator
            color = SEVERITY_COLORS.get(event['severity'], COLORS['text_secondary'])
            indicator = tk.Label(event_row, text="●", font=('Segoe UI', 10),
                               fg=color, bg=COLORS['bg_tertiary'])
            indicator.pack(side='left', padx=10, pady=8)
            
            # Event info
            info = tk.Label(event_row, 
                          text=f"{event['timestamp']} | {event['source']} | {event['event']}",
                          font=('Segoe UI', 9),
                          fg=COLORS['text_primary'], bg=COLORS['bg_tertiary'])
            info.pack(side='left', pady=8)
            
            # Severity badge
            badge = tk.Label(event_row, text=event['severity'],
                           font=('Segoe UI', 8, 'bold'),
                           fg='white', bg=color)
            badge.pack(side='right', padx=10, pady=8)
    
    def update_alerts_display(self):
        """Update the alerts display"""
        # Clear existing
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
        
        for alert in list(self.alerts)[:20]:
            alert_card = tk.Frame(self.alerts_scroll_frame, bg=COLORS['bg_secondary'])
            alert_card.pack(fill='x', padx=10, pady=5)
            
            # Left border color
            color = SEVERITY_COLORS.get(alert['severity'], COLORS['accent_blue'])
            border = tk.Frame(alert_card, bg=color, width=4)
            border.pack(side='left', fill='y')
            
            # Content
            content = tk.Frame(alert_card, bg=COLORS['bg_secondary'])
            content.pack(side='left', fill='both', expand=True, padx=15, pady=10)
            
            # Header
            header = tk.Frame(content, bg=COLORS['bg_secondary'])
            header.pack(fill='x')
            
            severity_label = tk.Label(header, text=f"🚨 {alert['severity']}", 
                                     font=('Segoe UI', 10, 'bold'),
                                     fg=color, bg=COLORS['bg_secondary'])
            severity_label.pack(side='left')
            
            time_label = tk.Label(header, text=alert['timestamp'],
                                 font=('Segoe UI', 9),
                                 fg=COLORS['text_secondary'],
                                 bg=COLORS['bg_secondary'])
            time_label.pack(side='right')
            
            # Details
            details = tk.Label(content, 
                             text=f"{alert['category']} - {alert['event']}",
                             font=('Segoe UI', 11),
                             fg=COLORS['text_primary'],
                             bg=COLORS['bg_secondary'])
            details.pack(anchor='w', pady=(5, 0))
            
            source_info = tk.Label(content,
                                  text=f"Source: {alert['source']} | IP: {alert['ip']}",
                                  font=('Segoe UI', 9),
                                  fg=COLORS['text_secondary'],
                                  bg=COLORS['bg_secondary'])
            source_info.pack(anchor='w', pady=(2, 0))
    
    def update_analytics_charts(self):
        """Update analytics charts"""
        # Category chart (bar chart)
        self.category_chart.delete('all')
        
        # Count events by category
        category_counts = {}
        for event in self.events:
            cat = event['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        if category_counts:
            max_val = max(category_counts.values()) or 1
            bar_height = 25
            y = 30
            
            colors = [COLORS['accent_blue'], COLORS['accent_purple'], 
                     COLORS['accent_green'], COLORS['accent_yellow'],
                     COLORS['accent_orange'], COLORS['accent_red']]
            
            for i, (cat, count) in enumerate(sorted(category_counts.items(), 
                                                    key=lambda x: x[1], reverse=True)[:6]):
                # Label
                self.category_chart.create_text(10, y + bar_height//2, 
                                               text=cat[:15], anchor='w',
                                               font=('Segoe UI', 9),
                                               fill=COLORS['text_primary'])
                
                # Bar
                bar_width = (count / max_val) * 250
                self.category_chart.create_rectangle(100, y, 100 + bar_width, y + bar_height - 5,
                                                    fill=colors[i % len(colors)], outline='')
                
                # Value
                self.category_chart.create_text(110 + bar_width, y + bar_height//2,
                                               text=str(count), anchor='w',
                                               font=('Segoe UI', 9),
                                               fill=COLORS['text_secondary'])
                y += bar_height + 10
        
        # Severity chart (pie chart simulation with rectangles)
        self.severity_chart.delete('all')
        
        total = sum(self.event_counts.values()) or 1
        
        y = 30
        bar_height = 35
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = self.event_counts[severity]
            percentage = (count / total) * 100
            color = SEVERITY_COLORS[severity]
            
            # Label
            self.severity_chart.create_text(10, y + bar_height//2,
                                           text=severity, anchor='w',
                                           font=('Segoe UI', 10, 'bold'),
                                           fill=color)
            
            # Progress bar background
            self.severity_chart.create_rectangle(100, y + 5, 350, y + bar_height - 5,
                                                fill=COLORS['bg_tertiary'], outline='')
            
            # Progress bar
            bar_width = (count / total) * 250 if total > 0 else 0
            self.severity_chart.create_rectangle(100, y + 5, 100 + bar_width, y + bar_height - 5,
                                                fill=color, outline='')
            
            # Value
            self.severity_chart.create_text(360, y + bar_height//2,
                                           text=f"{count} ({percentage:.1f}%)",
                                           anchor='w',
                                           font=('Segoe UI', 9),
                                           fill=COLORS['text_secondary'])
            y += bar_height + 5
    
    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if self.is_monitoring:
            self.is_monitoring = False
            self.monitor_btn._draw_button(COLORS['success'])
            self.monitor_btn.text = "▶ Start Monitor"
            self.monitor_btn.bg_color = COLORS['success']
            self.monitor_btn._draw_button(COLORS['success'])
            self.status_indicator.configure(text="● Idle", fg=COLORS['text_secondary'])
        else:
            self.is_monitoring = True
            self.monitor_btn.text = "⏸ Stop Monitor"
            self.monitor_btn.bg_color = COLORS['danger']
            self.monitor_btn._draw_button(COLORS['danger'])
            self.status_indicator.configure(text="● Monitoring", fg=COLORS['accent_green'])
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitor_thread.start()
    
    def monitoring_loop(self):
        """Background monitoring loop"""
        while self.is_monitoring:
            try:
                rate = int(self.rate_var.get())
            except:
                rate = 2
            
            event = self.generate_event()
            self.root.after(0, lambda e=event: self.add_event(e))
            time.sleep(1 / rate)
    
    def filter_events(self, severity=None):
        """Filter events by severity"""
        # Clear treeview
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        # Re-add filtered events
        for event in self.events:
            if severity is None or event['severity'] == severity:
                self.events_tree.insert('', 'end', values=(
                    event['timestamp'], event['severity'], event['source'],
                    event['category'], event['event'], event['ip']
                ), tags=(event['severity'],))
    
    def export_events(self):
        """Export events to JSON file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                json.dump(list(self.events), f, indent=2)
            messagebox.showinfo("Export Complete", f"Events exported to {filename}")
    
    def clear_events(self):
        """Clear all events"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all events?"):
            self.events.clear()
            self.alerts.clear()
            self.event_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            self.hourly_events = [0] * 24
            
            # Clear treeview
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
            
            self.update_stats()
            self.update_recent_events()
            self.update_alerts_display()
    
    def acknowledge_alerts(self):
        """Acknowledge all alerts"""
        self.alerts.clear()
        self.update_alerts_display()
        messagebox.showinfo("Alerts Acknowledged", "All alerts have been acknowledged.")
    
    def save_settings(self):
        """Save settings"""
        settings = {
            'rate': self.rate_var.get(),
            'threshold': self.threshold_var.get(),
            'sound': self.sound_var.get(),
            'desktop': self.desktop_var.get()
        }
        
        with open('siem_settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
        
        messagebox.showinfo("Settings Saved", "Your settings have been saved successfully.")
    
    def generate_initial_data(self):
        """Generate some initial events for demonstration"""
        for _ in range(50):
            event = self.generate_event()
            # Randomize timestamp for initial data
            minutes_ago = random.randint(0, 120)
            event['timestamp'] = (datetime.datetime.now() - 
                                 datetime.timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")
            self.add_event(event)


def main():
    root = tk.Tk()
    
    # Set window icon (if available)
    try:
        root.iconbitmap('shield.ico')
    except:
        pass
    
    # Center window on screen
    root.update_idletasks()
    width = 1400
    height = 850
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    app = SIEMApplication(root)
    root.mainloop()


if __name__ == "__main__":
    main()
