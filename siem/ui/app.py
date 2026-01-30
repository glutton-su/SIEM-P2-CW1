"""
Main SIEM Application UI
The main window and tab management for the SIEM system.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
from datetime import datetime
from collections import deque

from ..config import COLORS, SEVERITY_COLORS
from ..utils import EventQueue
from ..collectors import (
    WindowsEventLogCollector, 
    LogFileCollector, 
    SyslogServer, 
    NetworkMonitor,
    HAS_WIN32
)
from .widgets import ModernButton, StatCard, MiniChart, CircularProgress


class SIEMApplication:
    """Main SIEM Application"""
    
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
        self.refresh_analytics()  # Start analytics refresh loop
        
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
        
        # Stat cards
        self.stat_cards = {}
        
        stats_config = [
            ('total_events', 'Total Events', '0', '📋', COLORS['accent_blue']),
            ('critical', 'Critical', '0', '🔴', COLORS['accent_red']),
            ('high', 'High', '0', '🟠', COLORS['accent_orange']),
            ('medium', 'Medium', '0', '🟡', COLORS['accent_yellow']),
            ('sources', 'Active Sources', '0', '📡', COLORS['accent_purple']),
        ]
        
        for key, title, value, icon, color in stats_config:
            card = StatCard(sidebar, title, value, icon, color)
            card.pack(fill='x', padx=15, pady=8)
            self.stat_cards[key] = card
        
        # Mini chart
        chart_label = tk.Label(sidebar, text="📈 Event Trend (24h)",
                              font=('Segoe UI', 11, 'bold'),
                              fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        chart_label.pack(pady=(20, 10), padx=20, anchor='w')
        
        self.trend_chart = MiniChart(sidebar, width=250, height=100)
        self.trend_chart.pack(padx=15)

    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(dashboard, text="  🏠 Dashboard  ")
        
        # Status banner
        self.status_banner = tk.Label(dashboard, 
                                     text="⚠️ Monitoring stopped - Click 'Start Monitor' to begin",
                                     font=('Segoe UI', 12),
                                     fg=COLORS['accent_yellow'],
                                     bg=COLORS['bg_secondary'],
                                     pady=15)
        self.status_banner.pack(fill='x', padx=10, pady=10)
        
        # Quick stats row
        stats_row = tk.Frame(dashboard, bg=COLORS['bg_dark'])
        stats_row.pack(fill='x', padx=10, pady=10)
        
        # Progress indicators
        for i, (title, color) in enumerate([
            ("System Health", COLORS['accent_green']),
            ("Threat Level", COLORS['accent_yellow']),
            ("Coverage", COLORS['accent_blue'])
        ]):
            frame = tk.Frame(stats_row, bg=COLORS['bg_secondary'])
            frame.pack(side='left', fill='both', expand=True, padx=5)
            
            tk.Label(frame, text=title, font=('Segoe UI', 10, 'bold'),
                    fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(pady=(15, 5))
            
            progress = CircularProgress(frame, size=80, progress=85 - i*20, color=color)
            progress.pack(pady=(0, 15))
        
        # Recent events preview
        recent_frame = tk.LabelFrame(dashboard, text=" 📋 Recent Events ",
                                    font=('Segoe UI', 11, 'bold'),
                                    fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        recent_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.recent_events_list = tk.Frame(recent_frame, bg=COLORS['bg_secondary'])
        self.recent_events_list.pack(fill='both', expand=True, padx=10, pady=10)

    def create_events_tab(self):
        """Create the events tab"""
        events_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(events_frame, text="  📋 Events  ")
        
        # Toolbar
        toolbar = tk.Frame(events_frame, bg=COLORS['bg_secondary'])
        toolbar.pack(fill='x', padx=10, pady=10)
        
        # Search
        tk.Label(toolbar, text="🔍", font=('Segoe UI', 12),
                bg=COLORS['bg_secondary']).pack(side='left', padx=(10, 5))
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(toolbar, textvariable=self.search_var,
                               font=('Segoe UI', 10), width=30,
                               bg=COLORS['bg_tertiary'], fg=COLORS['text_primary'],
                               insertbackground=COLORS['text_primary'])
        search_entry.pack(side='left', padx=5, pady=10)
        search_entry.bind('<Return>', lambda e: self.filter_events_by_search())
        
        ModernButton(toolbar, "Search", command=self.filter_events_by_search,
                    width=80, bg_color=COLORS['accent_blue']).pack(side='left', padx=5)
        
        # Severity filters
        tk.Label(toolbar, text="Filter:", font=('Segoe UI', 10),
                fg=COLORS['text_secondary'], bg=COLORS['bg_secondary']).pack(side='left', padx=(20, 5))
        
        for sev in ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            color = SEVERITY_COLORS.get(sev, COLORS['accent_blue'])
            ModernButton(toolbar, sev, 
                        command=lambda s=sev: self.filter_events(None if s == 'ALL' else s),
                        width=80, bg_color=color).pack(side='left', padx=2)
        
        # Export button
        ModernButton(toolbar, "📤 Export", command=self.export_events,
                    width=100, bg_color=COLORS['accent_purple']).pack(side='right', padx=10)
        
        # Events treeview
        tree_frame = tk.Frame(events_frame, bg=COLORS['bg_dark'])
        tree_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        columns = ('Timestamp', 'Severity', 'Source', 'Category', 'Event', 'IP', 'Message')
        self.events_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                       style="Custom.Treeview")
        
        col_widths = [150, 80, 120, 100, 150, 120, 300]
        for col, width in zip(columns, col_widths):
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=width, minwidth=50)
        
        # Severity tag colors
        for sev, color in SEVERITY_COLORS.items():
            self.events_tree.tag_configure(sev, foreground=color)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                 command=self.events_tree.yview,
                                 style="Custom.Vertical.TScrollbar")
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        self.events_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        self.events_tree.bind('<Double-1>', self.show_event_details)

    def create_alerts_tab(self):
        """Create the alerts tab"""
        alerts_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(alerts_frame, text="  🚨 Alerts  ")
        
        # Alerts header
        header = tk.Frame(alerts_frame, bg=COLORS['bg_secondary'])
        header.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header, text="🚨 Active Alerts", font=('Segoe UI', 14, 'bold'),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left', padx=20, pady=15)
        
        self.alerts_count_label = tk.Label(header, text="0 alerts",
                                          font=('Segoe UI', 10),
                                          fg=COLORS['text_secondary'],
                                          bg=COLORS['bg_secondary'])
        self.alerts_count_label.pack(side='left')
        
        ModernButton(header, "✓ Acknowledge All", command=self.acknowledge_alerts,
                    width=150, bg_color=COLORS['success']).pack(side='right', padx=20, pady=10)
        
        # Alerts list
        self.alerts_list = tk.Frame(alerts_frame, bg=COLORS['bg_dark'])
        self.alerts_list.pack(fill='both', expand=True, padx=10, pady=(0, 10))

    def create_sources_tab(self):
        """Create the data sources tab"""
        sources_frame = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(sources_frame, text="  📡 Sources  ")
        
        title = tk.Label(sources_frame, text="📡 Data Sources Configuration",
                        font=('Segoe UI', 18, 'bold'),
                        fg=COLORS['text_primary'], bg=COLORS['bg_dark'])
        title.pack(pady=20, padx=20, anchor='w')
        
        # Sources container
        container = tk.Frame(sources_frame, bg=COLORS['bg_dark'])
        container.pack(fill='both', expand=True, padx=10)
        
        # Initialize source variables
        self.win_enabled = tk.BooleanVar(value=HAS_WIN32)
        self.log_enabled = tk.BooleanVar(value=True)
        self.log_paths_var = tk.StringVar()
        self.syslog_enabled = tk.BooleanVar(value=True)
        self.syslog_port_var = tk.StringVar(value="514")
        self.net_enabled = tk.BooleanVar(value=True)
        
        # Windows Event Log
        win_frame = tk.LabelFrame(container, text=" 🪟 Windows Event Log ",
                                 font=('Segoe UI', 11, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        win_frame.pack(fill='x', padx=10, pady=10)
        
        win_inner = tk.Frame(win_frame, bg=COLORS['bg_secondary'])
        win_inner.pack(fill='x', padx=20, pady=15)
        
        tk.Checkbutton(win_inner, text="Enable Windows Event Log Collection",
                      variable=self.win_enabled, font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(anchor='w')
        
        tk.Label(win_inner, text="Monitors: Security, System, Application logs",
                font=('Segoe UI', 9), fg=COLORS['text_secondary'],
                bg=COLORS['bg_secondary']).pack(anchor='w', pady=(5, 0))
        
        # Log File Monitor
        log_frame = tk.LabelFrame(container, text=" 📁 Log File Monitor ",
                                 font=('Segoe UI', 11, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        log_frame.pack(fill='x', padx=10, pady=10)
        
        log_inner = tk.Frame(log_frame, bg=COLORS['bg_secondary'])
        log_inner.pack(fill='x', padx=20, pady=15)
        
        tk.Checkbutton(log_inner, text="Enable Log File Monitoring",
                      variable=self.log_enabled, font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(anchor='w')
        
        path_frame = tk.Frame(log_inner, bg=COLORS['bg_secondary'])
        path_frame.pack(fill='x', pady=10)
        
        tk.Label(path_frame, text="Paths:", font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        tk.Entry(path_frame, textvariable=self.log_paths_var, width=40,
                font=('Segoe UI', 10), bg=COLORS['bg_tertiary'],
                fg=COLORS['text_primary']).pack(side='left', padx=10)
        
        ModernButton(path_frame, "Browse", command=self.browse_log_path,
                    width=80, bg_color=COLORS['accent_blue']).pack(side='left')
        
        # Syslog Server
        syslog_frame = tk.LabelFrame(container, text=" 📨 Syslog Server ",
                                    font=('Segoe UI', 11, 'bold'),
                                    fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        syslog_frame.pack(fill='x', padx=10, pady=10)
        
        syslog_inner = tk.Frame(syslog_frame, bg=COLORS['bg_secondary'])
        syslog_inner.pack(fill='x', padx=20, pady=15)
        
        tk.Checkbutton(syslog_inner, text="Enable Syslog Server",
                      variable=self.syslog_enabled, font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(anchor='w')
        
        port_frame = tk.Frame(syslog_inner, bg=COLORS['bg_secondary'])
        port_frame.pack(anchor='w', pady=10)
        
        tk.Label(port_frame, text="Port:", font=('Segoe UI', 10),
                fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(side='left')
        
        tk.Entry(port_frame, textvariable=self.syslog_port_var, width=10,
                font=('Segoe UI', 10), bg=COLORS['bg_tertiary'],
                fg=COLORS['text_primary']).pack(side='left', padx=10)
        
        # Network Monitor
        net_frame = tk.LabelFrame(container, text=" 🌐 Network Monitor ",
                                 font=('Segoe UI', 11, 'bold'),
                                 fg=COLORS['text_primary'], bg=COLORS['bg_secondary'])
        net_frame.pack(fill='x', padx=10, pady=10)
        
        net_inner = tk.Frame(net_frame, bg=COLORS['bg_secondary'])
        net_inner.pack(fill='x', padx=20, pady=15)
        
        tk.Checkbutton(net_inner, text="Enable Network Connection Monitoring",
                      variable=self.net_enabled, font=('Segoe UI', 10),
                      fg=COLORS['text_primary'], bg=COLORS['bg_secondary'],
                      selectcolor=COLORS['bg_tertiary'],
                      activebackground=COLORS['bg_secondary']).pack(anchor='w')
        
        tk.Label(net_inner, text="Uses netstat to monitor active connections",
                font=('Segoe UI', 9), fg=COLORS['text_secondary'],
                bg=COLORS['bg_secondary']).pack(anchor='w', pady=(5, 0))

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
    
    def refresh_analytics(self):
        """Periodically refresh analytics charts"""
        self.update_analytics_charts()
        self.root.after(5000, self.refresh_analytics)  # Refresh every 5 seconds
    
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
        
        # Update analytics charts periodically (every 10 events to avoid lag)
        total = sum(self.event_counts.values())
        if total % 10 == 0 or total <= 10:
            self.update_analytics_charts()
    
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
        
        # Update trend chart
        self.trend_chart.update_data(self.hourly_events)
    
    def update_recent_events(self):
        """Update the recent events list on dashboard"""
        for widget in self.recent_events_list.winfo_children():
            widget.destroy()
        
        for event in list(self.events)[:8]:
            event_frame = tk.Frame(self.recent_events_list, bg=COLORS['bg_tertiary'])
            event_frame.pack(fill='x', pady=2)
            
            severity = event.get('severity', 'INFO')
            color = SEVERITY_COLORS.get(severity, COLORS['text_primary'])
            
            tk.Label(event_frame, text="●", fg=color, 
                    bg=COLORS['bg_tertiary'], font=('Segoe UI', 10)).pack(side='left', padx=10)
            
            tk.Label(event_frame, text=event.get('timestamp', '')[-8:],
                    fg=COLORS['text_secondary'], bg=COLORS['bg_tertiary'],
                    font=('Segoe UI', 9)).pack(side='left', padx=5)
            
            tk.Label(event_frame, text=event.get('event', '-')[:30],
                    fg=COLORS['text_primary'], bg=COLORS['bg_tertiary'],
                    font=('Segoe UI', 9)).pack(side='left', padx=5)
            
            source_info = tk.Label(event_frame, text=event.get('source', '-'),
                                  fg=COLORS['text_secondary'], bg=COLORS['bg_tertiary'],
                                  font=('Segoe UI', 9))
            source_info.pack(anchor='w', pady=(2, 0))
    
    def update_alerts_display(self):
        """Update the alerts display"""
        for widget in self.alerts_list.winfo_children():
            widget.destroy()
        
        self.alerts_count_label.configure(text=f"{len(self.alerts)} alerts")
        
        for alert in list(self.alerts)[:20]:
            alert_frame = tk.Frame(self.alerts_list, bg=COLORS['bg_secondary'])
            alert_frame.pack(fill='x', padx=10, pady=5)
            
            severity = alert.get('severity', 'HIGH')
            color = SEVERITY_COLORS.get(severity, COLORS['accent_orange'])
            
            header = tk.Frame(alert_frame, bg=COLORS['bg_secondary'])
            header.pack(fill='x', padx=15, pady=(15, 5))
            
            tk.Label(header, text=f"🚨 {severity}", font=('Segoe UI', 11, 'bold'),
                    fg=color, bg=COLORS['bg_secondary']).pack(side='left')
            
            tk.Label(header, text=alert.get('timestamp', ''),
                    font=('Segoe UI', 9), fg=COLORS['text_secondary'],
                    bg=COLORS['bg_secondary']).pack(side='right')
            
            tk.Label(alert_frame, text=alert.get('event', 'Security Alert'),
                    font=('Segoe UI', 10),
                    fg=COLORS['text_primary'], bg=COLORS['bg_secondary']).pack(anchor='w', padx=15)
            
            tk.Label(alert_frame, text=f"Source: {alert.get('source', '-')} | IP: {alert.get('ip', '-')}",
                    font=('Segoe UI', 9),
                    fg=COLORS['text_secondary'], bg=COLORS['bg_secondary']).pack(anchor='w', padx=15, pady=(0, 15))
    
    def update_analytics_charts(self):
        """Update analytics charts"""
        # Check if charts are initialized
        if not hasattr(self, 'category_chart') or not hasattr(self, 'severity_chart'):
            return
            
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
