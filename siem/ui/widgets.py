"""
Custom UI widgets for the SIEM application.
Modern styled widgets using Tkinter Canvas.
"""

import tkinter as tk
from ..config import COLORS


class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    
    def __init__(self, parent, text, command=None, width=120, height=36, 
                 bg_color=None, hover_color=None, **kwargs):
        super().__init__(parent, width=width, height=height, 
                        bg=parent.cget('bg'), highlightthickness=0, **kwargs)
        
        self.bg_color = bg_color or COLORS['accent_blue']
        self.hover_color = hover_color or self._lighten_color(self.bg_color)
        self.command = command
        self.text = text
        self.width = width
        self.height = height
        
        self._draw_button(self.bg_color)
        
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
    
    def _lighten_color(self, color):
        """Create a lighter version of a color"""
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        factor = 1.2
        r = min(255, int(r * factor))
        g = min(255, int(g * factor))
        b = min(255, int(b * factor))
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def _draw_button(self, color):
        """Draw the button with rounded corners"""
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
        """Update button text"""
        self.text = text
        self._draw_button(self.bg_color)


class StatCard(tk.Frame):
    """Modern stat card widget"""
    
    def __init__(self, parent, title, value, icon="●", color=None, **kwargs):
        super().__init__(parent, bg=COLORS['bg_secondary'], **kwargs)
        
        color = color or COLORS['accent_blue']
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
        """Update the displayed value"""
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
        """Draw the bar chart"""
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
        """Interpolate between two colors"""
        r1, g1, b1 = int(color1[1:3], 16), int(color1[3:5], 16), int(color1[5:7], 16)
        r2, g2, b2 = int(color2[1:3], 16), int(color2[3:5], 16), int(color2[5:7], 16)
        r = int(r1 + (r2 - r1) * factor)
        g = int(g1 + (g2 - g1) * factor)
        b = int(b1 + (b2 - b1) * factor)
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def update_data(self, data):
        """Update chart data and redraw"""
        self.data = data
        self.draw_chart()


class CircularProgress(tk.Canvas):
    """Circular progress indicator"""
    
    def __init__(self, parent, size=100, progress=0, color=None, **kwargs):
        super().__init__(parent, width=size, height=size, 
                        bg=COLORS['bg_secondary'], highlightthickness=0, **kwargs)
        self.size = size
        self.color = color or COLORS['accent_green']
        self.progress = progress
        self.draw_progress()
    
    def draw_progress(self):
        """Draw the circular progress"""
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
        """Update progress value and redraw"""
        self.progress = min(100, max(0, progress))
        self.draw_progress()
