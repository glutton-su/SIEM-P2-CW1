"""
SIEM - Security Information and Event Management System
Main entry point for the application.

A real working SIEM with actual data collection from:
- Windows Event Logs (Security, System, Application)
- Log File Monitoring
- Syslog Server (UDP/TCP)
- Network Traffic Monitoring
"""

import tkinter as tk
from siem.ui import SIEMApplication


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Center window on screen
    root.update_idletasks()
    width = 1400
    height = 850
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    app = SIEMApplication(root)
    
    # Handle window close
    def on_closing():
        if app.is_monitoring:
            app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
