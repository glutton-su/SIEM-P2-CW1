# SIEM - Security Information and Event Management

A Python-based Security Information and Event Management (SIEM) system with a modern graphical interface for real-time security monitoring and event analysis.

## Features

- **Windows Event Log Collection** - Monitor Security, System, and Application event logs
- **Syslog Server** - Receive logs via UDP/TCP (default port 514)
- **Network Traffic Monitoring** - Track network connections and detect suspicious patterns
- **Log File Monitoring** - Watch and parse custom log files
- **Real-time Dashboard** - Modern Tkinter-based UI with event visualization
- **Severity Classification** - Events categorized as Critical, High, Medium, Low, or Info
- **Alert Management** - Configurable thresholds and alert notifications

## Requirements

- Python 3.8+
- Windows OS (for Windows Event Log collection)
- pywin32 >= 306

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/glutton-su/SIEM-P2-CW1.git
   cd SIEM-P2-CW1
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the application:
```bash
python main.py
```

The SIEM dashboard will open with controls to:
- Start/stop monitoring
- Configure data collection sources
- View real-time events and alerts
- Filter events by severity

## Configuration

Settings are stored in `siem_settings.json`:

| Setting | Description |
|---------|-------------|
| `threshold` | Minimum severity level to display (LOW, MEDIUM, HIGH, CRITICAL) |
| `max_events` | Maximum events to retain in memory |
| `win_enabled` | Enable Windows Event Log collection |
| `log_enabled` | Enable log file monitoring |
| `log_paths` | Paths to log files to monitor |
| `syslog_enabled` | Enable Syslog server |
| `syslog_port` | Syslog server port (default: 514) |
| `net_enabled` | Enable network traffic monitoring |

## Project Structure

```
├── main.py              # Application entry point
├── siem_settings.json   # Configuration file
├── ALGORITHM.md         # Algorithm documentation
├── requirements.txt     # Python dependencies
├── siem/
│   ├── config.py        # Configuration constants
│   ├── collectors/      # Data collection modules
│   │   ├── windows_event.py
│   │   ├── syslog_server.py
│   │   ├── network_monitor.py
│   │   └── log_file.py
│   ├── ui/              # User interface
│   │   ├── app.py       # Main application window
│   │   └── widgets.py   # Custom UI components
│   └── utils/           # Utilities
│       └── event_queue.py
└── tests/               # Unit tests
```

## Building Executable

To build a standalone executable:
```bash
pyinstaller SIEM.spec
```

## License

This project is for educational purposes.
