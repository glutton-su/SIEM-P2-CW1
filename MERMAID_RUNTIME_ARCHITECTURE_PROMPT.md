# Mermaid.ai Prompt for SIEM Runtime Architecture

## Prompt for Mermaid.ai

Create a comprehensive runtime architecture diagram for a Security Information and Event Management (SIEM) system using Mermaid syntax. The diagram should illustrate the multi-threaded architecture showing how different components interact during runtime.

### System Overview
The SIEM system is a Python-based security monitoring application with a Tkinter GUI. It collects security events from multiple sources in real-time using concurrent threads and presents them through a graphical interface.

### Components to Include

#### 1. Main Thread (UI Layer)
- **Tkinter Main Loop**: Runs continuously to handle UI events
- **Event Processing Timer**: Polls event queue every 100ms using `root.after()`
- **UI Updates**: Updates treeviews, statistics, charts, and alerts
- **User Interaction Handling**: Responds to button clicks, filters, searches

#### 2. Collector Threads (Data Collection Layer)
Create separate daemon threads for each collector:

a) **Windows Event Log Collector**
   - Polls System, Application, and Security logs
   - Runs every 2 seconds
   - Uses pywin32 API to access Windows Event Logs
   - Tracks last read record for incremental collection

b) **Syslog UDP Server**
   - Listens on UDP port 514
   - Uses blocking socket.recv() calls
   - Parses RFC 5424 syslog messages
   - Handles messages from network devices

c) **Syslog TCP Server**
   - Listens on TCP port 514
   - Uses accept() loop for client connections
   - Handles each client in separate context
   - More reliable than UDP variant

d) **Log File Monitor**
   - Watches specified file paths
   - Polls files every 1 second
   - Tracks file positions for new content
   - Supports multiple log files simultaneously

e) **Network Monitor**
   - Executes netstat command
   - Runs every 5 seconds
   - Tracks ESTABLISHED and LISTENING connections
   - Detects new network connections

#### 3. Thread-Safe Communication
- **Event Queue**: Python's `queue.Queue` (thread-safe FIFO)
  - Collectors use `put()` to add events (thread-safe, non-blocking)
  - Main thread uses `get_nowait()` to retrieve events
  - Prevents race conditions between threads

#### 4. Data Flow
Show the following data flow:
1. **Collection Phase**: Each collector thread reads from its source independently
2. **Normalization Phase**: Raw events are parsed into standard format with fields:
   - timestamp
   - severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
   - source (e.g., "Windows Event Log", "Syslog")
   - category (e.g., "Authentication", "Network", "System")
   - event_name (e.g., "Login Failed", "Service Started")
   - ip_address (if applicable)
   - message (full event details)
3. **Queue Phase**: Normalized events are placed in thread-safe queue
4. **Processing Phase**: Main thread retrieves events from queue
5. **Classification Phase**: Apply pattern matching and severity rules
6. **Storage Phase**: Store in deque structures (events, alerts)
7. **Display Phase**: Update UI components (treeview, statistics, charts)

#### 5. Data Sources (External)
Show connections from external sources:
- **Windows Operating System**: Provides System, Application, Security event logs
- **Network Devices**: Send syslog messages via UDP/TCP
- **Log Files**: Plain text log files on disk (.log, .txt)
- **Network Stack**: Netstat provides connection information

#### 6. Synchronization Mechanisms
- Daemon threads (automatically terminate when main thread exits)
- Thread-safe queue for inter-thread communication
- Running flags for graceful shutdown
- Timeout values on thread joins (2 seconds)
- Socket timeouts to prevent blocking (1 second)

### Diagram Requirements

1. **Use appropriate Mermaid diagram type**: Consider using a `graph TD` (top-down flowchart) or `sequenceDiagram` to show the runtime flow
2. **Show concurrency**: Clearly indicate which components run in parallel
3. **Show communication paths**: Use arrows to indicate data flow and method calls
4. **Label intervals**: Show polling intervals (e.g., "every 2s", "every 100ms")
5. **Indicate thread types**: Distinguish between main thread and daemon threads
6. **Show thread-safety**: Highlight the event queue as thread-safe boundary
7. **Color coding** (optional): Use different colors/styles for:
   - Main UI thread
   - Collector threads
   - Data stores
   - External sources

### Example Structure (Adapt as Needed)

```mermaid
graph TD
    %% Main Thread
    MainThread[Main Thread: Tkinter UI]
    ProcessTimer[Event Processor<br/>100ms Timer]
    
    %% Event Queue
    Queue[Thread-Safe Event Queue<br/>queue.Queue]
    
    %% Collector Threads
    WinCollector[Windows Event Collector<br/>Thread - 2s interval]
    SyslogUDP[Syslog UDP Server<br/>Thread - blocking]
    SyslogTCP[Syslog TCP Server<br/>Thread - accept loop]
    LogMonitor[Log File Monitor<br/>Thread - 1s interval]
    NetMonitor[Network Monitor<br/>Thread - 5s interval]
    
    %% External Sources
    WinOS[Windows OS<br/>Event Logs]
    NetDevices[Network Devices<br/>Syslog Messages]
    LogFiles[Log Files<br/>.log, .txt]
    NetStack[Network Stack<br/>netstat]
    
    %% Data Flow
    WinOS -->|Read Events| WinCollector
    NetDevices -->|Send UDP/TCP| SyslogUDP
    NetDevices -->|Send UDP/TCP| SyslogTCP
    LogFiles -->|Monitor Changes| LogMonitor
    NetStack -->|Query Connections| NetMonitor
    
    WinCollector -->|put()| Queue
    SyslogUDP -->|put()| Queue
    SyslogTCP -->|put()| Queue
    LogMonitor -->|put()| Queue
    NetMonitor -->|put()| Queue
    
    Queue -->|get_nowait()| ProcessTimer
    ProcessTimer -->|Update| MainThread
    MainThread -->|root.after(100ms)| ProcessTimer
```

### Expected Output

The mermaid diagram should:
- Clearly show the multi-threaded architecture
- Illustrate how data flows from sources through collectors to the UI
- Demonstrate the thread-safe communication pattern
- Show timing intervals for each polling operation
- Be visually clear and easy to understand
- Accurately represent the runtime behavior of the system

### Additional Notes

- All collector threads are daemon threads (automatically terminated when main thread exits)
- The system uses cooperative threading (no locks needed due to queue)
- Each collector operates independently - failure of one doesn't affect others
- Main thread is responsible for all UI updates (Tkinter thread-safety requirement)
- Event queue acts as the producer-consumer boundary between threads

---

## Usage Instructions

1. Copy the prompt above (everything from "Create a comprehensive runtime architecture..." to "...producer-consumer boundary between threads")
2. Go to mermaid.ai or any Mermaid-compatible tool
3. Paste the prompt and let the AI generate the diagram
4. Review and refine the diagram as needed
5. Export as SVG, PNG, or include directly in documentation

## Alternative: Direct Mermaid Code

If you prefer to create the diagram manually, use the example structure provided above and expand it to include all components and interactions described in the prompt.
