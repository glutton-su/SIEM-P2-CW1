# ALGORITHM.md

## Purpose
This document describes the high-level algorithm for the SIEM-P2-CW1 (Security Information and Event Management) project. This Python-based SIEM system is designed to collect, parse, correlate, and alert on security events from multiple sources including Windows Event Logs, Syslog servers, network traffic, and log files. The algorithm outlines the operational workflow, from system initialization through data collection, processing, alerting, and secure shutdown.

## High-Level Algorithm

### Step 1: Component Initialization and Configuration
Initialize all SIEM system components and load configuration settings.

1.1. Load system configuration from `config.py` including:
   - Collection source settings (Windows Event Log channels, Syslog ports, network interfaces)
   - Parsing rules and normalization schemas
   - Correlation rules and alert thresholds
   - Storage paths and retention policies
   - UI display preferences

1.2. Initialize the event queue for thread-safe event processing

1.3. Initialize data collectors:
   - Windows Event Log collector
   - Syslog server listener (UDP/TCP)
   - Network traffic monitor
   - Log file watcher

1.4. Initialize the graphical user interface (Tkinter-based) with monitoring controls and event display widgets

1.5. Set up logging infrastructure for system diagnostics and audit trails

### Step 2: Start Data Collection Services
Activate all configured data collection sources in separate threads.

2.1. Start Windows Event Log collection thread:
   - Subscribe to configured event channels (Security, System, Application)
   - Filter events by severity and event IDs as configured

2.2. Start Syslog server thread:
   - Bind to configured UDP and/or TCP ports (default 514)
   - Listen for incoming syslog messages from network devices

2.3. Start network traffic monitoring thread:
   - Capture network connection events using system APIs
   - Monitor for suspicious connection patterns

2.4. Start log file monitoring thread:
   - Watch configured log file paths for changes
   - Read and parse new log entries as they appear

2.5. Ensure all collection threads signal readiness before proceeding

### Step 3: Event Ingestion and Queuing
Collect raw events from all sources and place them in the event queue.

3.1. Each collector retrieves events from its respective source

3.2. Raw events are wrapped with metadata:
   - Source identifier (Windows Event, Syslog, Network, File)
   - Timestamp of collection
   - Original format indicator

3.3. Events are pushed to the thread-safe event queue for processing

3.4. Queue implements overflow protection to prevent memory exhaustion

### Step 4: Event Parsing and Normalization
Process raw events into a standardized format for analysis.

4.1. Dequeue events from the event queue in FIFO order

4.2. Parse event based on source type:
   - Windows Event: Extract EventID, TimeCreated, Level, Message, Computer
   - Syslog: Parse RFC 3164/5424 format (priority, timestamp, hostname, message)
   - Network: Extract protocol, source/destination IP and port, connection state
   - Log File: Apply regex patterns or structured parsers based on log format

4.3. Normalize parsed events into common schema with fields:
   - Event timestamp
   - Source host/IP
   - Event type/category
   - Severity level (Critical, High, Medium, Low, Info)
   - Description/message
   - Additional context fields

4.4. Handle parsing errors gracefully and log malformed events

### Step 5: Event Enrichment and Context Addition
Enhance normalized events with additional context and metadata.

5.1. Add geographic information for IP addresses (GeoIP lookup) if available

5.2. Add threat intelligence data:
   - Check IPs against known malicious IP lists
   - Check domains against threat feeds
   - Tag events with threat indicators

5.3. Add user and asset context:
   - Map usernames to user roles or departments
   - Map hostnames to asset inventory data

5.4. Calculate risk scores based on event type, source, and historical patterns

### Step 6: Correlation and Pattern Detection
Identify relationships between events and detect security incidents.

6.1. Apply correlation rules:
   - Time-based correlation (e.g., multiple failed logins within time window)
   - Cross-source correlation (e.g., failed login followed by network scan)
   - Sequence detection (e.g., reconnaissance → exploitation → lateral movement)

6.2. Detect known attack patterns:
   - Brute force attacks (repeated authentication failures)
   - Port scanning (connection attempts to multiple ports)
   - Data exfiltration (large outbound transfers)
   - Privilege escalation attempts

6.3. Maintain state for stateful correlation (e.g., session tracking, connection tracking)

6.4. Generate composite security incidents from correlated events

### Step 7: Alert Generation and Notification
Create alerts for significant security events and incidents.

7.1. Evaluate events and incidents against alert rules:
   - Severity thresholds
   - Event type matching
   - Correlation pattern matches

7.2. Generate alerts with priority levels:
   - Critical: Immediate security threats requiring urgent response
   - High: Significant security events requiring prompt investigation
   - Medium: Suspicious activity requiring review
   - Low: Informational events for awareness

7.3. Format alert messages with:
   - Alert title and description
   - Affected assets and users
   - Contributing events
   - Recommended response actions

7.4. Deliver alerts through configured channels:
   - UI notification display
   - System notifications
   - Log file output for integration with external systems

7.5. Implement alert deduplication to prevent alert flooding

### Step 8: Event Storage and Retention
Persist events and alerts for historical analysis and compliance.

8.1. Store normalized events in structured format:
   - Use JSON or CSV format for easy parsing
   - Organize by date for efficient retrieval

8.2. Store generated alerts with associated event references

8.3. Implement data retention policies:
   - Define retention periods for different event types
   - Automatically archive or purge old events per policy

8.4. Ensure atomic write operations to prevent data corruption

8.5. Maintain index structures for fast search and retrieval

### Step 9: User Interface and Command Processing
Handle user interactions and commands through the GUI.

9.1. Display real-time event stream in the GUI:
   - Show recent events with timestamps and severity
   - Apply filters for event types, severity, and time ranges
   - Highlight critical alerts

9.2. Process user commands:
   - Start/stop monitoring
   - Clear event display
   - Export events to file
   - Configure collection sources
   - Adjust alert thresholds

9.3. Provide search and query interface:
   - Search events by keyword, IP address, hostname, or time range
   - Display event details and context

9.4. Update UI responsively without blocking event collection

9.5. Handle user-initiated shutdown gracefully

### Step 10: Error Handling and System Shutdown
Implement robust error handling and clean shutdown procedures.

10.1. Error handling throughout the system:
   - Catch and log exceptions in all threads
   - Implement retry logic for transient failures
   - Fail gracefully without crashing the entire system
   - Provide meaningful error messages in logs and UI

10.2. Handle resource constraints:
   - Manage memory usage with queue size limits
   - Handle disk space limitations
   - Throttle collection if system resources are exhausted

10.3. Graceful shutdown procedure:
   - Signal all collection threads to stop
   - Flush event queue and process remaining events
   - Close all open file handles and network sockets
   - Save current state and configuration
   - Log shutdown completion

10.4. Emergency shutdown:
   - Implement timeout for thread termination
   - Force close resources if threads do not respond

## Security and Privacy Controls

### Access Control
- Implement authentication for system access (if multi-user)
- Enforce role-based access control (RBAC) for administrative functions
- Apply principle of least privilege to all system operations

### Data Protection
- Encrypt sensitive data at rest (alerts, stored events) if containing PII
- Use secure protocols (TLS/SSL) for syslog over TCP where applicable
- Sanitize sensitive data from logs (passwords, tokens, keys) before storage

### Privacy Considerations
- Obtain proper authorization before monitoring systems and networks
- Clearly document what data is collected and its purpose
- Implement data minimization: only collect necessary security event data
- Provide data subject access mechanisms where required by regulations (GDPR, etc.)
- Anonymize or pseudonymize personal identifiers where possible

### Audit Logging
- Log all administrative actions (configuration changes, user commands)
- Log system events (startup, shutdown, errors, collection status changes)
- Protect audit logs from tampering using write-once mechanisms or signatures

### Vulnerability Management
- Regularly update dependencies to patch security vulnerabilities
- Run security scanning tools on codebase (e.g., CodeQL, Bandit)
- Implement input validation to prevent injection attacks

### Data Retention and Deletion
- Define and enforce data retention policies
- Implement secure deletion of expired data (overwrite, not just unlink)
- Provide mechanisms to purge data upon request (right to erasure)

## Next Steps

The following implementation tasks are recommended to enhance the SIEM system:

1. **Define JSON Schema**: Create a formal JSON schema for normalized event structure to ensure consistency across all parsers and processors.

2. **Configuration File**: Implement a YAML or JSON configuration file for runtime settings (collection sources, alert rules, retention policies) instead of hardcoding values.

3. **Unit Tests**: Develop comprehensive unit tests for each module:
   - Event parsing logic
   - Correlation engine
   - Alert generation
   - Queue thread safety

4. **Integration Tests**: Create end-to-end integration tests that simulate event collection from mock sources and validate the entire pipeline.

5. **CI/CD Pipeline**: Set up continuous integration checks:
   - Automated testing on commit
   - Code quality scanning (linting, type checking)
   - Security vulnerability scanning

6. **Example Dataset**: Provide sample log files and events for testing and demonstration purposes.

7. **Performance Benchmarking**: Test system performance with high event volumes to identify bottlenecks and optimize throughput.

8. **Documentation Expansion**: Add API documentation, deployment guide, and troubleshooting guide.

9. **Alert Rule Editor**: Implement a GUI or configuration interface for users to define custom correlation rules and alert conditions without code changes.

10. **External Integration**: Add support for forwarding alerts to external systems (email, SIEM platforms, ticketing systems).

---

*This algorithm provides a comprehensive framework for implementing a functional and secure SIEM system suitable for educational and coursework purposes.*
