"""
Configuration and constants for the SIEM application.
Contains color schemes, security patterns, and Windows event mappings.
"""

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

SEVERITY_COLORS = {
    'CRITICAL': COLORS['accent_red'],
    'HIGH': COLORS['accent_orange'],
    'MEDIUM': COLORS['accent_yellow'],
    'LOW': COLORS['accent_blue'],
    'INFO': COLORS['accent_green'],
}

# ==================== Security Event Patterns ====================
SECURITY_PATTERNS = {
    # Authentication patterns
    r'(?i)(failed|failure).*(login|logon|auth|password)': ('Authentication', 'Login Failed', 'HIGH'),
    r'(?i)(success).*(login|logon|auth)': ('Authentication', 'Login Success', 'INFO'),
    r'(?i)(logout|logoff)': ('Authentication', 'Logout', 'INFO'),
    r'(?i)(password).*(change|reset|expire)': ('Authentication', 'Password Change', 'MEDIUM'),
    r'(?i)(account).*(lock|disable|block)': ('Authentication', 'Account Locked', 'HIGH'),
    r'(?i)(brute.?force|multiple.?failed)': ('Authentication', 'Brute Force Attempt', 'CRITICAL'),
    
    # Network patterns
    r'(?i)(connection).*(refused|denied|blocked)': ('Network', 'Connection Blocked', 'MEDIUM'),
    r'(?i)(port.?scan|scanning)': ('Network', 'Port Scan Detected', 'HIGH'),
    r'(?i)(ddos|dos.?attack|flood)': ('Network', 'DDoS Attempt', 'CRITICAL'),
    r'(?i)(firewall).*(block|deny|drop)': ('Firewall', 'Packet Dropped', 'MEDIUM'),
    r'(?i)(intrusion|ids|ips).*(detect|alert)': ('Firewall', 'Intrusion Detected', 'CRITICAL'),
    
    # Malware patterns
    r'(?i)(malware|virus|trojan|ransomware|worm)': ('Malware', 'Threat Detected', 'CRITICAL'),
    r'(?i)(quarantine|isolat)': ('Malware', 'Quarantine Action', 'HIGH'),
    r'(?i)(scan).*(complete|finish)': ('Malware', 'Scan Complete', 'INFO'),
    
    # System patterns
    r'(?i)(service).*(start|begin)': ('System', 'Service Started', 'INFO'),
    r'(?i)(service).*(stop|end|terminat)': ('System', 'Service Stopped', 'MEDIUM'),
    r'(?i)(privilege).*(escalat|elevat)': ('System', 'Privilege Escalation', 'CRITICAL'),
    r'(?i)(config|setting).*(change|modif|update)': ('System', 'Configuration Change', 'MEDIUM'),
    r'(?i)(error|critical|fatal)': ('System', 'System Error', 'HIGH'),
    r'(?i)(warning|warn)': ('System', 'System Warning', 'MEDIUM'),
    
    # Data patterns
    r'(?i)(file).*(access|open|read|write|delete)': ('Data', 'File Access', 'LOW'),
    r'(?i)(data).*(export|transfer|copy)': ('Data', 'Data Export', 'MEDIUM'),
    r'(?i)(encrypt|decrypt)': ('Data', 'Encryption Event', 'LOW'),
    r'(?i)(backup).*(complete|success|fail)': ('Data', 'Backup Event', 'INFO'),
    r'(?i)(unauthorized|permission.?denied|access.?denied)': ('Data', 'Unauthorized Access', 'HIGH'),
}

# Windows Event IDs and their meanings (System & Application logs work without admin)
WINDOWS_EVENT_MAPPING = {
    # ===== SYSTEM LOG EVENTS (No admin needed) =====
    1: ('System', 'System Event', 'INFO'),
    6: ('System', 'Driver Loaded', 'INFO'),
    7: ('System', 'Driver Load Failed', 'HIGH'),
    10: ('System', 'Event Processing Error', 'MEDIUM'),
    12: ('System', 'OS Starting', 'INFO'),
    13: ('System', 'OS Shutdown', 'INFO'),
    20: ('System', 'Boot Notification', 'INFO'),
    41: ('System', 'Unexpected Shutdown', 'CRITICAL'),
    104: ('System', 'Event Log Cleared', 'HIGH'),
    1001: ('System', 'Windows Error Report', 'MEDIUM'),
    1014: ('System', 'DNS Resolution Timeout', 'MEDIUM'),
    1074: ('System', 'System Shutdown/Restart', 'INFO'),
    6005: ('System', 'Event Log Started', 'INFO'),
    6006: ('System', 'Event Log Stopped', 'INFO'),
    6008: ('System', 'Unexpected Shutdown', 'HIGH'),
    6009: ('System', 'OS Version Info', 'INFO'),
    6013: ('System', 'System Uptime', 'INFO'),
    7000: ('System', 'Service Start Failed', 'HIGH'),
    7001: ('System', 'Service Dependency Failed', 'HIGH'),
    7009: ('System', 'Service Connect Timeout', 'MEDIUM'),
    7011: ('System', 'Service Timeout', 'MEDIUM'),
    7022: ('System', 'Service Hung', 'HIGH'),
    7023: ('System', 'Service Terminated Error', 'HIGH'),
    7024: ('System', 'Service Terminated', 'MEDIUM'),
    7026: ('System', 'Boot Driver Failed', 'HIGH'),
    7031: ('System', 'Service Crashed', 'HIGH'),
    7032: ('System', 'Service Recovery', 'MEDIUM'),
    7034: ('System', 'Service Crashed Unexpectedly', 'HIGH'),
    7035: ('System', 'Service Control Sent', 'INFO'),
    7036: ('System', 'Service State Changed', 'INFO'),
    7040: ('System', 'Service Start Type Changed', 'MEDIUM'),
    7045: ('System', 'New Service Installed', 'HIGH'),
    10000: ('System', 'COM+ Event', 'INFO'),
    10001: ('System', 'COM+ Error', 'MEDIUM'),
    10010: ('System', 'COM Server Start Timeout', 'MEDIUM'),
    10016: ('System', 'DCOM Permission Error', 'MEDIUM'),
    
    # ===== APPLICATION LOG EVENTS (No admin needed) =====
    0: ('Application', 'Application Event', 'INFO'),
    1000: ('Application', 'Application Error', 'HIGH'),
    1002: ('Application', 'Application Hang', 'HIGH'),
    1026: ('Application', '.NET Runtime Error', 'HIGH'),
    1033: ('Application', 'Windows Installer', 'INFO'),
    1034: ('Application', 'App Reconfigured', 'INFO'),
    1040: ('Application', 'DCOM Service Started', 'INFO'),
    11707: ('Application', 'Installation Success', 'INFO'),
    11708: ('Application', 'Installation Failed', 'HIGH'),
    11724: ('Application', 'Uninstall Complete', 'INFO'),
    
    # ===== SECURITY LOG EVENTS (Needs admin) =====
    4624: ('Authentication', 'Login Success', 'INFO'),
    4625: ('Authentication', 'Login Failed', 'HIGH'),
    4634: ('Authentication', 'Logout', 'INFO'),
    4648: ('Authentication', 'Explicit Credential Logon', 'MEDIUM'),
    4672: ('Authentication', 'Admin Login', 'MEDIUM'),
    4720: ('Authentication', 'User Account Created', 'MEDIUM'),
    4722: ('Authentication', 'User Account Enabled', 'LOW'),
    4723: ('Authentication', 'Password Change Attempt', 'LOW'),
    4724: ('Authentication', 'Password Reset Attempt', 'MEDIUM'),
    4725: ('Authentication', 'User Account Disabled', 'MEDIUM'),
    4726: ('Authentication', 'User Account Deleted', 'HIGH'),
    4740: ('Authentication', 'Account Locked Out', 'HIGH'),
    4767: ('Authentication', 'Account Unlocked', 'MEDIUM'),
    4768: ('Authentication', 'Kerberos TGT Request', 'INFO'),
    4769: ('Authentication', 'Kerberos Service Ticket', 'INFO'),
    4771: ('Authentication', 'Kerberos Pre-Auth Failed', 'HIGH'),
    4776: ('Authentication', 'NTLM Authentication', 'INFO'),
    
    # Object Access
    4656: ('Data', 'Object Handle Request', 'LOW'),
    4658: ('Data', 'Object Handle Closed', 'LOW'),
    4660: ('Data', 'Object Deleted', 'MEDIUM'),
    4663: ('Data', 'Object Access Attempt', 'LOW'),
    4670: ('Data', 'Permissions Changed', 'MEDIUM'),
    
    # Policy Changes
    4704: ('System', 'User Right Assigned', 'MEDIUM'),
    4705: ('System', 'User Right Removed', 'MEDIUM'),
    4706: ('System', 'Trust Created', 'HIGH'),
    4713: ('System', 'Kerberos Policy Changed', 'HIGH'),
    4719: ('System', 'Audit Policy Changed', 'HIGH'),
    4739: ('System', 'Domain Policy Changed', 'HIGH'),
    
    # Firewall Events
    5152: ('Firewall', 'Packet Dropped', 'LOW'),
    5153: ('Firewall', 'Packet Permitted', 'INFO'),
    5154: ('Firewall', 'Listen Allowed', 'INFO'),
    5155: ('Firewall', 'Listen Blocked', 'MEDIUM'),
    5156: ('Firewall', 'Connection Allowed', 'INFO'),
    5157: ('Firewall', 'Connection Blocked', 'MEDIUM'),
}
