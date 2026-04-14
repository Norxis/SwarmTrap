"""Shared constants for the GOD pipeline.

Used by: god1.py, god2_brain.py
"""

# XGB 5-class names
CLASS_NAMES = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTE', 3: 'EXPLOIT', 4: 'CLEAN'}

# Service identification (dst_port -> service_id)
SERVICE_MAP = {
    22: 1, 2222: 1,                                          # SSH
    80: 2, 443: 2, 8080: 2, 8443: 2, 8090: 2, 8081: 2,     # HTTP
    5000: 2, 9200: 2,                                        # HTTP (Docker, Elasticsearch)
    3389: 3, 13389: 3,                                       # RDP
    1433: 4, 3306: 4, 3307: 4, 5432: 4,                     # SQL
    445: 5,                                                   # SMB
    25: 6, 110: 6, 143: 6, 993: 6, 587: 6,                  # MAIL
    23: 7,                                                    # TELNET
    5900: 8, 5901: 8,                                        # VNC
    6379: 9,                                                  # REDIS
    27017: 10,                                                # MONGODB
    53: 11,                                                   # DNS
    5060: 12, 5061: 12,                                      # SIP
    2375: 13,                                                 # DOCKER_API
    389: 14, 636: 14,                                        # LDAP
    161: 15,                                                  # SNMP
}

SERVICE_NAMES = {
    0: 'UNKNOWN', 1: 'SSH', 2: 'HTTP', 3: 'RDP', 4: 'SQL', 5: 'SMB',
    6: 'MAIL', 7: 'TELNET', 8: 'VNC', 9: 'REDIS', 10: 'MONGODB',
    11: 'DNS', 12: 'SIP', 13: 'DOCKER', 14: 'LDAP', 15: 'SNMP',
}

# Short names for verdict_group strings
SVC_NAMES = {
    1: 'SSH', 2: 'HTTP', 3: 'RDP', 4: 'SQL', 5: 'SMB',
    6: 'MAIL', 7: 'TELNET', 8: 'VNC', 9: 'REDIS', 10: 'MONGODB',
    11: 'DNS', 12: 'SIP', 13: 'DOCKER', 14: 'LDAP', 15: 'SNMP',
}

# Evidence type bitmask (matches evidence_events.evidence_mask_bit)
EVD_AUTH_FAIL    = 1
EVD_AUTH_SUCCESS = 2
EVD_CRED_CAPTURE = 4
EVD_SUS_COMMAND  = 8
EVD_PRIV_ESC     = 16
EVD_LATERAL      = 32
EVD_BIND         = 64
EVD_SQL_INJECT   = 128

# Verdict values
V_NONE    = 'NONE'
V_CAPTURE = 'CAPTURE'
V_DONE    = 'DONE'       # Score only — enough training data, stop capture, no drop
V_DROP    = 'DROP'

# Known infrastructure IPs — captured as RB, never dropped
RB_ALLOWLIST = frozenset([
    '8.8.8.8', '8.8.4.4',
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9',
    '208.67.222.222', '208.67.220.220',
])

# Behavioral class names (per-service overrides)
BCLASS_NAMES = {
    0: 'SCAN', 1: 'PROBE', 2: 'BRUTE', 3: 'CREDENTIAL',
    4: 'COMMAND', 5: 'PERSIST',
    # HTTP
    (2, 1): 'CRAWL', (2, 2): 'FUZZ', (2, 3): 'EXPLOIT',
    (2, 4): 'WEBSHELL', (2, 5): 'EXFIL',
    # SQL
    (4, 3): 'INJECTION', (4, 4): 'EXFIL',
    # SMB
    (5, 1): 'NEGOTIATE', (5, 2): 'ENUM', (5, 3): 'BRUTE',
    (5, 4): 'EXPLOIT', (5, 5): 'LATERAL',
}


def bclass_name(service_id: int, service_class: int) -> str:
    """Get human-readable behavioral class name for verdict_group strings."""
    return BCLASS_NAMES.get((service_id, service_class),
           BCLASS_NAMES.get(service_class, str(service_class)))


# DROP TTL
DROP_TTL_DAYS = 7
