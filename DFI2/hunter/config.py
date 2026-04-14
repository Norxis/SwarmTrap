import os

# Capture
HUNTER_IFACE = os.environ.get('HUNTER_IFACE', 'ens192')
CAPTURE_MODE = os.environ.get('CAPTURE_MODE', 'honeypot')  # 'span' or 'honeypot'
FANOUT_WORKERS = int(os.environ.get('FANOUT_WORKERS', '4'))
CPU_LIST = os.environ.get('CPU_LIST', '')
BPF_VLAN_AWARE = int(os.environ.get('BPF_VLAN_AWARE', '0'))
BLOCK_SIZE_MB = int(os.environ.get('BLOCK_SIZE_MB', '2'))
BLOCK_COUNT = int(os.environ.get('BLOCK_COUNT', '128'))

# ClickHouse
CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
CH_DATABASE = os.environ.get('CH_DATABASE', 'dfi')

# SQLite watchlist
WATCHLIST_DB = os.environ.get('WATCHLIST_DB', '/opt/dfi-hunter/watchlist.db')
WATCHLIST_REFRESH = int(os.environ.get('WATCHLIST_REFRESH', '30'))

# Session management
SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', '120'))
FLUSH_INTERVAL = int(os.environ.get('FLUSH_INTERVAL', '10'))
MAX_SESSIONS = int(os.environ.get('MAX_SESSIONS', '500000'))
MAX_READY_Q = int(os.environ.get('MAX_READY_Q', '200000'))

# Honeypot mode
HONEYPOT_IPS = os.environ.get('HONEYPOT_IPS', '').split(',') if os.environ.get('HONEYPOT_IPS') else []
HONEYPOT_EXCLUDE = os.environ.get('HONEYPOT_EXCLUDE', '172.16.0.0/12,10.0.0.0/8,192.168.0.0/16')

# XGBoost early scoring
XGB_MODEL_PATH = os.environ.get('XGB_MODEL_PATH', '')
XGB_EARLY_PACKETS = int(os.environ.get('XGB_EARLY_PACKETS', '50'))
XGB_CONFIDENCE_THRESHOLD = float(os.environ.get('XGB_CONFIDENCE_THRESHOLD', '0.9'))

# RECON v2 scoring (leave empty to disable)
RECON_MODEL_PATH = os.environ.get('RECON_MODEL_PATH', '')
RECON_CONFIDENCE_THRESHOLD = float(os.environ.get('RECON_CONFIDENCE_THRESHOLD', '0.9'))

# Identity
SENSOR_ID = os.environ.get('SENSOR_ID', 'aio1')
TAP_POINT = os.environ.get('TAP_POINT', 'SPAN_MIRROR')
DEFAULT_LABEL = os.environ.get('DEFAULT_LABEL', 'HUNTER_OBSERVED')
