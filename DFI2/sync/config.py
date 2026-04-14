import os


PV1_HOST = os.environ.get('PV1_HOST', '172.16.3.2')
PV1_CH_PORT = int(os.environ.get('PV1_CH_PORT', '9000'))
AIO_HOST = os.environ.get('AIO_HOST', '192.168.0.113')
AIO_SSH_PORT = int(os.environ.get('AIO_SSH_PORT', '2222'))
AIO_CH_PORT = int(os.environ.get('AIO_CH_PORT', '9000'))
AIO_USER = os.environ.get('AIO_USER', 'colo8gent')
AIO_PASS = os.environ.get('AIO_PASS')
WATCHLIST_DB_PATH = os.environ.get('WATCHLIST_DB_PATH', '/opt/dfi-hunter/watchlist.db')
PULL_INTERVAL_SEC = int(os.environ.get('PULL_INTERVAL_SEC', '300'))
PUSH_INTERVAL_SEC = int(os.environ.get('PUSH_INTERVAL_SEC', '600'))
WATERMARK_FILE = os.environ.get('WATERMARK_FILE', '/var/lib/dfi2/sync_watermark.json')
