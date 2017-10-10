'''
Default settings for AMPT generator

'''
import logging


# Server / application level defaults
LISTEN_ADDRESS = 'localhost'
LISTEN_PORT = 5000
USER = 'nobody'
GROUP = 'nobody'
CONFIG_FILE = '/etc/ampt-generator.conf'
LOGLEVEL = 'warning'
ZMQ_BIND = 'tcp://127.0.0.1:9959'
PROC_NAME_RUNNER = 'TaskRunner'
PROC_NAME_SERVER = 'AppServer'
CONSOLE_LOG_FORMATTER = logging.Formatter('%(asctime)s: %(processName)s (pid: %(process)d) - %(message)s')
DEBUG_LOG_FORMATTER = logging.Formatter('%(asctime)s [%(levelname)s] %(module)s:%(funcName)s:%(lineno)s: %(processName)s (pid: %(process)d) - %(message)s')
FILE_LOG_FORMATTER = logging.Formatter('%(asctime)s [%(levelname)s] %(module)s: %(processName)s (pid: %(process)d) - %(message)s')
HMAC_DIGEST = 'sha256'

# Database defaults
DB_PATH = '/var/ampt/ampt-generator.db'
DB_INIT_VAL = 0

# Packet generator / NIDS rule defaults
RULE_STRUCTURE = ('alert ip any any -> any any (msg:"NIDS HEALTH MONITORING"; '
                  'content:"|%s|"; fast_pattern:only; '
                  'classtype:not-suspicious; '
                  'reference:url,github.com/nids-io/ampt-generator; '
                  'sid:3900001; rev:1;)')
PACKET_CONTENT = '0c56f99b-cf66-4679-9be2-3b6384c27586.NIDS_HEALTH_CHECK'
PACKET_CONTENT_SNORT = ''.join('{:02x}'.format(ord(c)) for c in PACKET_CONTENT)
SRC_PORT = 65500
IP_ID = 1

