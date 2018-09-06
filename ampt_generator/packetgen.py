'''Generation of dispatched probe packets'''

import logging

# Tone down scapy builtin logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, send, conf

from . import app


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Collect all log levels
logger.addHandler(logging.NullHandler())  # Set the default logger to be a nullhandler

# Quiet down logging from scapy
conf.verb = 0


def generate_packet(dest_addr, dest_port, src_port=app.config['SRC_PORT'],
                    proto='tcp', ip_id=app.config['IP_ID']):
    'Craft and send requested probe packet'

    if proto == 'tcp':
        transport = TCP
    elif proto == 'udp':
        transport = UDP
    else:
        raise ValueError('Invalid IP protocol specified (must be one of '
                         '"tcp" or "udp")')

    src_addr = app.config.get('SRC_ADDR', None)
    dest_port = int(dest_port)
    src_port = int(src_port)
    ip_id = int(ip_id)
    payload_text = app.config.get('PACKET_CONTENT')

    protocol = transport(dport=dest_port, sport=src_port)
    packet = IP(dst=dest_addr, src=src_addr, id=ip_id)/protocol/payload_text
    app.logger.debug('generated probe packet with Scapy: %s', packet.summary())
    send(packet)
    app.logger.debug('finished sending crafted probe packet')

    return packet

