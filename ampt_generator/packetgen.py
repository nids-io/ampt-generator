import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, send, conf

from . import app


logger = logging.getLogger('ampt_generator.packetgen')
logger.setLevel(logging.DEBUG)  # Collect all log levels
logger.addHandler(logging.NullHandler())  # Set the default logger to be a nullhandler

conf.verb = 0


def generate_packet(dest_addr, dest_port, src_port=app.config.get('SRC_PORT', None), proto='tcp',
                    ip_id=app.config.get('IP_ID', 1)):
    '''
    Craft and send requested probe packet
    '''
    src_addr = app.config.get('SRC_ADDR', None)
    dest_port = int(dest_port)
    src_port = int(src_port)
    ip_id = int(ip_id)
    payload_text = app.config.get('PACKET_CONTENT')
    logger.info('Generating packet to %s:%s' % (dest_addr, dest_port))
    if proto == 'tcp':
        transport = TCP
    elif proto == 'udp':
        transport = UDP
    else:
        raise ValueError('Invalid IP protocol specified (must be one of tcp or udp)')
    protocol = transport(dport=dest_port, sport=src_port)
    packet = IP(dst=dest_addr, src=src_addr, id=ip_id)/protocol/payload_text
    send(packet)
    logging.debug('Sent crafted packet!')
    return packet

