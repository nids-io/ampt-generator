from __future__ import print_function
from __future__ import absolute_import
import os
import grp
import pwd
import argparse
import logging
import multiprocessing
import zmq

from . import packetgen
from . import app


logger = logging.getLogger('ampt_generator')  # TODO: per module logs based off verbosity
logger.setLevel(logging.DEBUG)  # Collect all log levels
logger.addHandler(logging.NullHandler())  # Set the default logger to be a nullhandler


def ampt_gen():
    """
    Create CLI to generate a one-off packet.
    :return:
    """
    description = 'Generate TCP packet to specified destination address and port'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('dest_addr', help='destination IP address', default=None)
    parser.add_argument('dest_port', help='destination port', default=None)
    parser.add_argument('-v', '--verbose', dest='verbose', help='enable verbose logging', action='store_true')
    parser.add_argument('-l', '--log', dest='logfile', help='log file name', default=None)
    args = parser.parse_args()

    console_handler = logging.StreamHandler()
    if args.verbose:
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(app.config.get('DEBUG_LOG_FORMATTER'))
    else:
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(app.config.get('CONSOLE_LOG_FORMATTER'))
    logger.addHandler(console_handler)
    packetgen.generate_packet(args.dest_addr, args.dest_port)


def ampt_rulegen():
    """
    Generate Suricata/Snort IDS rule for the currently configured
    healthcheck packet

    :return:
    """
    print(app.config.get('RULE_STRUCTURE') % app.config.get('PACKET_CONTENT_SNORT'))


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    """
    Drop privileges to execute as non-root user
    :param uid_name: Username
    :param gid_name: Group
    :return:
    """
    if os.getuid() != 0:
        return
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid
    os.setgroups([])
    os.setgid(running_gid)
    os.setuid(running_uid)
    os.umask(0o077)


def ampt_gen_taskrunner():
    """
    Run packet generation as privileged process. This needs to run as root :(
    :return:
    """
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.bind(app.config.get('ZMQ_BIND'))
    while True:
        packet = socket.recv_json()
        logger.info('Received workload: %s' % repr(packet))
        packetgen.generate_packet(**packet)


def ampt_builtin_server():
    """
    Run standalone Flask app and API server
    :return:
    """
    drop_privileges()
    app.run(use_reloader=False)


def ampt_server():
    """
    Run main process to start the AMPT runner and Flask web server
    :return:
    """
    runner = multiprocessing.Process(target=ampt_gen_taskrunner)
    unprivileged_process = multiprocessing.Process(target=ampt_builtin_server)
    runner.start()
    unprivileged_process.start()

