from __future__ import print_function
from __future__ import absolute_import
import os
import grp
import pwd
import os.path
import argparse
import logging
import multiprocessing

import zmq

from . import packetgen
from . import app


DEFAULTS = {
    'listen_address': '127.0.0.1',
    'listen_port': 5000,
    'config_file': '/etc/ampt-generator.conf',
    'loglevel': 'warning',
    'app_user': 'nobody',
    'app_group': 'nobody',
}

LOGLEVEL_CHOICES = ['debug', 'info', 'warning', 'error', 'critical']

logger = logging.getLogger('ampt_generator')  # XXX: per module logs based off verbosity
# XXX logger.setLevel(logging.DEBUG)  # Collect all log levels
logger.setLevel(DEFAULTS['loglevel'].upper())
logger.addHandler(logging.NullHandler())  # Set the default logger to be a nullhandler


def valid_configfile(s):
    'Validate that specified argument is a file path that can be opened'
    try:
        with open(s, 'r') as f:
            pass
    except Exception as e:
        raise argparse.ArgumentTypeError(e.strerror)
    return s

def ampt_gen():
    '''
    Create CLI to generate a one-off packet.
    :return:

    '''
    description = 'Generate TCP packet to specified destination address and port'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('dest_addr', default=None,
                        help='destination IP address')
    parser.add_argument('dest_port', help='destination port', default=None)
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='enable verbose logging')
    parser.add_argument('-l', '--log', dest='logfile', default=None,
                        help='log file name')
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
    '''
    Generate Suricata/Snort IDS rule for the currently configured
    healthcheck packet

    :return:

    '''
    # Use argparse only to get consistent command behavior and --help support
    description = 'Output health check probe network IDS rule'
    parser = argparse.ArgumentParser(description=description)
    args = parser.parse_args()
    print(app.config.get('RULE_STRUCTURE') % app.config.get('PACKET_CONTENT_SNORT'))


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    '''
    Drop privileges to execute as non-root user
    :param uid_name: Username
    :param gid_name: Group
    :return:

    '''
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid
    os.setgroups([])
    os.setgid(running_gid)
    os.setuid(running_uid)
    os.umask(0o077)


def ampt_gen_taskrunner():
    '''
    Run packet generation as privileged process. This needs to run as root :(
    XXX does it when using scapy-python3?
    :return:

    '''
    name = multiprocessing.current_process().name
    pid = multiprocessing.current_process().pid

    running_user = pwd.getpwuid(os.getuid()).pw_name
    running_group = grp.getgrgid(os.getgid()).gr_name
    app.logger.debug('process %s (pid: %d) running as user %s, group %s',
                     name, pid, running_user, running_group)
    app.logger.debug('starting probe packet dispatch loop')

    try:
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind(app.config.get('ZMQ_BIND'))
        while True:
            packet = socket.recv_json()
            # XXX swap and standardize?
            #logger.info('Received workload: %s' % repr(packet))
            app.logger.info('received workload: %s', repr(packet))
            packetgen.generate_packet(**packet)
    except KeyboardInterrupt:
        pass


def ampt_builtin_server(host, port, user, group):
    '''
    Run standalone Flask app and API server
    :return:

    '''
    name = multiprocessing.current_process().name
    pid = multiprocessing.current_process().pid

    host = (host or app.config.get('LISTEN_ADDRESS')
            or DEFAULTS['listen_address'])
    port = (port or app.config.get('LISTEN_PORT')
            or DEFAULTS['listen_port'])
    user = (user or app.config.get('USER')
            or DEFAULTS['app_user'])
    group = (group or app.config.get('GROUP')
            or DEFAULTS['app_group'])

    if os.getuid() == 0:
        app.logger.debug('dropping privileges for %s process (pid: %d)...',
                         name, pid)
        drop_privileges(uid_name=user, gid_name=group)

    running_user = pwd.getpwuid(os.getuid()).pw_name
    running_group = grp.getgrgid(os.getgid()).gr_name
    app.logger.debug('process %s (pid: %d) running as user %s, group %s',
                     name, pid, running_user, running_group)
    app.logger.debug('loading app server on address %s and port %d',
                     host, port)

    app.run(host=host, port=port, use_reloader=False)


def ampt_server():
    '''
    Run main process to start the AMPT runner and Flask web server
    :return:

    '''
    # Avoid setting defaults for options that can/should also be read from the
    # configuration file to allow inheritance/override to function correctly.
    description = 'Run AMPT probe generator API and dispatch workers'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-c', '--config-file', type=valid_configfile,
                        default=DEFAULTS['config_file'],
                        help='load app configuration from specified file '
                             '(default: %(default)s)')
    parser.add_argument('-L', '--listen-address',
                        help='listen for connections on specified IP address '
                             '(default: {addr})'.format(addr=DEFAULTS["listen_address"]))
    parser.add_argument('-p', '--listen-port', type=int,
                        help='listen for connections on specified port '
                             '(default: {port})'.format(port=DEFAULTS["listen_port"]))
    parser.add_argument('-u', '--user',
                        help='set app server process to run as specified user '
                             '(default: {user})'.format(user=DEFAULTS["app_user"]))
    parser.add_argument('-g', '--group',
                        help='set app server process to run as specified group '
                             '(default: {group})'.format(group=DEFAULTS["app_group"]))
    parser.add_argument('-l', '--loglevel', choices=LOGLEVEL_CHOICES,
                        help='set logging verbosity level '
                             '(default: {level})'.format(level=DEFAULTS["loglevel"]))
    args = parser.parse_args()

    # XXX replace ampt_builtin_server with a function that runs the app in a
    # Gunicorn instance like ampt-manager does

    app.config.from_pyfile(os.path.abspath(args.config_file))

    loglevel = (args.loglevel or app.config.get('LOGLEVEL')
            or DEFAULTS['loglevel']).upper()

    if not app.debug:
        app_formatter = app.config['CONSOLE_LOG_FORMATTER']
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(loglevel)
        stream_handler.setFormatter(app_formatter)
        app.logger.addHandler(stream_handler)
        app.logger.setLevel(loglevel)
    if app.config.get('LOGFILE'):
        file_formatter = app.config['FILE_LOG_FORMATTER']
        file_handler = logging.FileHandler(app.config['LOGFILE'])
        file_handler.setLevel(loglevel)
        file_handler.setFormatter(file_formatter)
        app.logger.addHandler(file_handler)

    app.logger.info('starting ampt-manager API and packet dispatch services')
    app.logger.info('configuring logging at level: %s',
                    logging.getLevelName(app.logger.level))

    server_options =  {
        'host': args.listen_address,
        'port': args.listen_port,
        'user': args.user,
        'group': args.group,
    }

    runner = multiprocessing.Process(
        target=ampt_gen_taskrunner,
        name='task_runner'
    )
    unprivileged_process = multiprocessing.Process(
        target=ampt_builtin_server,
        name='app_server',
        kwargs=server_options
    )

    runner.start()
    unprivileged_process.start()

