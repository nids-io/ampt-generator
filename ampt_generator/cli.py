from __future__ import print_function
from __future__ import absolute_import
import os
import grp
import pwd
import sys
import os.path
import argparse
import logging
import multiprocessing

import zmq
from scapy.all import conf as scapy_conf

from . import packetgen
from . import app
from .validator import prep_counter_db


LOGLEVEL_CHOICES = ['debug', 'info', 'warning', 'error', 'critical']

### XXX what are we doing in this section? Flask has a default logger as a
### StreamHandler at app.logger and this is creating a new root logger.
logger = logging.getLogger('ampt_generator')  # XXX: per module logs based off verbosity
# XXX logger.setLevel(logging.DEBUG)  # Collect all log levels
logger.setLevel(app.config['LOGLEVEL'].upper())
logger.addHandler(logging.NullHandler())  # Set the default logger to be a nullhandler


def valid_configfile(s):
    'Validate that specified argument is a file path that can be opened'
    try:
        with open(s, 'r') as f:
            pass
    except Exception as e:
        raise argparse.ArgumentTypeError('{} ({})'.format(e.strerror, s))
    return s

def ampt_gen():
    '''
    Create CLI to generate a one-off packet.
    :return:

    '''
    # XXX determine if this function/entry point has any real use today
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

    # XXX this is working with the non-Flask root logger noted at top of module
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
    Run packet generation dispatch receipt child process.
    :return:

    '''
    msg_queue_bind = app.config['ZMQ_BIND']

    running_user = pwd.getpwuid(os.getuid()).pw_name
    running_group = grp.getgrgid(os.getgid()).gr_name
    app.logger.debug('initialized as user %s, group %s',
                     running_user, running_group)
    app.logger.debug('starting probe packet dispatcher using message queue '
                     'at %s...', msg_queue_bind)

    try:
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.bind(msg_queue_bind)
        while True:
            packet = socket.recv_json()
            app.logger.debug('received dispatch workload: %s', repr(packet))
            packetgen.generate_packet(**packet)
    except KeyboardInterrupt:
        pass


def ampt_builtin_server(host, port, user, group):
    '''
    Run standalone Flask app and API server
    :return:

    '''
    host = host or app.config['LISTEN_ADDRESS']
    port = port or app.config['LISTEN_PORT']
    user = user or app.config['USER']
    group = group or app.config['GROUP']

    if os.getuid() == 0:
        app.logger.debug('dropping privileges...')
        drop_privileges(uid_name=user, gid_name=group)

    running_user = pwd.getpwuid(os.getuid()).pw_name
    running_group = grp.getgrgid(os.getgid()).gr_name
    app.logger.debug('initialized as user %s, group %s',
                     running_user, running_group)
    app.logger.debug('loading application on address %s, port %d...',
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
                        default=app.config['CONFIG_FILE'],
                        help='load app configuration from specified file '
                             '(default: %(default)s)')
    parser.add_argument('-L', '--listen-address',
                        help='listen for connections on specified IP address '
                             '(default: {addr})'.format(addr=app.config['LISTEN_ADDRESS']))
    parser.add_argument('-p', '--listen-port', type=int,
                        help='listen for connections on specified port '
                             '(default: {port})'.format(port=app.config['LISTEN_PORT']))
    parser.add_argument('-d', '--db-path',
                        help='set specified file path for counter database storage '
                             '(default: {db})'.format(db=app.config['DB_PATH']))
    parser.add_argument('-u', '--user',
                        help='set app server process to run as specified user '
                             '(default: {user})'.format(user=app.config['USER']))
    parser.add_argument('-g', '--group',
                        help='set app server process to run as specified group '
                             '(default: {group})'.format(group=app.config['GROUP']))
    parser.add_argument('-o', '--logfile',
                        help='log to specified file (default: do not log to file)')
    parser.add_argument('-l', '--loglevel', choices=LOGLEVEL_CHOICES,
                        help='set logging verbosity level '
                             '(default: {level})'.format(level=app.config['LOGLEVEL']))
    args = parser.parse_args()

    # Apply user configuration (default path or specified from cmd line)
    app.config.from_pyfile(os.path.abspath(args.config_file))

    loglevel = (args.loglevel or app.config['LOGLEVEL']).upper()
    logfile = args.logfile or app.config['LOGFILE']
    db_path = args.db_path or app.config['DB_PATH']

    if not app.debug:
        app_formatter = app.config['CONSOLE_LOG_FORMATTER']
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(loglevel)
        stream_handler.setFormatter(app_formatter)
        app.logger.addHandler(stream_handler)
        app.logger.setLevel(loglevel)
    if logfile:
        try:
            file_formatter = app.config['FILE_LOG_FORMATTER']
            file_handler = logging.FileHandler(logfile)
            file_handler.setLevel(loglevel)
            file_handler.setFormatter(file_formatter)
            app.logger.addHandler(file_handler)
        except OSError as e:
            msg = 'failure opening log file (%s)'
            app.logger.critical(msg, e)
            sys.exit(1)

    ver_info = 'ampt-generator running on Python %s using Scapy %s'
    ver_py = '.'.join([str(x) for x in sys.version_info[:3]])
    ver_scapy = scapy_conf.version
    app.logger.info(ver_info, ver_py, ver_scapy)

    app.logger.info('loaded configuration from file %s',
                    args.config_file)
    app.logger.info('configured logging at level: %s',
                    logging.getLevelName(app.logger.level))

    # Allow CLI path to override configuration file path for database
    app.config['DB_PATH'] = db_path

    if not os.path.exists(app.config['DB_PATH']):
        app.logger.debug('initializing new replay counter database...')
        try:
            _kwargs = {'db_path': app.config['DB_PATH']}
            # If executed as superuser, app will require access to counter DB
            # with lower privileges and file should be writable to that user:
            if os.getuid() == 0:
                _kwargs.update(
                    user=app.config['USER'],
                    group=app.config['GROUP'])
            prep_counter_db(**_kwargs)
        except OSError as e:
            msg = 'unable to create counter database (%s)'
            app.logger.critical(msg, e.strerror)
            sys.exit(1)

    app.logger.debug('using counter database path %s', app.config['DB_PATH'])
    app.logger.info('starting ampt-manager API and packet dispatch services...')

    server_options =  {
        'host': args.listen_address,
        'port': args.listen_port,
        'user': args.user,
        'group': args.group,
    }

    task_runner_process = multiprocessing.Process(
        target=ampt_gen_taskrunner,
        name=app.config['PROC_NAME_RUNNER']
    )
    app_server_process = multiprocessing.Process(
        target=ampt_builtin_server,
        name=app.config['PROC_NAME_SERVER'],
        kwargs=server_options
    )

    task_runner_process.start()
    app_server_process.start()

