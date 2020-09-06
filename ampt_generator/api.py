'''
API for AMPT generator

'''
import multiprocessing

import zmq
from flask import request, abort
from flask_restx import Resource, Api, reqparse, inputs

from . import app, packetgen
from .validator import (persist_counter, validate_request,
                        RequestValidationError)


class Alive(Resource):
    '''
    Simple service healthcheck resource. If the API is available and
    functioning, return successful response.

    '''
    def get(self):
        return True


class GenerateProbe(Resource):
    '''
    API resource to pass probe request data to queue for processing

    '''
    def get(self):
        probe_parser = reqparse.RequestParser()
        probe_parser.add_argument('dest_addr', type=inputs.ip, location='args',
                                  required=True)
        probe_parser.add_argument('dest_port', type=inputs.int_range(0, 65535),
                                  location='args', required=True)
        probe_parser.add_argument('src_port', type=inputs.int_range(0, 65535),
                                  location='args', required=False)
        probe_parser.add_argument('proto', choices=('tcp', 'udp'), default='tcp',
                                  location='args', required=False)
        probe_parser.add_argument('ts', type=float, location='args',
                                  required=True)
        probe_parser.add_argument('h', type=inputs.regex('^[0-9a-f]{32,512}$'),
                                  location='args', required=True)
        args = probe_parser.parse_args(strict=True)

        remote_addr = request.remote_addr
        req_counter = args['ts']

        context = zmq.Context()
        socket = context.socket(zmq.PUSH)
        socket.connect(app.config.get('ZMQ_BIND'))

        # Validate HMAC and timestamp or return HTTP 403
        try:
            validate_request(args)
            app.logger.info('authenticated dispatch request from %s '
                            'with valid HMAC', remote_addr)
        except RequestValidationError as e:
            msg = ('received invalid request from %s: %s')
            app.logger.warning(msg, remote_addr, e)
            abort(403, e)

        persist_counter(app.config['DB_PATH'], req_counter)
        app.logger.debug('stored new value %s in counter database', req_counter)

        # Remove counter from args and pass to task runner
        del args['ts']
        socket.send_json(args)
        app.logger.debug('passed dispatch request parameters to message queue')
        return args

app.logger.debug('initializing application API')
api = Api(app)

app.logger.debug('adding "Alive" API resource')
api.add_resource(Alive, '/api/health')
app.logger.debug('adding "GenerateProbe" API resource')
api.add_resource(GenerateProbe, '/api/generate_probe')

