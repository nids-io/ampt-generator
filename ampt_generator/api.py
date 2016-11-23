"""
API for ampt-generator
"""

import zmq
from flask_restful import Resource, Api, reqparse

from . import app, packetgen

api = Api(app)

probe_parser = reqparse.RequestParser()
probe_parser.add_argument('dest_addr')
probe_parser.add_argument('dest_port', type=int)
probe_parser.add_argument('src_port', type=int, required=False)
probe_parser.add_argument('proto', choices=('tcp', 'udp'), default='tcp', required=False)

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
        context = zmq.Context()
        socket = context.socket(zmq.PUSH)
        socket.connect(app.config.get('ZMQ_BIND'))
        args = probe_parser.parse_args()
        socket.send_json(args)
        return args


api.add_resource(Alive, '/api/health')
api.add_resource(GenerateProbe, '/api/generate_probe')
