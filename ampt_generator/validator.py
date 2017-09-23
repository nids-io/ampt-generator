'''
Validation of received probe dispatch requests.

Validation is performed in two parts:

1. Requests are handled as messages and are required to carry an HMAC digest
   allowing the server to verify the message and validate that client is a
   trusted AMPT manager using the same shared key.
2. Request messages contain the core packet dispatch parameters as well as a
   per-request counter in the form of a timestamp, included to allow for a basic
   level of replay protection. After a request is validated, the counter (a
   floating point timestamp value) is stored in the counter database. Future
   requests ensure that the counter in the validated message is greater than the
   stored counter from the previous message.

'''

import os
import hmac
import json
import os.path
from shutil import chown

from . import app


class RequestValidationError(Exception):
    'Failure validating HMAC or replay counter in request'
    pass

def prep_counter_db(db_path, user=None, group=None):
    '''
    Initialize new counter DB file.

    If user and group are specified, caller is a privileged process specifying
    ownership of file by less privileged user/group.

    '''
    try:
        persist_counter(db_path)
    except FileNotFoundError as e:
        os.makedirs(os.path.dirname(db_path))
        persist_counter(db_path)
    if user is not None and group is not None:
        chown(db_path, user, group)

def persist_counter(db_path, ctr=app.config['DB_INIT_VAL']):
    'Store counter into DB file'
    with open(db_path, 'w') as f:
        f.write(str(ctr))
        if ctr == app.config['DB_INIT_VAL']:
            app.logger.debug('initialized counter database with base '
                             'value of %d', app.config['DB_INIT_VAL'])

def validate_request(args):
    'Validate HMAC and timestamp counter on request'

    # Extract HMAC hash from request, grab timestamp
    req_digest = args.pop('h')
    req_ts = args['ts']

    # Construct message from request and compute digest
    j = json.dumps(args, sort_keys=True)
    computed_digest = (hmac.new(bytes(app.config['HMAC_KEY'].encode('utf-8')),
                               j.encode('utf-8'), app.config['HMAC_DIGEST'])
                               .hexdigest())

    # Fail out if HMAC comparison unsuccessful
    if not hmac.compare_digest(req_digest, computed_digest):
        raise RequestValidationError('HMAC digest failed verification')

    # Compare stored counter to request counter. The counter is valid if it is
    # greater than the previously stored one. 
    with open(app.config['DB_PATH'], 'r') as f:
        if not req_ts > float(f.read()):
            raise RequestValidationError('Replay counter comparison '
                                         'failed verification')

