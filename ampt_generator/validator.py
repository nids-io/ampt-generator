'''Validation of received probe dispatch requests'''

import hmac
import json

from . import app


class HMACValidationError(Exception):
    'Failure validating HMAC in request'
    pass

class CounterValidationError(Exception):
    'Failure validating timestamp counter in request'
    pass

def validate_request(args):
    'Validate HMAC and timestamp counter on request'

    # Extract HMAC hash from request, grab timestamp
    req_digest = args.pop('h')
    ts = args['ts']

    # Construct message from request and compute digest
    j = json.dumps(args, sort_keys=True)
    computed_digest = (hmac.new(bytes(app.config['HMAC_KEY'].encode('utf-8')),
                               j.encode('utf-8'), app.config['HMAC_DIGEST'])
                               .hexdigest())

    # Fail out if HMAC comparison unsuccessful
    if not hmac.compare_digest(req_digest, computed_digest):
        raise HMACValidationError

    # XXX here the stored timestamp must be compared
    if not ts:
        raise CounterValidationError

